//! In-memory file cache.
//!
//! * Weighted by bytes (not by entry count) and limited per file by `max_file_size`.
//! * The file is opened once; size/mtime/inode/ctime are read from the open descriptor
//!   and re-checked after reading, so a file swapped mid-read is never cached under
//!   the wrong identity (TOCTOU).
//! * Concurrent misses for the same file are collapsed (singleflight).
//! * Values are `Bytes`, so cloning a hit is a refcount bump done outside any lock.

mod body;
mod stamp;

pub use body::FileBody;

use super::cache_util::{SingleFlight, WeightedLru, lock_unpoisoned, run_cpu};
use bytes::Bytes;
use stamp::FileStamp;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;
use tokio::io::AsyncReadExt;

pub const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
pub const DEFAULT_CACHE_BUDGET: u64 = 256 * 1024 * 1024;

/// How many times a read is restarted when the file changes underneath it.
const READ_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub struct CachedFile {
	pub bytes: FileBody,
	pub modified: Option<SystemTime>,
}

type Entry = (FileStamp, CachedFile);

static MAX_FILE_SIZE: AtomicU64 = AtomicU64::new(DEFAULT_MAX_FILE_SIZE);

static FILE_CACHE: LazyLock<Mutex<WeightedLru<PathBuf, Entry>>> =
	LazyLock::new(|| Mutex::new(WeightedLru::new(clamp_to_usize(DEFAULT_CACHE_BUDGET))));

static FLIGHTS: LazyLock<SingleFlight<(PathBuf, FileStamp), CachedFile>> =
	LazyLock::new(SingleFlight::new);

fn clamp_to_usize(value: u64) -> usize {
	usize::try_from(value).unwrap_or(usize::MAX)
}

/// Applies the limits from the server config. Safe to call more than once.
pub fn configure_file_cache(max_file_size: u64, cache_budget: u64) {
	MAX_FILE_SIZE.store(max_file_size, Ordering::Relaxed);
	lock_unpoisoned(&FILE_CACHE).set_budget(clamp_to_usize(cache_budget));
}

fn lookup(path: &Path, stamp: &FileStamp) -> Option<CachedFile> {
	let mut cache = lock_unpoisoned(&FILE_CACHE);
	let (cached_stamp, file) = cache.get(&path.to_path_buf())?;
	(cached_stamp == stamp).then(|| file.clone())
}

fn changed_error() -> io::Error {
	io::Error::new(io::ErrorKind::Interrupted, "file changed while reading")
}

/// Reads a file through the cache. Files over `max_file_size` are refused with
/// `ErrorKind::FileTooLarge`; the protocols have no streaming mode to serve them.
pub async fn read_file_cached(path: &Path) -> io::Result<CachedFile> {
	read_file_limited(path, MAX_FILE_SIZE.load(Ordering::Relaxed)).await
}

async fn read_file_limited(path: &Path, max_size: u64) -> io::Result<CachedFile> {
	let mut last_error = changed_error();

	for _ in 0..READ_ATTEMPTS {
		match read_once(path, max_size).await {
			Err(error) if error.kind() == io::ErrorKind::Interrupted => last_error = error,
			other => return other,
		}
	}

	Err(last_error)
}

async fn read_once(path: &Path, max_size: u64) -> io::Result<CachedFile> {
	let file = tokio::fs::File::open(path).await?;
	let metadata = file.metadata().await?;

	if !metadata.is_file() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"not a regular file",
		));
	}

	if metadata.len() > max_size {
		return Err(io::Error::new(
			io::ErrorKind::FileTooLarge,
			"file exceeds max_file_size",
		));
	}

	let stamp = FileStamp::of(&metadata);

	if let Some(hit) = lookup(path, &stamp) {
		return Ok(hit);
	}

	let key = (path.to_path_buf(), stamp.clone());
	let path = path.to_path_buf();

	FLIGHTS
		.run(key, || load(file, path, stamp, metadata.modified().ok()))
		.await
}

async fn load(
	mut file: tokio::fs::File,
	path: PathBuf,
	stamp: FileStamp,
	modified: Option<SystemTime>,
) -> io::Result<CachedFile> {
	// A concurrent flight may have finished between our miss and becoming the leader.
	if let Some(hit) = lookup(&path, &stamp) {
		return Ok(hit);
	}

	let expected = stamp.size();
	let capacity = usize::try_from(expected).map_err(|_| io::ErrorKind::FileTooLarge)?;
	let mut buffer = Vec::with_capacity(capacity);

	// Read one byte past the expected size to notice a file that grew.
	(&mut file)
		.take(expected.saturating_add(1))
		.read_to_end(&mut buffer)
		.await?;

	if buffer.len() as u64 != expected {
		return Err(changed_error());
	}

	if FileStamp::of(&file.metadata().await?) != stamp {
		return Err(changed_error());
	}

	let body = run_cpu(buffer.len(), move || FileBody::new(Bytes::from(buffer)))
		.await
		.ok_or_else(|| io::Error::other("hashing task failed"))?;

	let cached = CachedFile {
		bytes: body,
		modified,
	};

	let weight = cached.bytes.len();
	lock_unpoisoned(&FILE_CACHE).put(path, (stamp, cached.clone()), weight);

	Ok(cached)
}

#[cfg(test)]
#[path = "file_cache_tests.rs"]
mod tests;
