//! On-disk compression cache.
//!
//! Record layout (little endian):
//! `magic[4] "TNCC" | version u32 | body_len u64 | source_sha256[32] | body_sha256[32] | body`
//!
//! File names derive from the source content hash plus the algorithm, so two versions of
//! one path never overwrite each other. Writes go to a unique temp file and are renamed
//! into place, so readers only ever see complete records.

use super::super::cache_util::run_cpu;
use super::super::file_cache::FileBody;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAGIC: &[u8; 4] = b"TNCC";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 4 + 4 + 8 + 32 + 32;

/// An invalid record younger than this may belong to a writer from another process
/// using a non-atomic filesystem; it is ignored but not deleted.
const FRESH_GRACE: Duration = Duration::from_secs(30);

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn record_path(dir: &Path, source_hex: &str, alg: &str) -> PathBuf {
	dir.join(format!("{source_hex}.{alg}"))
}

pub fn encode(source: &[u8; 32], body: &[u8]) -> Vec<u8> {
	let mut record = Vec::with_capacity(HEADER_LEN + body.len());
	record.extend_from_slice(MAGIC);
	record.extend_from_slice(&VERSION.to_le_bytes());
	record.extend_from_slice(&(body.len() as u64).to_le_bytes());
	record.extend_from_slice(source);
	record.extend_from_slice(&Sha256::digest(body));
	record.extend_from_slice(body);
	record
}

/// Validates a record against the expected source digest and returns the compressed body.
pub fn decode(record: Vec<u8>, source: &[u8; 32]) -> Result<Bytes, &'static str> {
	if record.len() < HEADER_LEN {
		return Err("truncated header");
	}
	if &record[..4] != MAGIC {
		return Err("bad magic");
	}
	if record[4..8] != VERSION.to_le_bytes() {
		return Err("unsupported version");
	}

	let declared = u64::from_le_bytes(record[8..16].try_into().map_err(|_| "bad length")?);
	if declared != (record.len() - HEADER_LEN) as u64 {
		return Err("length mismatch");
	}
	if record[16..48] != source[..] {
		return Err("source hash mismatch");
	}

	let body = &record[HEADER_LEN..];
	if record[48..80] != Sha256::digest(body)[..] {
		return Err("body hash mismatch");
	}

	Ok(Bytes::from(record).slice(HEADER_LEN..))
}

pub async fn read(dir: &Path, content: &FileBody, alg: &str) -> Option<Bytes> {
	let path = record_path(dir, content.sha256_hex(), alg);

	let mut file = match tokio::fs::File::open(&path).await {
		Ok(file) => file,
		Err(error) => {
			if error.kind() != io::ErrorKind::NotFound {
				tracing::debug!(path = %path.display(), error = %error, "cache open failed");
			}
			return None;
		}
	};

	let modified = file.metadata().await.ok().and_then(|m| m.modified().ok());
	let mut record = Vec::new();

	if let Err(error) = file.read_to_end(&mut record).await {
		tracing::debug!(path = %path.display(), error = %error, "cache read failed");
		return None;
	}

	let source = *content.digest();
	let len = record.len();

	match run_cpu(len, move || decode(record, &source)).await? {
		Ok(body) => Some(body),
		Err(reason) => {
			let stale = modified
				.and_then(|m| m.elapsed().ok())
				.is_none_or(|age| age >= FRESH_GRACE);

			tracing::warn!(path = %path.display(), reason, removing = stale, "ignoring invalid cache record");

			if stale {
				let _ = tokio::fs::remove_file(&path).await;
			}
			None
		}
	}
}

pub async fn write(dir: &Path, content: &FileBody, alg: &str, body: &Bytes) -> io::Result<()> {
	let target = record_path(dir, content.sha256_hex(), alg);
	let tmp = dir.join(format!(
		".{}.{}.{}.{}.tmp",
		content.sha256_hex(),
		alg,
		std::process::id(),
		TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
	));

	let source = *content.digest();
	let payload = body.clone();
	let record = run_cpu(body.len(), move || encode(&source, &payload))
		.await
		.ok_or_else(|| io::Error::other("encode task failed"))?;

	let result = write_and_rename(&tmp, &target, &record).await;

	if result.is_err() {
		let _ = tokio::fs::remove_file(&tmp).await;
	}

	result
}

async fn write_and_rename(tmp: &Path, target: &Path, record: &[u8]) -> io::Result<()> {
	let mut options = tokio::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	options.mode(0o600);

	let mut file = options.open(tmp).await?;
	file.write_all(record).await?;
	file.flush().await?;
	drop(file);

	tokio::fs::rename(tmp, target).await
}
