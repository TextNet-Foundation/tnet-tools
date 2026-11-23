//! Response compression: negotiation, CPU-bounded encoding and a two-level cache
//! (weighted in-memory LRU, then an integrity-checked disk cache).

mod disk;

use super::cache_util::{SingleFlight, WeightedLru, lock_unpoisoned};
use super::file_cache::FileBody;
use bytes::Bytes;
use std::convert::Infallible;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use tokio::sync::Semaphore;

/// Algorithms the servers can apply. Order is irrelevant: the client's order/q-values decide.
pub const SUPPORTED_COMPRESSION: &[&str] = &["gzip", "zstd"];

/// Memory budget (bytes of compressed data) for the in-memory compressed cache.
const COMPRESSED_MEMORY_BUDGET: usize = 128 * 1024 * 1024;

const DEFAULT_SOURCE_MAXIMUM: u64 = 64 * 1024 * 1024;

type MemoryKey = ([u8; 32], &'static str);

static MEMORY: LazyLock<Mutex<WeightedLru<MemoryKey, Bytes>>> =
	LazyLock::new(|| Mutex::new(WeightedLru::new(COMPRESSED_MEMORY_BUDGET)));

static FLIGHTS: LazyLock<SingleFlight<MemoryKey, Option<Bytes>>> = LazyLock::new(SingleFlight::new);

/// Range responses are keyed by (source digest, algorithm, start, end): a repeated
/// range request must not re-compress the same bytes. Memory-only on purpose —
/// ranges are transient, the disk cache stays reserved for whole files.
// Only the TMUTP handler serves ranges; other bins never call this.
#[allow(dead_code)]
type RangeKey = ([u8; 32], &'static str, usize, usize);

#[allow(dead_code)]
const RANGE_MEMORY_BUDGET: usize = 32 * 1024 * 1024;

#[allow(dead_code)]
static RANGE_MEMORY: LazyLock<Mutex<WeightedLru<RangeKey, Bytes>>> =
	LazyLock::new(|| Mutex::new(WeightedLru::new(RANGE_MEMORY_BUDGET)));

#[allow(dead_code)]
static RANGE_FLIGHTS: LazyLock<SingleFlight<RangeKey, Option<Bytes>>> =
	LazyLock::new(SingleFlight::new);

/// Limits how many compressions run at once so they cannot starve the blocking pool.
static PERMITS: LazyLock<Semaphore> = LazyLock::new(|| {
	let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
	Semaphore::new(cores)
});

static DISK_ENABLED: AtomicBool = AtomicBool::new(true);
static DISK_SOURCE_MAXIMUM: AtomicU64 = AtomicU64::new(DEFAULT_SOURCE_MAXIMUM);

/// Disk-cache policy of a server instance.
#[derive(Clone, Copy)]
pub struct DiskCachePolicy {
	pub enable: bool,
	pub source_maximum: u64,
}

impl DiskCachePolicy {
	/// The policy installed by [`configure_disk_cache`] (used where the caller has no config at hand).
	#[allow(dead_code)]
	pub fn global() -> Self {
		Self {
			enable: DISK_ENABLED.load(Ordering::Relaxed),
			source_maximum: DISK_SOURCE_MAXIMUM.load(Ordering::Relaxed),
		}
	}
}

pub fn configure_disk_cache(policy: DiskCachePolicy) {
	DISK_ENABLED.store(policy.enable, Ordering::Relaxed);
	DISK_SOURCE_MAXIMUM.store(policy.source_maximum, Ordering::Relaxed);
}

/// Picks the algorithm to use from an `Accept-Compression` value.
///
/// Tokens may carry `;q=<0..1>`: `q=0` forbids the algorithm, higher q wins, and equal
/// q keeps the client's order. A missing or unparsable q counts as 1. Unknown tokens
/// (including `*`) are ignored.
pub fn negotiate_compression(accept: Option<&str>) -> Option<&'static str> {
	let value = accept?;
	let mut best: Option<(f32, &'static str)> = None;
	let mut seen: Vec<&'static str> = Vec::new();

	for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
		let (name, weight) = split_quality(token);
		let alg = name.to_ascii_lowercase();

		let Some(&supported) = SUPPORTED_COMPRESSION.iter().find(|&&s| s == alg) else {
			continue;
		};

		// The first mention of an algorithm decides, like the first token used to.
		if seen.contains(&supported) {
			continue;
		}
		seen.push(supported);

		if weight <= 0.0 {
			continue;
		}

		if best.is_none_or(|(current, _)| weight > current) {
			best = Some((weight, supported));
		}
	}

	best.map(|(_, alg)| alg)
}

fn split_quality(token: &str) -> (&str, f32) {
	let mut parts = token.split(';');
	let name = parts.next().unwrap_or("").trim();

	let weight = parts
		.filter_map(|param| {
			let (key, value) = param.split_once('=')?;
			key.trim()
				.eq_ignore_ascii_case("q")
				.then(|| value.trim().parse::<f32>().ok())
				.flatten()
		})
		.next()
		.map_or(1.0, |q| if q.is_nan() { 1.0 } else { q.clamp(0.0, 1.0) });

	(name, weight)
}

/// Synchronous compression for small inputs or code already running on a blocking thread.
pub fn compress_body(body: &[u8], alg: &str) -> Option<Vec<u8>> {
	use std::io::Write;

	if body.is_empty() {
		return None;
	}

	match alg {
		"gzip" => {
			let mut encoder = flate2::write::GzEncoder::new(
				Vec::with_capacity(body.len() / 2 + 64),
				flate2::Compression::default(),
			);
			encoder.write_all(body).ok()?;
			encoder.finish().ok()
		}
		"zstd" => {
			let mut encoder =
				zstd::stream::Encoder::new(Vec::with_capacity(body.len() / 2 + 64), 3).ok()?;
			encoder.write_all(body).ok()?;
			encoder.finish().ok()
		}
		_ => None,
	}
}

/// Compresses on the blocking pool, at most one job per CPU core at a time.
pub async fn compress_blocking(body: Bytes, alg: &str) -> Option<Bytes> {
	let _permit = PERMITS.acquire().await.ok()?;
	let alg = alg.to_owned();

	match tokio::task::spawn_blocking(move || compress_body(&body, &alg)).await {
		Ok(result) => result.map(Bytes::from),
		Err(error) => {
			tracing::error!(error = %error, "compression task failed");
			None
		}
	}
}

fn memory_get(key: &MemoryKey) -> Option<Bytes> {
	lock_unpoisoned(&MEMORY).get(key).cloned()
}

fn memory_put(key: MemoryKey, value: &Bytes) {
	lock_unpoisoned(&MEMORY).put(key, value.clone(), value.len());
}

/// Compressed form of `content[start..=end]`, computed at most once per
/// (content, algorithm, range) and shared between concurrent requests.
/// Compression is deterministic, so a cache hit is byte-identical to a recompute.
#[allow(dead_code)] // used by tmutp only
pub async fn get_compressed_range_cached(
	content: &FileBody,
	start: usize,
	end: usize,
	alg: &str,
) -> Option<Bytes> {
	let alg = SUPPORTED_COMPRESSION.iter().find(|&&s| s == alg).copied()?;

	let key: RangeKey = (*content.digest(), alg, start, end);

	if let Some(hit) = lock_unpoisoned(&RANGE_MEMORY).get(&key).cloned() {
		return Some(hit);
	}

	let outcome = RANGE_FLIGHTS
		.run(key, || async move {
			if let Some(hit) = lock_unpoisoned(&RANGE_MEMORY).get(&key).cloned() {
				return Ok::<_, Infallible>(Some(hit));
			}

			let range = content.bytes().slice(start..=end);
			let compressed = compress_blocking(range, alg).await;

			if let Some(data) = &compressed {
				lock_unpoisoned(&RANGE_MEMORY).put(key, data.clone(), data.len());
			}

			Ok(compressed)
		})
		.await;

	outcome.unwrap_or_else(|never| match never {})
}

/// Returns the compressed form of `content`, computing it at most once per (content, alg)
/// no matter how many requests ask concurrently. `None` means "serve it uncompressed".
pub async fn get_compressed_cached(
	cache_dir: &Path,
	content: &FileBody,
	alg: &str,
	policy: DiskCachePolicy,
) -> Option<Bytes> {
	let alg = SUPPORTED_COMPRESSION.iter().find(|&&s| s == alg).copied()?;
	let key: MemoryKey = (*content.digest(), alg);

	if let Some(hit) = memory_get(&key) {
		return Some(hit);
	}

	let use_disk = policy.enable && (content.len() as u64) <= policy.source_maximum;

	let outcome = FLIGHTS
		.run(key, || async move {
			if let Some(hit) = memory_get(&key) {
				return Ok::<_, Infallible>(Some(hit));
			}

			if use_disk && let Some(hit) = disk::read(cache_dir, content, alg).await {
				memory_put(key, &hit);
				return Ok(Some(hit));
			}

			let compressed = compress_blocking(content.bytes().clone(), alg).await;

			if let Some(data) = &compressed {
				memory_put(key, data);

				if use_disk && let Err(error) = disk::write(cache_dir, content, alg, data).await {
					tracing::warn!(
						dir = %cache_dir.display(),
						error = %error,
						"failed to write compression cache entry"
					);
				}
			}

			Ok(compressed)
		})
		.await;

	outcome.unwrap_or_else(|never| match never {})
}

#[cfg(test)]
#[path = "compression_tests.rs"]
mod tests;
