//! In-memory cache of compressed byte ranges (TMUTP only: TBIP never compresses ranges
//! through this path).
//!
//! Range responses are keyed by (source digest, algorithm, start, end): a repeated
//! range request must not re-compress the same bytes. Memory-only on purpose —
//! ranges are transient, the disk cache stays reserved for whole files.

use crate::common::cache_util::{SingleFlight, WeightedLru, lock_unpoisoned};
use crate::common::{FileBody, SUPPORTED_COMPRESSION, compress_blocking};
use bytes::Bytes;
use std::convert::Infallible;
use std::sync::{LazyLock, Mutex};

type RangeKey = ([u8; 32], &'static str, usize, usize);

const RANGE_MEMORY_BUDGET: usize = 32 * 1024 * 1024;

static RANGE_MEMORY: LazyLock<Mutex<WeightedLru<RangeKey, Bytes>>> =
	LazyLock::new(|| Mutex::new(WeightedLru::new(RANGE_MEMORY_BUDGET)));

static RANGE_FLIGHTS: LazyLock<SingleFlight<RangeKey, Option<Bytes>>> =
	LazyLock::new(SingleFlight::new);

/// Compressed form of `content[start..=end]`, computed at most once per
/// (content, algorithm, range) and shared between concurrent requests.
/// Compression is deterministic, so a cache hit is byte-identical to a recompute.
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
