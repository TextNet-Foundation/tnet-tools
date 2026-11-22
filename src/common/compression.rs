use crate::config::SUPPORTED_COMPRESSION;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const COMPRESSED_CACHE_CAPACITY: usize = 128;

type CompressedCache = LruCache<([u8; 32], String), Vec<u8>>;

static COMPRESSED_CACHE: Mutex<Option<CompressedCache>> = Mutex::new(None);

fn ensure_compressed_cache() {
	let mut guard = COMPRESSED_CACHE.lock().unwrap();
	if guard.is_none() {
		guard.replace(LruCache::new(
			NonZeroUsize::new(COMPRESSED_CACHE_CAPACITY).unwrap(),
		));
	}
}

pub fn negotiate_compression(accept: Option<&str>) -> Option<&'static str> {
	let value = accept?;

	for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
		let alg = token.to_ascii_lowercase();

		if let Some(&supported) = SUPPORTED_COMPRESSION.iter().find(|&&s| s == alg) {
			return Some(supported);
		}
	}

	None
}

pub fn compress_body(body: &[u8], alg: &str) -> Option<Vec<u8>> {
	use std::io::Write;

	if body.is_empty() {
		return None;
	}

	match alg {
		"gzip" => {
			let mut encoder = flate2::write::GzEncoder::new(
				Vec::with_capacity(body.len()),
				flate2::Compression::default(),
			);
			encoder.write_all(body).ok()?;
			encoder.finish().ok()
		}
		"zstd" => {
			let mut encoder = zstd::stream::Encoder::new(Vec::with_capacity(body.len()), 3).ok()?;
			encoder.write_all(body).ok()?;
			encoder.finish().ok()
		}
		_ => None,
	}
}

pub fn cache_path(cache_dir: &Path, source_path: &Path, alg: &str) -> PathBuf {
	let path_hash = Sha256::digest(source_path.to_string_lossy().as_bytes());
	let hex = format!("{:x}", path_hash);
	cache_dir.join(format!("{}.{}", hex, alg))
}

pub async fn get_compressed_cached(
	cache_dir: &Path,
	source_path: &Path,
	body: &[u8],
	alg: &str,
	cache_enable: bool,
	source_maximum: u64,
) -> Option<Vec<u8>> {
	let can_cache = cache_enable && (body.len() as u64) <= source_maximum;

	let body_hash = Sha256::digest(body);
	let mut key_hash = [0u8; 32];
	key_hash.copy_from_slice(&body_hash);

	let key = (key_hash, alg.to_string());

	// In-memory LRU first to avoid disk I/O.
	{
		ensure_compressed_cache();
		let mut guard = COMPRESSED_CACHE.lock().unwrap();
		if let Some(cache) = guard.as_mut()
			&& let Some(cached) = cache.get(&key)
		{
			return Some(cached.clone());
		}
	}

	let cache_file = cache_path(cache_dir, source_path, alg);

	if can_cache && let Ok(data) = tokio::fs::read(&cache_file).await {
		if data.len() >= 32 && data[..32] == body_hash[..] {
			let compressed = data[32..].to_vec();

			{
				ensure_compressed_cache();
				let mut guard = COMPRESSED_CACHE.lock().unwrap();
				if let Some(cache) = guard.as_mut() {
					cache.put(key.clone(), compressed.clone());
				}
			}

			return Some(compressed);
		}

		let _ = tokio::fs::remove_file(&cache_file).await;
	}

	let compressed = compress_body(body, alg)?;

	{
		ensure_compressed_cache();
		let mut guard = COMPRESSED_CACHE.lock().unwrap();
		if let Some(cache) = guard.as_mut() {
			cache.put(key, compressed.clone());
		}
	}

	if can_cache {
		let mut cache_data = Vec::with_capacity(32 + compressed.len());
		cache_data.extend_from_slice(&body_hash);
		cache_data.extend_from_slice(&compressed);

		let _ = tokio::fs::write(&cache_file, &cache_data).await;
	}

	Some(compressed)
}
