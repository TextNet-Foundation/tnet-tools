use bytes::Bytes;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

const FILE_CACHE_CAPACITY: usize = 64;

type FileCache = LruCache<FileCacheKey, CachedFile>;

#[derive(Clone)]
pub struct CachedFile {
    pub bytes: Bytes,
    pub modified: Option<SystemTime>,
    #[allow(dead_code)]
    pub sha256_hex: String,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FileCacheKey {
    path: PathBuf,
    modified: Option<SystemTime>,
    size: u64,
}

static FILE_CACHE: Mutex<Option<FileCache>> = Mutex::new(None);

fn ensure_file_cache() {
    let mut guard = FILE_CACHE.lock().unwrap();
    if guard.is_none() {
        guard.replace(LruCache::new(
            NonZeroUsize::new(FILE_CACHE_CAPACITY).unwrap(),
        ));
    }
}

pub async fn read_file_cached(path: &Path) -> std::io::Result<CachedFile> {
    let metadata = tokio::fs::metadata(path).await?;
    let modified = metadata.modified().ok();
    let size = metadata.len();
    let key = FileCacheKey {
        path: path.to_path_buf(),
        modified,
        size,
    };

    {
        ensure_file_cache();
        let mut guard = FILE_CACHE.lock().unwrap();
        if let Some(cache) = guard.as_mut()
            && let Some(entry) = cache.get(&key)
        {
            return Ok(entry.clone());
        }
    }

    let bytes = Bytes::from(tokio::fs::read(path).await?);
    let digest = Sha256::digest(&bytes);
    let sha256_hex = format!("{:x}", digest);

    let entry = CachedFile {
        bytes,
        modified,
        sha256_hex,
    };

    {
        let mut guard = FILE_CACHE.lock().unwrap();
        if let Some(cache) = guard.as_mut() {
            cache.put(key, entry.clone());
        }
    }

    Ok(entry)
}
