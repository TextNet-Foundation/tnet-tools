use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Максимальный размер файла скрипта.
pub const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;
const MAX_CACHED_SCRIPTS: usize = 256;

type CacheEntry = (SystemTime, u64, Arc<str>);

/// Загрузчик исходников скриптов. При `hot_reload = true` читает диск на каждый
/// запрос; иначе отдаёт кэш по (mtime, size) без повторного чтения.
#[derive(Debug)]
pub struct SourceCache {
	hot_reload: bool,
	entries: Mutex<HashMap<PathBuf, CacheEntry>>,
}

impl SourceCache {
	pub fn new(hot_reload: bool) -> Self {
		Self {
			hot_reload,
			entries: Mutex::new(HashMap::new()),
		}
	}

	pub fn load(&self, path: &Path) -> io::Result<Arc<str>> {
		let metadata = fs::metadata(path)?;
		if !metadata.is_file() || metadata.len() > MAX_SCRIPT_BYTES {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Script is not a regular file or is too large",
			));
		}

		if self.hot_reload {
			return Ok(Arc::from(fs::read_to_string(path)?));
		}

		let stamp = (metadata.modified()?, metadata.len());
		let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

		if let Some((mtime, len, source)) = entries.get(path)
			&& (*mtime, *len) == stamp
		{
			return Ok(source.clone());
		}

		let source: Arc<str> = Arc::from(fs::read_to_string(path)?);
		if entries.len() >= MAX_CACHED_SCRIPTS {
			entries.clear();
		}
		entries.insert(path.to_path_buf(), (stamp.0, stamp.1, source.clone()));
		Ok(source)
	}
}
