//! Песочница файловых операций скриптов: всё внутри root, без обхода через `..`
//! и симлинки, с лимитами размера и защитой исходников скриптов.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub mod source;

/// Максимальный размер данных одной записи.
pub const MAX_WRITE_BYTES: usize = 8 * 1024 * 1024;
/// Максимальный размер файла, читаемого скриптом.
pub const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;

fn denied() -> io::Error {
	io::Error::new(io::ErrorKind::PermissionDenied, "Access denied")
}

#[derive(Debug)]
struct Inner {
	root: PathBuf,
	protected_suffixes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Sandbox {
	inner: Arc<Inner>,
}

impl Sandbox {
	pub fn new(root: impl Into<PathBuf>, protected_suffixes: Vec<String>) -> Self {
		Self {
			inner: Arc::new(Inner {
				root: root.into(),
				protected_suffixes: protected_suffixes
					.into_iter()
					.map(|s| s.to_ascii_lowercase())
					.collect(),
			}),
		}
	}

	fn canonical_root(&self) -> io::Result<PathBuf> {
		fs::canonicalize(&self.inner.root)
	}

	/// Разбирает запрошенный путь на нормальные компоненты. Ведущие `/` отбрасываются
	/// (путь считается относительным root); `..`, префиксы и пустой путь запрещены.
	fn components(requested: &str) -> io::Result<Vec<OsString>> {
		let relative = requested.trim_start_matches(['/', '\\']);
		let mut parts = Vec::new();

		for component in Path::new(relative).components() {
			match component {
				Component::Normal(part) => parts.push(part.to_os_string()),
				Component::CurDir => {}
				Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
					return Err(denied());
				}
			}
		}

		if parts.is_empty() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Invalid file path",
			));
		}

		Ok(parts)
	}

	fn is_protected(&self, name: &OsStr) -> bool {
		let lower = name.to_string_lossy().to_ascii_lowercase();
		self.inner
			.protected_suffixes
			.iter()
			.any(|suffix| lower.ends_with(suffix.as_str()))
	}

	/// Канонический путь существующего файла; результат всегда внутри root.
	pub fn resolve_existing(&self, requested: &str) -> io::Result<PathBuf> {
		let root = self.canonical_root()?;
		let mut candidate = root.clone();
		candidate.extend(Self::components(requested)?);

		let canonical = fs::canonicalize(candidate)?;
		if !canonical.starts_with(&root) {
			return Err(denied());
		}

		Ok(canonical)
	}

	/// Каноническая родительская директория записи. Каталоги создаются только
	/// после того, как весь путь проверен, и только для реально отсутствующих компонентов.
	fn locate_parent(&self, parts: &[OsString], create: bool) -> io::Result<PathBuf> {
		let root = self.canonical_root()?;
		let dirs = &parts[..parts.len() - 1];
		let mut current = root.clone();
		let mut resolved = 0;

		while resolved < dirs.len() {
			let next = current.join(&dirs[resolved]);
			match fs::symlink_metadata(&next) {
				Ok(_) => {
					// Висячий симлинк даст здесь NotFound и ничего не создаст.
					let canonical = fs::canonicalize(&next)?;
					if !canonical.starts_with(&root) || !canonical.is_dir() {
						return Err(denied());
					}
					current = canonical;
					resolved += 1;
				}
				Err(e) if e.kind() == io::ErrorKind::NotFound => break,
				Err(e) => return Err(e),
			}
		}

		if resolved < dirs.len() {
			if !create {
				return Err(io::Error::from(io::ErrorKind::NotFound));
			}
			current.extend(&dirs[resolved..]);
			fs::create_dir_all(&current)?;
		}

		Ok(current)
	}

	pub fn read(&self, requested: &str) -> io::Result<Vec<u8>> {
		let path = self.resolve_existing(requested)?;
		let file = fs::File::open(&path)?;
		let metadata = file.metadata()?;

		if !metadata.is_file() || metadata.len() > MAX_READ_BYTES {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Not a readable file",
			));
		}

		let mut data = Vec::new();
		file.take(MAX_READ_BYTES).read_to_end(&mut data)?;
		Ok(data)
	}

	/// Для путей вне root или несуществующих возвращает false (без оракула).
	pub fn exists(&self, requested: &str) -> bool {
		self.resolve_existing(requested).is_ok()
	}

	pub fn write(&self, requested: &str, data: &[u8]) -> io::Result<()> {
		if data.len() > MAX_WRITE_BYTES {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Data too large",
			));
		}

		let parts = Self::components(requested)?;
		let name = parts.last().ok_or_else(denied)?;
		if self.is_protected(name) {
			return Err(denied());
		}

		let target = self.locate_parent(&parts, true)?.join(name);

		match fs::symlink_metadata(&target) {
			Ok(md) if md.file_type().is_symlink() || !md.is_file() => return Err(denied()),
			Ok(_) => {}
			Err(e) if e.kind() == io::ErrorKind::NotFound => {}
			Err(e) => return Err(e),
		}

		// Открываем без усечения: сначала убеждаемся, что открыт тот же обычный файл.
		let mut file = fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(false)
			.open(&target)?;

		if !file.metadata()?.is_file() || !same_entry(&file, &target)? {
			return Err(denied());
		}

		file.set_len(0)?;
		file.write_all(data)
	}

	/// Удаляет сам файл (симлинк удаляется как ссылка, цель не затрагивается).
	pub fn remove(&self, requested: &str) -> io::Result<()> {
		let parts = Self::components(requested)?;
		let name = parts.last().ok_or_else(denied)?;
		if self.is_protected(name) {
			return Err(denied());
		}

		let target = self.locate_parent(&parts, false)?.join(name);
		let md = fs::symlink_metadata(&target)?;
		if md.is_dir() {
			return Err(denied());
		}

		fs::remove_file(&target)
	}
}

#[cfg(unix)]
fn same_entry(file: &fs::File, path: &Path) -> io::Result<bool> {
	use std::os::unix::fs::MetadataExt;

	let opened = file.metadata()?;
	let on_disk = fs::symlink_metadata(path)?;
	Ok(!on_disk.file_type().is_symlink()
		&& opened.dev() == on_disk.dev()
		&& opened.ino() == on_disk.ino())
}

#[cfg(not(unix))]
fn same_entry(_file: &fs::File, path: &Path) -> io::Result<bool> {
	Ok(!fs::symlink_metadata(path)?.file_type().is_symlink())
}

#[cfg(test)]
#[path = "fs_tests.rs"]
mod tests;
