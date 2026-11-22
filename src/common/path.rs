use std::fs;
use std::path::PathBuf;

pub fn resolve_path(root: &str, path: &str) -> std::io::Result<Option<PathBuf>> {
	use std::io::{Error, ErrorKind};
	use std::path::Component;

	let canonical_root = fs::canonicalize(root)?;

	let normalized_path = path.replace('\\', "/");
	let is_directory = normalized_path.is_empty() || normalized_path.ends_with('/');

	let mut relative = PathBuf::new();

	for component in PathBuf::from(&normalized_path).components() {
		match component {
			Component::Prefix(_) => {
				return Err(Error::new(
					ErrorKind::PermissionDenied,
					"Path is outside root",
				));
			}
			Component::RootDir | Component::CurDir => {}
			Component::Normal(part) => relative.push(part),
			Component::ParentDir => {
				if !relative.pop() {
					return Err(Error::new(
						ErrorKind::PermissionDenied,
						"Path is outside root",
					));
				}
			}
		}
	}

	if is_directory {
		relative.push("index.tmkup");
	}

	if relative.as_os_str().is_empty() {
		relative.push("index.tmkup");
	}

	let mut current = canonical_root.clone();
	let components: Vec<_> = relative.components().collect();

	for (index, component) in components.iter().enumerate() {
		let Component::Normal(part) = component else {
			continue;
		};

		current.push(part);

		match fs::symlink_metadata(&current) {
			Ok(_) => {
				let canonical = fs::canonicalize(&current)?;

				if !canonical.starts_with(&canonical_root) {
					return Err(Error::new(
						ErrorKind::PermissionDenied,
						"Path is outside root",
					));
				}

				current = canonical;

				if index + 1 < components.len() && !current.is_dir() {
					return Ok(None);
				}
			}
			Err(error) if error.kind() == ErrorKind::NotFound => {
				return Ok(None);
			}
			Err(error) => return Err(error),
		}
	}

	if current.is_file() {
		Ok(Some(current))
	} else {
		Ok(None)
	}
}

pub fn percent_decode(value: &str) -> String {
	use percent_encoding::percent_decode_str;

	percent_decode_str(value).decode_utf8_lossy().into_owned()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	fn temp_root(name: &str) -> std::path::PathBuf {
		let dir = std::env::temp_dir().join(format!("tnet-tmutp-test-{}", name));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		fs::write(dir.join("index.tmkup"), b"idx").unwrap();
		fs::write(dir.join("hello.txt"), b"hi").unwrap();
		fs::create_dir_all(dir.join("sub")).unwrap();
		fs::write(dir.join("sub").join("file.txt"), b"x").unwrap();
		dir
	}

	#[test]
	fn resolve_path_blocks_traversal() {
		let root = temp_root("trav");
		let r = resolve_path(root.to_str().unwrap(), "../../etc/passwd");
		assert!(r.is_err() || r.unwrap().is_none());
		let _ = fs::remove_dir_all(&root);
	}

	#[test]
	fn resolve_path_serves_existing_file() {
		let root = temp_root("file");
		let r = resolve_path(root.to_str().unwrap(), "hello.txt").unwrap();
		assert!(r.is_some());
		let _ = fs::remove_dir_all(&root);
	}

	#[test]
	fn resolve_path_directory_index() {
		let root = temp_root("dir");
		let r = resolve_path(root.to_str().unwrap(), "").unwrap();
		assert!(r.is_some());
		let _ = fs::remove_dir_all(&root);
	}

	#[test]
	fn resolve_path_missing_returns_none() {
		let root = temp_root("missing");
		let r = resolve_path(root.to_str().unwrap(), "nope.txt").unwrap();
		assert!(r.is_none());
		let _ = fs::remove_dir_all(&root);
	}
}
