use anyhow::{Context, Result, anyhow};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

pub fn validate_port(port: u16) -> Result<()> {
	if port == 0 {
		return Err(anyhow!("port must be in 1..=65535, got 0"));
	}
	Ok(())
}

pub fn validate_bind_address(address: &str) -> Result<()> {
	address
		.parse::<IpAddr>()
		.map(|_| ())
		.map_err(|_| anyhow!("bind_address '{address}' is not a valid IP address"))
}

/// Script suffixes must look like `.script.lua`: a dot followed by at least one character.
pub fn validate_script_extensions(extensions: &[(&str, Option<&str>)]) -> Result<()> {
	for (name, value) in extensions {
		if let Some(value) = value
			&& (!value.starts_with('.') || value.len() < 2)
		{
			return Err(anyhow!(
				"scripting.{name} must start with '.' and have at least one more character, got '{value}'"
			));
		}
	}
	Ok(())
}

/// Removes `.`/`..` lexically, so paths that do not exist yet can still be compared.
fn lexical_clean(path: &Path) -> PathBuf {
	let mut clean = PathBuf::new();
	for component in path.components() {
		match component {
			Component::CurDir => {}
			Component::ParentDir => {
				clean.pop();
			}
			other => clean.push(other.as_os_str()),
		}
	}
	clean
}

/// Canonicalizes the longest existing prefix of `path` and appends the rest, so symlinked
/// ancestors are resolved even when the leaf has not been created yet.
fn canonicalize_lenient(path: &Path) -> PathBuf {
	let mut missing = Vec::new();
	let mut current = path.to_path_buf();

	loop {
		if let Ok(real) = std::fs::canonicalize(&current) {
			return missing.iter().rev().fold(real, |acc, part| acc.join(part));
		}
		match (current.file_name().map(|n| n.to_owned()), current.parent()) {
			(Some(name), Some(parent)) => {
				missing.push(name);
				current = parent.to_path_buf();
			}
			_ => return path.to_path_buf(),
		}
	}
}

/// Resolves the compression cache directory.
///
/// A relative path is taken relative to the directory of the config file (not to `root`,
/// which is served to clients). The server refuses to start if the result lies inside `root`.
pub fn resolve_cache_dir(configured: &str, config_path: &Path, root: &Path) -> Result<PathBuf> {
	let raw = PathBuf::from(configured);

	let joined = if raw.is_absolute() {
		raw
	} else {
		let base = match config_path.parent() {
			Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
			_ => PathBuf::from("."),
		};
		let base = if base.is_absolute() {
			base
		} else {
			std::env::current_dir()
				.context("Cannot determine the current directory")?
				.join(base)
		};
		base.join(raw)
	};

	let cache_dir = canonicalize_lenient(&lexical_clean(&joined));
	let root = canonicalize_lenient(&lexical_clean(&if root.is_absolute() {
		root.to_path_buf()
	} else {
		std::env::current_dir()
			.context("Cannot determine the current directory")?
			.join(root)
	}));

	if cache_dir.starts_with(&root) {
		return Err(anyhow!(
			"compression_cache '{}' resolves to {} which is inside root {}; \
			 files there would be served to clients. Point compression_cache outside root.",
			configured,
			cache_dir.display(),
			root.display()
		));
	}

	Ok(cache_dir)
}

/// Creates the cache directory with mode 0700 (unix). An already existing directory is left
/// alone, but a warning is logged if others can access it.
pub fn prepare_cache_dir(dir: &Path) -> Result<()> {
	let existed = dir.is_dir();

	std::fs::create_dir_all(dir).with_context(|| {
		format!(
			"Cannot create compression cache directory: {}",
			dir.display()
		)
	})?;

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;

		if !existed {
			std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
				.with_context(|| format!("Cannot restrict permissions of {}", dir.display()))?;
		} else if let Ok(metadata) = std::fs::metadata(dir)
			&& metadata.permissions().mode() & 0o077 != 0
		{
			tracing::warn!(
				path = %dir.display(),
				"compression cache directory is accessible by group/others; chmod 700 it"
			);
		}
	}

	#[cfg(not(unix))]
	let _ = existed;

	Ok(())
}
