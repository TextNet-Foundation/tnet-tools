//! Single source of truth for request path handling.
//!
//! Pipeline: `normalize_request_path` (percent-decode once, reject NUL and
//! invalid UTF-8, `\` is a separator, collapse `.`/`..`, no escape above root)
//! produces the canonical request path. Every consumer (script lookup, static
//! files, `Request.path` seen by scripts) must use that string only.
//! `resolve_path` then maps it onto the filesystem and applies the static
//! file policy.
//!
//! Static policy (constant, not configurable):
//! * dotfiles / dotdirs and `*.toml`, `*.pem`, `*.key` are answered exactly like
//!   a missing file (`Ok(None)` -> 31), so there is no existence oracle;
//! * a file whose name ends with a configured script extension is never served
//!   as static content (`PermissionDenied` -> 32), regardless of `order`,
//!   `hide_scripts_behind` and even when scripting is disabled, because the
//!   source must not leak after a config change. The name is checked both
//!   lexically (before touching the filesystem, so existence is not revealed)
//!   and on the canonical target (so a symlink alias cannot bypass it).

use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

pub const MAX_HEADERS: usize = 100;
pub const MAX_HEADER_LINE: usize = 8192;
pub const MAX_FIELDS: usize = 256;

const DEFAULT_LUA_EXTENSION: &str = ".script.lua";
const DEFAULT_RHAI_EXTENSION: &str = ".script.rhai";
const DENIED_EXTENSIONS: [&str; 3] = ["toml", "pem", "key"];
const INDEX_FILE: &str = "index.tmkup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
	/// NUL byte in the decoded path (maps to "30 Bad request").
	Nul,
	/// Decoded path is not valid UTF-8 (maps to "30 Bad request").
	InvalidUtf8,
	/// Path climbs above the root (maps to "32 Forbidden").
	OutsideRoot,
}

/// Configured script extensions with defaults applied; empty ones are dropped.
pub fn script_extensions(lua: Option<&str>, rhai: Option<&str>) -> Vec<String> {
	[
		lua.unwrap_or(DEFAULT_LUA_EXTENSION),
		rhai.unwrap_or(DEFAULT_RHAI_EXTENSION),
	]
	.into_iter()
	.filter(|ext| !ext.is_empty())
	.map(str::to_owned)
	.collect()
}

/// Percent-decodes exactly once, rejecting NUL and invalid UTF-8.
pub fn decode_request_path(raw: &str) -> Result<String, PathError> {
	let decoded = percent_decode_str(raw)
		.decode_utf8()
		.map_err(|_| PathError::InvalidUtf8)?;

	if decoded.contains('\0') {
		return Err(PathError::Nul);
	}

	Ok(decoded.into_owned())
}

fn segments(decoded: &str) -> Result<(Vec<String>, bool), PathError> {
	let unified = decoded.replace('\\', "/");
	let mut parts: Vec<String> = Vec::new();
	let mut is_directory = true;

	for part in unified.split('/') {
		is_directory = matches!(part, "" | "." | "..");

		match part {
			"" | "." => {}
			".." => {
				parts.pop().ok_or(PathError::OutsideRoot)?;
			}
			other => parts.push(other.to_owned()),
		}
	}

	let is_empty = parts.is_empty();
	Ok((parts, is_directory || is_empty))
}

fn join_canonical(parts: &[String], is_directory: bool) -> String {
	if parts.is_empty() {
		return "/".to_owned();
	}

	let mut out = String::new();

	for part in parts {
		out.push('/');
		out.push_str(part);
	}

	if is_directory {
		out.push('/');
	}

	out
}

/// Collapses an already decoded path into canonical form (`/a/b` or `/a/b/`).
pub fn collapse_path(decoded: &str) -> Result<String, PathError> {
	let (parts, is_directory) = segments(decoded)?;

	Ok(join_canonical(&parts, is_directory))
}

/// Full normalization of the raw (still percent-encoded) request path.
pub fn normalize_request_path(raw: &str) -> Result<String, PathError> {
	collapse_path(&decode_request_path(raw)?)
}

enum Verdict {
	Allow,
	Hidden,
	Script,
}

fn judge<'a>(names: impl Iterator<Item = &'a str>, script_exts: &[String]) -> Verdict {
	let mut verdict = Verdict::Allow;

	for name in names {
		if name.starts_with('.') {
			return Verdict::Hidden;
		}

		let lower = name.to_ascii_lowercase();
		let denied = Path::new(&lower)
			.extension()
			.and_then(|ext| ext.to_str())
			.is_some_and(|ext| DENIED_EXTENSIONS.contains(&ext));

		if denied {
			return Verdict::Hidden;
		}

		if script_exts
			.iter()
			.any(|ext| lower.ends_with(&ext.to_ascii_lowercase()))
		{
			verdict = Verdict::Script;
		}
	}

	verdict
}

fn denied(message: &'static str) -> Error {
	Error::new(ErrorKind::PermissionDenied, message)
}

fn map_path_error(error: PathError) -> Error {
	match error {
		PathError::OutsideRoot => denied("Path is outside root"),
		PathError::Nul | PathError::InvalidUtf8 => {
			Error::new(ErrorKind::InvalidInput, "Invalid request path")
		}
	}
}

/// Maps a canonical request path (see `normalize_request_path`) to a file.
///
/// `Ok(None)` = not found or hidden by policy; `PermissionDenied` = outside
/// root or script source. The input is collapsed again but never decoded again.
#[cfg(test)]
pub fn resolve_path(
	root: &str,
	path: &str,
	script_exts: &[String],
) -> std::io::Result<Option<PathBuf>> {
	let canonical_root = fs::canonicalize(root)?;
	resolve_path_in(&canonical_root, path, script_exts)
}

/// Canonical form of each seen root, computed once per process. A server binds
/// its root at startup, so re-canonicalizing it on every request is pure cost.
static CANONICAL_ROOTS: LazyLock<Mutex<HashMap<String, PathBuf>>> =
	LazyLock::new(|| Mutex::new(HashMap::new()));

fn canonical_root_cached(root: &str) -> std::io::Result<PathBuf> {
	let mut cache = CANONICAL_ROOTS.lock().unwrap_or_else(|e| e.into_inner());

	if let Some(cached) = cache.get(root) {
		return Ok(cached.clone());
	}

	let canonical = fs::canonicalize(root)?;
	cache.insert(root.to_owned(), canonical.clone());
	Ok(canonical)
}

/// [`resolve_path`] with the canonical root cached per process: identical
/// verdicts, one `canonicalize(root)` syscall saved per request.
pub fn resolve_path_cached_root(
	root: &str,
	path: &str,
	script_exts: &[String],
) -> std::io::Result<Option<PathBuf>> {
	let canonical_root = canonical_root_cached(root)?;
	resolve_path_in(&canonical_root, path, script_exts)
}

/// Same as [`resolve_path`], but for a root that is already canonicalized
/// (e.g. cached once in server state), so it is not re-canonicalized per request.
pub fn resolve_path_in(
	canonical_root: &Path,
	path: &str,
	script_exts: &[String],
) -> std::io::Result<Option<PathBuf>> {
	let (mut parts, is_directory) = segments(path).map_err(map_path_error)?;

	if is_directory {
		parts.push(INDEX_FILE.to_owned());
	}

	// The last name is checked before touching the filesystem on purpose.
	match judge(parts.iter().map(String::as_str), script_exts) {
		Verdict::Allow => {}
		Verdict::Hidden => return Ok(None),
		Verdict::Script => return Err(denied("Script sources are not served")),
	}

	let mut current = canonical_root.to_path_buf();

	for (index, part) in parts.iter().enumerate() {
		current.push(part);

		// Canonicalize alone distinguishes "missing" from other errors exactly
		// like symlink_metadata did: a missing component, a dangling symlink and
		// a broken tail all surface as NotFound here and count as missing.
		current = match fs::canonicalize(&current) {
			Ok(canonical) => canonical,
			Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
			Err(error) => return Err(error),
		};

		if !current.starts_with(canonical_root) {
			return Err(denied("Path is outside root"));
		}

		if index + 1 < parts.len() && !current.is_dir() {
			return Ok(None);
		}
	}

	if !current.is_file() {
		return Ok(None);
	}

	let relative = current
		.strip_prefix(canonical_root)
		.map_err(|_| denied("Path is outside root"))?;
	let names: Vec<String> = relative
		.components()
		.map(|component| component.as_os_str().to_string_lossy().into_owned())
		.collect();

	match judge(names.iter().map(String::as_str), script_exts) {
		Verdict::Allow => Ok(Some(current)),
		Verdict::Hidden => Ok(None),
		Verdict::Script => Err(denied("Script sources are not served")),
	}
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
