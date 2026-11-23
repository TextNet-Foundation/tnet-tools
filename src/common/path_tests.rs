use super::*;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Unique temp directory (pid + counter), removed on drop.
struct TempDir(PathBuf);

impl TempDir {
	fn new() -> Self {
		let id = COUNTER.fetch_add(1, Ordering::Relaxed);
		let dir =
			std::env::temp_dir().join(format!("tnet-path-test-{}-{}", std::process::id(), id));
		fs::create_dir_all(&dir).expect("create temp dir");
		TempDir(dir)
	}

	fn path(&self) -> &Path {
		&self.0
	}

	fn write(&self, relative: &str, data: &[u8]) {
		let target = self.0.join(relative);
		fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
		fs::write(target, data).expect("write");
	}
}

impl Drop for TempDir {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

fn site() -> TempDir {
	let dir = TempDir::new();
	for file in [
		"index.tmkup",
		"hello.txt",
		"sub/file.txt",
		"sub/.hidden",
		".env",
		".git/config",
		"secrets.toml",
		"cert.pem",
		"server.key",
		"a.script.lua",
		"x/f.script.lua",
		"foo.script.rhai",
		"api.v2.script.lua",
	] {
		dir.write(file, b"data");
	}
	dir
}

fn exts() -> Vec<String> {
	script_extensions(None, None)
}

/// Full pipeline used by both servers: normalize once, then resolve.
fn serve(dir: &TempDir, raw: &str) -> Result<std::io::Result<Option<PathBuf>>, PathError> {
	let path = normalize_request_path(raw)?;
	Ok(resolve_path(
		dir.path().to_str().expect("utf8"),
		&path,
		&exts(),
	))
}

fn assert_forbidden(dir: &TempDir, raw: &str) {
	match serve(dir, raw) {
		Ok(Err(error)) if error.kind() == ErrorKind::PermissionDenied => {}
		Err(PathError::OutsideRoot) => {}
		other => panic!("{raw}: expected forbidden, got {other:?}"),
	}
}

fn assert_not_served(dir: &TempDir, raw: &str) {
	match serve(dir, raw) {
		Ok(Ok(None)) => {}
		other => panic!("{raw}: expected hidden/missing, got {other:?}"),
	}
}

#[test]
fn normalize_rejects_escapes() {
	for raw in [
		"../x",
		"/../x",
		"a/../../x",
		"..\\..\\x",
		"%2e%2e/%2e%2e/etc/passwd",
		"a%5c..%5c..%5cx",
		"%2E%2E%2fx",
	] {
		assert_eq!(
			normalize_request_path(raw),
			Err(PathError::OutsideRoot),
			"{raw}"
		);
	}
}

#[test]
fn normalize_rejects_nul_and_bad_utf8() {
	assert_eq!(normalize_request_path("/a%00b"), Err(PathError::Nul));
	assert_eq!(normalize_request_path("%00"), Err(PathError::Nul));
	assert_eq!(normalize_request_path("/%ff"), Err(PathError::InvalidUtf8));
}

#[test]
fn normalize_decodes_exactly_once() {
	assert_eq!(
		normalize_request_path("/%252e%252e/x").as_deref(),
		Ok("/%2e%2e/x")
	);
	assert_eq!(normalize_request_path("/a%5cb").as_deref(), Ok("/a/b"));
}

#[test]
fn normalize_collapses() {
	let cases = [
		("", "/"),
		("/", "/"),
		("/a/./b", "/a/b"),
		("/a/b/../c", "/a/c"),
		("//a///b", "/a/b"),
		("/a/b/", "/a/b/"),
		("/a/b/.", "/a/b/"),
		("/a/b/..", "/a/"),
		("/a/..", "/"),
		("\\a\\b", "/a/b"),
	];
	for (raw, expected) in cases {
		assert_eq!(
			normalize_request_path(raw).as_deref(),
			Ok(expected),
			"{raw}"
		);
	}
}

#[test]
fn resolve_path_rejects_escape_directly() {
	let dir = site();
	let error =
		resolve_path(dir.path().to_str().expect("utf8"), "../x", &exts()).expect_err("must fail");
	assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn serves_existing_files_and_index() {
	let dir = site();
	let root = fs::canonicalize(dir.path()).expect("canonical");
	assert_eq!(
		serve(&dir, "hello.txt").unwrap().unwrap(),
		Some(root.join("hello.txt"))
	);
	assert_eq!(
		serve(&dir, "sub/file.txt").unwrap().unwrap(),
		Some(root.join("sub/file.txt"))
	);
	assert_eq!(
		serve(&dir, "").unwrap().unwrap(),
		Some(root.join("index.tmkup"))
	);
	assert_eq!(
		serve(&dir, "/").unwrap().unwrap(),
		Some(root.join("index.tmkup"))
	);
	assert_not_served(&dir, "sub/");
	assert_not_served(&dir, "nope.txt");
	assert_not_served(&dir, "hello.txt/more");
}

#[test]
fn script_bypasses_do_not_serve_source() {
	let dir = site();
	// Direct and encoded-separator forms are refused outright.
	assert_forbidden(&dir, "/x%5Cf.script.lua");
	assert_forbidden(&dir, "/x/f.script.lua");
	assert_forbidden(&dir, "/api.v2.script.lua");
	assert_forbidden(&dir, "/foo.script.rhai");
	assert_forbidden(&dir, "/FOO.SCRIPT.RHAI");
	assert_forbidden(&dir, "/nonexistent.script.lua");
	// Dot segments collapse to a directory, never to the source file.
	// Script-extension names are refused (PermissionDenied) even as directories.
	assert_forbidden(&dir, "/a.script.lua/.");
	assert_forbidden(&dir, "/a.script.lua/x/..");
}

#[test]
fn custom_script_extension_is_denied() {
	let dir = site();
	dir.write("page.tscript", b"code");
	let custom = script_extensions(Some(".tscript"), None);
	let path = normalize_request_path("/page.tscript").unwrap();
	let error = resolve_path(dir.path().to_str().expect("utf8"), &path, &custom).unwrap_err();
	assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn dotfiles_and_secret_extensions_look_missing() {
	let dir = site();
	for raw in [
		"/.env",
		"/.git/config",
		"/sub/.hidden",
		"/.nonexistent",
		"/secrets.toml",
		"/cert.pem",
		"/server.key",
		"/SERVER.KEY",
		"/sub/../.env",
		"/%2eenv",
	] {
		assert_not_served(&dir, raw);
	}
}

#[cfg(unix)]
mod symlinks {
	use super::*;
	use std::os::unix::fs::symlink;

	fn outside() -> TempDir {
		let dir = TempDir::new();
		dir.write("secret.txt", b"top secret");
		dir
	}

	#[test]
	fn file_symlink_outside_root_is_rejected() {
		let dir = site();
		let out = outside();
		symlink(out.path().join("secret.txt"), dir.path().join("link")).unwrap();
		assert_forbidden(&dir, "/link");
	}

	#[test]
	fn dir_symlink_outside_root_is_rejected() {
		let dir = site();
		let out = outside();
		symlink(out.path(), dir.path().join("linkdir")).unwrap();
		assert_forbidden(&dir, "/linkdir/secret.txt");
	}

	#[test]
	fn dangling_symlink_gives_nothing() {
		let dir = site();
		symlink("/nonexistent/target", dir.path().join("dangle")).unwrap();
		assert_not_served(&dir, "/dangle");
	}

	#[test]
	fn symlink_loop_gives_nothing() {
		let dir = site();
		symlink("loop2", dir.path().join("loop1")).unwrap();
		symlink("loop1", dir.path().join("loop2")).unwrap();
		match serve(&dir, "/loop1") {
			Ok(Ok(None)) => {}
			Ok(Err(error)) if error.kind() != ErrorKind::PermissionDenied => {}
			other => panic!("loop must not be served: {other:?}"),
		}
	}

	#[test]
	fn inside_symlink_cannot_alias_hidden_or_script() {
		let dir = site();
		symlink("a.script.lua", dir.path().join("alias.txt")).unwrap();
		symlink(".env", dir.path().join("env.txt")).unwrap();
		symlink("hello.txt", dir.path().join("ok.txt")).unwrap();
		assert_forbidden(&dir, "/alias.txt");
		assert_not_served(&dir, "/env.txt");
		assert!(matches!(serve(&dir, "/ok.txt"), Ok(Ok(Some(_)))));
	}
}
