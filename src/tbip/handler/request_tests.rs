use super::*;
use crate::script_engine::ScriptingConfig;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl Drop for TempDir {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

fn state() -> (TempDir, AppState) {
	let id = COUNTER.fetch_add(1, Ordering::Relaxed);
	let dir = std::env::temp_dir().join(format!("tnet--req-{}-{}", std::process::id(), id));
	fs::create_dir_all(&dir).expect("mkdir");
	for (name, data) in [
		("index.tmkup", "idx"),
		("hello.txt", "hi"),
		(".env", "SECRET"),
		("a.script.lua", "SRC"),
		("api.v2.script.lua", "SRC"),
	] {
		fs::write(dir.join(name), data).expect("write");
	}
	fs::create_dir_all(dir.join("x")).expect("mkdir");
	fs::write(dir.join("x/f.script.lua"), "SRC").expect("write");

	let state = AppState {
		root: dir.to_string_lossy().into_owned(),
		lua_engine: None,
		rhai_engine: None,
		scripting_config: ScriptingConfig::default(),
		require_secure: false,
		support_first_version: true,
		compression_minimum: 1024,
		compression_cache: dir.join(".cache"),
		compression_cache_enable: false,
		compression_cache_source_maximum: 0,
	};

	(TempDir(dir), state)
}

async fn get(raw: &str) -> String {
	let (_dir, state) = state();
	String::from_utf8_lossy(&process_request(raw.as_bytes(), &state).await).into_owned()
}

fn status(response: &str) -> &str {
	response.lines().next().unwrap_or_default()
}

#[tokio::test]
async fn nul_and_invalid_utf8_are_bad_request() {
	for path in ["/%00", "/a%00.txt", "/%ff"] {
		let response = get(&format!("TBIP/2.0 GET {path}\n\n")).await;
		assert!(status(&response).contains(" 30 "), "{path}: {response}");
	}
}

#[tokio::test]
async fn traversal_is_forbidden() {
	for path in [
		"/../x",
		"/a/../../x",
		"/..%5c..%5cx",
		"/%2e%2e/%2e%2e/etc/passwd",
	] {
		let response = get(&format!("TBIP/2.0 GET {path}\n\n")).await;
		assert!(status(&response).contains(" 32 "), "{path}: {response}");
	}
}

#[tokio::test]
async fn script_sources_are_never_served_statically() {
	for path in [
		"/a.script.lua",
		"/x%5Cf.script.lua",
		"/api.v2.script.lua",
		"/x/f.script.lua",
	] {
		let response = get(&format!("TBIP/2.0 GET {path}\n\n")).await;
		assert!(status(&response).contains(" 32 "), "{path}: {response}");
		assert!(!response.contains("SRC"), "{path}");
	}
	for path in ["/a.script.lua/.", "/a.script.lua/x/.."] {
		let response = get(&format!("TBIP/2.0 GET {path}\n\n")).await;
		assert!(!response.contains("SRC"), "{path}: {response}");
	}
}

#[tokio::test]
async fn hidden_files_look_missing_and_path_is_not_reflected() {
	let hidden = get("TBIP/2.0 GET /.env\n\n").await;
	let missing = get("TBIP/2.0 GET /nothing-here\n\n").await;
	assert!(status(&hidden).contains(" 31 "), "{hidden}");
	assert!(!hidden.contains("SECRET"));
	assert_eq!(hidden, missing);

	let reflected = get("TBIP/2.0 GET /%3Cscript%3Ealert%281%29%3C%2Fscript%3E\n\n").await;
	assert!(status(&reflected).contains(" 31 "));
	assert!(!reflected.contains("alert"));
	assert!(!reflected.contains("<script"));
}

#[tokio::test]
async fn header_limits_are_enforced() {
	let mut many = String::from("TBIP/2.0 GET /hello.txt\n");
	for index in 0..=crate::common::MAX_HEADERS {
		many.push_str(&format!("X-H{index}: v\n"));
	}
	many.push('\n');
	assert!(status(&get(&many).await).contains(" 30 "));

	let long = format!("TBIP/2.0 GET /hello.txt\nX-Long: {}\n\n", "a".repeat(9000));
	assert!(status(&get(&long).await).contains(" 30 "));

	let conflicting = "TBIP/2.0 GET /hello.txt\nContent-Length: 1\nContent-Length: 2\n\n";
	assert!(status(&get(conflicting).await).contains(" 30 "));

	let malformed = "TBIP/2.0 GET /hello.txt\nno-colon-here\n\n";
	assert!(status(&get(malformed).await).contains(" 30 "));
}

#[tokio::test]
async fn unsupported_version_and_short_request_line() {
	assert!(!status(&get("TBIP/9.9 GET /hello.txt\n\n").await).contains(" 20 "));
	assert!(status(&get("TBIP/2.0 GET\n\n").await).contains(" 30 "));
}

#[tokio::test]
async fn serves_regular_file() {
	let response = get("TBIP/2.0 GET /hello.txt\n\n").await;
	assert!(status(&response).contains(" 20 "), "{response}");
}
