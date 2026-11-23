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
		let response = get(&format!("TMUTP/2.0 GET {path}\n\n")).await;
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
		let response = get(&format!("TMUTP/2.0 GET {path}\n\n")).await;
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
		let response = get(&format!("TMUTP/2.0 GET {path}\n\n")).await;
		assert!(status(&response).contains(" 32 "), "{path}: {response}");
		assert!(!response.contains("SRC"), "{path}");
	}
	for path in ["/a.script.lua/.", "/a.script.lua/x/.."] {
		let response = get(&format!("TMUTP/2.0 GET {path}\n\n")).await;
		assert!(!response.contains("SRC"), "{path}: {response}");
	}
}

#[tokio::test]
async fn hidden_files_look_missing_and_path_is_not_reflected() {
	let hidden = get("TMUTP/2.0 GET /.env\n\n").await;
	let missing = get("TMUTP/2.0 GET /nothing-here\n\n").await;
	assert!(status(&hidden).contains(" 31 "), "{hidden}");
	assert!(!hidden.contains("SECRET"));
	assert_eq!(hidden, missing);

	let reflected = get("TMUTP/2.0 GET /%3Cscript%3Ealert%281%29%3C%2Fscript%3E\n\n").await;
	assert!(status(&reflected).contains(" 31 "));
	assert!(!reflected.contains("alert"));
	assert!(!reflected.contains("<script"));
}

#[tokio::test]
async fn header_limits_are_enforced() {
	let mut many = String::from("TMUTP/2.0 GET /hello.txt\n");
	for index in 0..=crate::common::MAX_HEADERS {
		many.push_str(&format!("X-H{index}: v\n"));
	}
	many.push('\n');
	assert!(status(&get(&many).await).contains(" 30 "));

	let long = format!("TMUTP/2.0 GET /hello.txt\nX-Long: {}\n\n", "a".repeat(9000));
	assert!(status(&get(&long).await).contains(" 30 "));

	let conflicting = "TMUTP/2.0 GET /hello.txt\nContent-Length: 1\nContent-Length: 2\n\n";
	assert!(status(&get(conflicting).await).contains(" 30 "));

	let malformed = "TMUTP/2.0 GET /hello.txt\nno-colon-here\n\n";
	assert!(status(&get(malformed).await).contains(" 30 "));
}

#[tokio::test]
async fn unsupported_version_and_short_request_line() {
	assert!(!status(&get("TMUTP/9.9 GET /hello.txt\n\n").await).contains(" 20 "));
	assert!(status(&get("TMUTP/2.0 GET\n\n").await).contains(" 30 "));
}

#[tokio::test]
async fn serves_regular_file() {
	let response = get("TMUTP/2.0 GET /hello.txt\n\n").await;
	assert!(status(&response).contains(" 20 "), "{response}");
}

#[tokio::test]
async fn post_body_with_crlf_crlf_and_lf_headers() {
	// Headers end at the earliest terminator; a CRLFCRLF inside the body must
	// not move the header boundary (depends on find_header_end semantics).
	let body = "a=1\r\n\r\nb=2";
	let raw = format!(
		"TMUTP/2.0 POST /hello.txt\nContent-Length: {}\n\n{}",
		body.len(),
		body
	);
	let response = get(&raw).await;
	assert!(status(&response).contains(" 20 "), "{response}");
}

#[tokio::test]
async fn post_requires_valid_content_length() {
	for header in [
		"",
		"Content-Length: abc\n",
		"Content-Length: +1\n",
		"Content-Length: 5\nContent-Length: 6\n",
	] {
		let raw = format!("TMUTP/2.0 POST /hello.txt\n{header}\nx");
		assert!(status(&get(&raw).await).contains(" 30 "), "{header}");
	}
}

#[tokio::test]
async fn too_many_form_fields_are_rejected() {
	let body: String = (0..=crate::common::MAX_FIELDS)
		.map(|index| format!("k{index}=v"))
		.collect::<Vec<_>>()
		.join("&");
	let raw = format!(
		"TMUTP/2.0 POST /hello.txt\nContent-Length: {}\n\n{}",
		body.len(),
		body
	);
	assert!(status(&get(&raw).await).contains(" 30 "));
}
