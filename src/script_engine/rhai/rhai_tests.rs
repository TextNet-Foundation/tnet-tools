use super::*;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
	fn new() -> Self {
		let dir = std::env::temp_dir().join(format!(
			"tnet-rhai-{}-{}",
			std::process::id(),
			COUNTER.fetch_add(1, Ordering::SeqCst)
		));
		fs::create_dir_all(&dir).expect("create temp root");
		TempRoot(dir)
	}
}

impl Drop for TempRoot {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

fn request() -> Request {
	Request {
		protocol: "tmutp".into(),
		method: "GET".into(),
		path: "/t".into(),
		query: HashMap::new(),
		body: Vec::new(),
		form: HashMap::new(),
		headers: HashMap::new(),
	}
}

fn run(tmp: &TempRoot, source: &str) -> Result<Option<Response>, String> {
	fs::write(tmp.0.join("t.script.rhai"), source).expect("write script");
	let limits = ScriptLimits {
		deadline: Duration::from_millis(500),
		..ScriptLimits::default()
	};
	RhaiEngine::new(&tmp.0, None, true).execute("/t", &request(), &limits)
}

fn body_of(result: Result<Option<Response>, String>) -> String {
	let response = result.expect("script ok").expect("response");
	String::from_utf8(response.body.expect("body")).expect("utf8")
}

#[test]
fn readme_helpers_work() {
	let tmp = TempRoot::new();
	let r = run(&tmp, "fn handle(r) { ok(\"hi\") }")
		.expect("ok")
		.expect("resp");
	assert_eq!(r.status, 20);
	let r = run(&tmp, "fn handle(r) { err(30, \"bad\") }")
		.expect("ok")
		.expect("resp");
	assert_eq!(r.status, 30);
	let r = run(&tmp, "fn handle(r) { redirect(\"/x\") }")
		.expect("ok")
		.expect("resp");
	assert_eq!(r.headers.get("Location").map(String::as_str), Some("/x"));
	assert!(run(&tmp, "fn handle(r) { }").expect("ok").is_none());
}

#[test]
fn status_is_validated() {
	let tmp = TempRoot::new();
	assert!(run(&tmp, "fn handle(r) { err(65556, \"x\") }").is_err());
	assert!(run(&tmp, "fn handle(r) { #{ status: 70000 } }").is_err());
}

#[test]
fn runaway_scripts_are_stopped() {
	let tmp = TempRoot::new();
	let started = std::time::Instant::now();
	assert!(run(&tmp, "fn handle(r) { loop { } }").is_err());
	assert!(run(&tmp, "fn f(n) { f(n + 1) } fn handle(r) { f(0) }").is_err());
	assert!(
		run(
			&tmp,
			"fn handle(r) { let s = \"xxxxxxxx\"; for i in 0..40 { s += s; } ok(s) }"
		)
		.is_err()
	);
	assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn eval_and_import_are_disabled() {
	let tmp = TempRoot::new();
	assert!(run(&tmp, "fn handle(r) { eval(\"1\"); ok(\"x\") }").is_err());
	fs::write(tmp.0.join("m.rhai"), "let x = 1;").expect("module");
	assert!(run(&tmp, "import \"m\" as m; fn handle(r) { ok(\"x\") }").is_err());
}

#[test]
fn file_helpers_work_and_are_sandboxed() {
	let tmp = TempRoot::new();
	let src = "fn handle(r) {
		write_file(\"d/a.txt\", \"v\");
		let s = read_file(\"d/a.txt\");
		let e = exists(\"d/a.txt\");
		let out = exists(\"../nothing\");
		remove_file(\"d/a.txt\");
		ok(s + e + out + exists(\"d/a.txt\"))
	}";
	assert_eq!(body_of(run(&tmp, src)), "vtruefalsefalse");
	assert!(run(&tmp, "fn handle(r) { write_file(\"../x\", \"a\"); }").is_err());
	assert!(
		run(
			&tmp,
			"fn handle(r) { write_file(\"p.script.rhai\", \"a\"); }"
		)
		.is_err()
	);
	assert!(run(&tmp, "fn handle(r) { ok(read_file(\"/etc/passwd\")) }").is_err());
}
