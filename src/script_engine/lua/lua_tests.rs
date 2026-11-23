use super::*;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
	fn new() -> Self {
		let dir = std::env::temp_dir().join(format!(
			"tnet-lua-{}-{}",
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

fn short_limits() -> ScriptLimits {
	ScriptLimits {
		deadline: Duration::from_millis(300),
		..ScriptLimits::default()
	}
}

fn run(tmp: &TempRoot, source: &str) -> Result<Option<Response>, String> {
	fs::write(tmp.0.join("t.script.lua"), source).expect("write script");
	LuaEngine::new(&tmp.0, None, true).execute("/t", &request(), &short_limits())
}

fn body_of(result: Result<Option<Response>, String>) -> String {
	let response = result.expect("script ok").expect("response");
	String::from_utf8(response.body.expect("body")).expect("utf8")
}

#[test]
fn readme_helpers_work() {
	let tmp = TempRoot::new();
	let r = run(&tmp, "function handle(r) return ok('hi') end")
		.expect("ok")
		.expect("resp");
	assert_eq!(r.status, 20);
	let r = run(&tmp, "function handle(r) return empty() end")
		.expect("ok")
		.expect("resp");
	assert_eq!(r.status, 22);
	let r = run(&tmp, "function handle(r) return redirect('/x') end")
		.expect("ok")
		.expect("resp");
	assert_eq!(r.headers.get("Location").map(String::as_str), Some("/x"));
	let r = run(&tmp, "function handle(r) return error(30, 'bad') end")
		.expect("ok")
		.expect("resp");
	assert_eq!((r.status, r.body), (30, Some(b"bad".to_vec())));
	assert!(run(&tmp, "function handle(r) end").expect("ok").is_none());
}

#[test]
fn standard_error_still_raises() {
	let tmp = TempRoot::new();
	assert!(run(&tmp, "function handle(r) error('boom') end").is_err());
	let src = "function handle(r) local okk, m = pcall(error, 'x') return ok(tostring(okk)) end";
	assert_eq!(body_of(run(&tmp, src)), "false");
}

#[test]
fn dangerous_globals_are_unavailable() {
	let tmp = TempRoot::new();
	for expr in [
		"os.execute('true')",
		"io.open('/etc/passwd')",
		"require('os')",
		"load('return 1')()",
		"dofile('/etc/passwd')",
		"loadfile('/etc/passwd')",
		"collectgarbage()",
		"debug.getinfo(1)",
	] {
		let src = format!("function handle(r) {expr} return ok('x') end");
		assert!(run(&tmp, &src).is_err(), "{expr}");
	}
}

#[test]
fn safe_os_helpers_exist() {
	let tmp = TempRoot::new();
	let src = "function handle(r) return ok(type(os.time()) .. type(os.clock())) end";
	assert_eq!(body_of(run(&tmp, src)), "numbernumber");
}

#[test]
fn infinite_loop_is_interrupted() {
	let tmp = TempRoot::new();
	let started = std::time::Instant::now();
	assert!(run(&tmp, "function handle(r) while true do end end").is_err());
	assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn huge_string_rep_hits_memory_limit() {
	let tmp = TempRoot::new();
	let src = "function handle(r) local s = string.rep('x', 512*1024*1024) return ok('x') end";
	assert!(run(&tmp, src).is_err());
}

#[test]
fn file_helpers_are_sandboxed() {
	let tmp = TempRoot::new();
	let src = "function handle(r)
		write_file('d/a.txt', 'v')
		local s = read_file('d/a.txt')
		local e = exists('d/a.txt')
		local out = exists('../nothing')
		remove_file('d/a.txt')
		return ok(s .. tostring(e) .. tostring(out) .. tostring(exists('d/a.txt')))
	end";
	assert_eq!(body_of(run(&tmp, src)), "vtruefalsefalse");
	assert!(run(&tmp, "function handle(r) write_file('../x', 'a') end").is_err());
	assert!(
		run(
			&tmp,
			"function handle(r) write_file('p.script.lua', 'a') end"
		)
		.is_err()
	);
	assert!(
		run(
			&tmp,
			"function handle(r) return ok(read_file('/etc/passwd')) end"
		)
		.is_err()
	);
}

#[test]
fn status_outside_range_is_rejected() {
	let tmp = TempRoot::new();
	assert!(run(&tmp, "function handle(r) return {status=65556} end").is_err());
	assert!(run(&tmp, "function handle(r) return error(99, 'x') end").is_err());
}

#[test]
fn suffix_is_appended_to_name() {
	let tmp = TempRoot::new();
	fs::write(
		tmp.0.join("api.v2.script.lua"),
		"function handle(r) return ok('v2') end",
	)
	.expect("write");
	let engine = LuaEngine::new(&tmp.0, None, true);
	assert!(engine.has_script("/api.v2"));
	assert!(!engine.has_script("/api.html"));
	assert!(!engine.has_script("/api"));
}
