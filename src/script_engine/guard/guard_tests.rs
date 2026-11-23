use super::*;
use crate::script_engine::Response;
use std::collections::HashMap;

fn response_with(headers: &[(&str, &str)], status: u16) -> Response {
	Response {
		status,
		headers: headers
			.iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect::<HashMap<_, _>>(),
		body: None,
	}
}

fn known(code: u16) -> bool {
	matches!(code, 20 | 21 | 22 | 40 | 50)
}

#[test]
fn crlf_in_header_value_or_name_is_rejected() {
	let bad_value = response_with(&[("X-A", "v\r\nInjected: 1")], 20);
	assert!(validate_response(&bad_value, known).is_err());
	let bad_name = response_with(&[("X-A\r\nB", "v")], 20);
	assert!(validate_response(&bad_name, known).is_err());
	let nul = response_with(&[("X-A", "v\0")], 20);
	assert!(validate_response(&nul, known).is_err());
	let lf = response_with(&[("X-A", "v\nB: 1")], 20);
	assert!(validate_response(&lf, known).is_err());
}

#[test]
fn reserved_headers_are_rejected_case_insensitively() {
	for name in [
		"Content-Length",
		"content-encoding",
		"CONTENT-RANGE",
		"File-SHA256",
	] {
		let r = response_with(&[(name, "1")], 20);
		assert!(validate_response(&r, known).is_err(), "{name}");
	}
}

#[test]
fn unknown_status_is_rejected_and_valid_response_passes() {
	assert!(validate_response(&response_with(&[], 99), known).is_err());
	let ok = response_with(&[("Location", "/x"), ("Content-Type", "text/plain")], 21);
	assert!(validate_response(&ok, known).is_ok());
}

struct Sleeper;

impl ScriptEngine for Sleeper {
	fn has_script(&self, _: &str) -> bool {
		true
	}

	fn execute(
		&self,
		_: &str,
		_: &Request,
		_: &crate::script_engine::ScriptLimits,
	) -> Result<Option<Response>, String> {
		std::thread::sleep(std::time::Duration::from_millis(400));
		Ok(None)
	}
}

#[tokio::test]
async fn exhausted_slots_yield_busy_instead_of_hanging() {
	let config = ScriptingConfig {
		max_concurrent: Some(1),
		queue_timeout_ms: Some(50),
		..ScriptingConfig::default()
	};
	let request = Request {
		protocol: "tmutp".into(),
		method: "GET".into(),
		path: "/".into(),
		query: HashMap::new(),
		body: Vec::new(),
		form: HashMap::new(),
		headers: HashMap::new(),
	};

	let engine: Arc<dyn ScriptEngine> = Arc::new(Sleeper);
	let first = tokio::spawn({
		let (engine, request, config) = (engine.clone(), request.clone(), config.clone());
		async move { run_script(engine, "/".into(), request, &config).await }
	});
	tokio::time::sleep(std::time::Duration::from_millis(100)).await;

	let second = run_script(engine, "/".into(), request, &config).await;
	assert!(matches!(second, Err(RunError::Busy)));
	assert!(matches!(first.await.expect("join"), Ok(None)));
}
