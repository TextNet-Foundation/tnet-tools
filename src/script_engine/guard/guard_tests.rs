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

const GRACE: std::time::Duration = std::time::Duration::from_millis(100);

/// Скрипт, который «работает» заданное время и игнорирует дедлайн (как долгая C-функция).
struct Blocker(u64);

impl ScriptEngine for Blocker {
	fn has_script(&self, _: &str) -> bool {
		true
	}

	fn execute(
		&self,
		_: &str,
		_: &Request,
		_: &crate::script_engine::ScriptLimits,
	) -> Result<Option<Response>, String> {
		std::thread::sleep(std::time::Duration::from_millis(self.0));
		Ok(None)
	}
}

fn test_request() -> Request {
	Request {
		protocol: "tmutp".into(),
		method: "GET".into(),
		path: "/".into(),
		query: HashMap::new(),
		body: Vec::new(),
		form: HashMap::new(),
		headers: HashMap::new(),
	}
}

fn config(timeout_ms: u64, queue_timeout_ms: u64) -> ScriptingConfig {
	ScriptingConfig {
		max_concurrent: Some(1),
		queue_timeout_ms: Some(queue_timeout_ms),
		timeout_ms: Some(timeout_ms),
		..ScriptingConfig::default()
	}
}

#[tokio::test]
async fn hung_script_returns_error_fast_but_keeps_slot() {
	// Свой семафор: ничего не зависит от глобального состояния и других тестов.
	let slots = Arc::new(Semaphore::new(1));
	let config = config(100, 50);
	let engine: Arc<dyn ScriptEngine> = Arc::new(Blocker(900));

	let started = std::time::Instant::now();
	let first = run_script_in(
		&slots,
		GRACE,
		engine.clone(),
		"/".into(),
		test_request(),
		&config,
	)
	.await;
	let elapsed = started.elapsed();

	// Клиент получил ошибку по таймауту (~200 мс), раньше чем поток закончил (900 мс).
	assert!(matches!(first, Err(RunError::Failed(_))));
	assert!(
		elapsed < std::time::Duration::from_millis(700),
		"{elapsed:?}"
	);

	// Поток ещё работает: слот занят.
	let second = run_script_in(&slots, GRACE, engine, "/".into(), test_request(), &config).await;
	assert!(matches!(second, Err(RunError::Busy)));

	// После завершения потока слот освобождается: ждём его самого, а не угадываем время.
	let free = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		slots.clone().acquire_owned(),
	)
	.await;
	assert!(free.is_ok(), "slot was never released");
}

#[tokio::test]
async fn exhausted_slots_yield_busy_instead_of_hanging() {
	let slots = Arc::new(Semaphore::new(1));
	let config = config(5_000, 50);
	let engine: Arc<dyn ScriptEngine> = Arc::new(Blocker(400));

	let first = tokio::spawn({
		let (slots, engine, config) = (slots.clone(), engine.clone(), config.clone());
		async move { run_script_in(&slots, GRACE, engine, "/".into(), test_request(), &config).await }
	});
	tokio::time::sleep(std::time::Duration::from_millis(100)).await;

	let second = run_script_in(&slots, GRACE, engine, "/".into(), test_request(), &config).await;
	assert!(matches!(second, Err(RunError::Busy)));
	assert!(matches!(first.await.expect("join"), Ok(None)));
}
