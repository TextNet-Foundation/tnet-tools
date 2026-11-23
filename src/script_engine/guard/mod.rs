//! Защита сервера от скриптов: глобальный лимит параллелизма и проверка ответов.

use super::{Request, Response, ScriptEngine, ScriptingConfig};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

pub mod response;

pub use response::validate_response;

/// Причина, по которой скрипт не дал ответа.
#[derive(Debug)]
pub enum RunError {
	/// Не удалось получить слот выполнения вовремя (ответ 42).
	Busy,
	/// Скрипт завершился ошибкой; текст только для логов.
	Failed(String),
}

static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn slots(max_concurrent: usize) -> Arc<Semaphore> {
	SLOTS
		.get_or_init(|| Arc::new(Semaphore::new(max_concurrent.max(1))))
		.clone()
}

/// Выполняет скрипт в blocking-потоке под глобальным семафором.
/// Слот удерживается, пока поток реально не завершится (лимит времени
/// внутри движков гарантирует завершение).
pub async fn run_script(
	engine: Arc<dyn ScriptEngine>,
	path: String,
	request: Request,
	config: &ScriptingConfig,
) -> Result<Option<Response>, RunError> {
	let limits = config.limits();

	let permit = match tokio::time::timeout(
		limits.queue_timeout,
		slots(limits.max_concurrent).acquire_owned(),
	)
	.await
	{
		Ok(Ok(permit)) => permit,
		_ => return Err(RunError::Busy),
	};

	tokio::task::spawn_blocking(move || {
		let _permit = permit;
		engine.execute(&path, &request, &limits)
	})
	.await
	.map_err(|e| RunError::Failed(format!("join error: {}", e)))?
	.map_err(RunError::Failed)
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
