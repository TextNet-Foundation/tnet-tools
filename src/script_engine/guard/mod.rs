//! Защита сервера от скриптов: глобальный лимит параллелизма и проверка ответов.

use super::{Request, Response, ScriptEngine, ScriptingConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
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

/// Запас сверх дедлайна скрипта перед тем, как клиенту вернётся ошибка.
const TIMEOUT_GRACE: Duration = Duration::from_secs(2);

/// Один процесс = один конфиг: семафор создаётся по первой конфигурации,
/// последующие значения `max_concurrent` игнорируются (с одним предупреждением).
static SLOTS: OnceLock<(Arc<Semaphore>, usize)> = OnceLock::new();
static MISMATCH_WARNED: AtomicBool = AtomicBool::new(false);

fn slots(max_concurrent: usize) -> Arc<Semaphore> {
	let wanted = max_concurrent.max(1);
	let (semaphore, installed) = SLOTS.get_or_init(|| (Arc::new(Semaphore::new(wanted)), wanted));
	if *installed != wanted && !MISMATCH_WARNED.swap(true, Ordering::Relaxed) {
		tracing::warn!(
			installed = *installed,
			requested = wanted,
			"script max_concurrent differs from the already installed limit; ignoring"
		);
	}
	semaphore.clone()
}

/// Выполняет скрипт в blocking-потоке под глобальным семафором.
/// Слот удерживается внутри blocking-замыкания, пока поток реально не завершится,
/// даже если клиент уже получил ошибку по таймауту: так зависшие потоки не
/// накапливаются сверх лимита.
pub async fn run_script(
	engine: Arc<dyn ScriptEngine>,
	path: String,
	request: Request,
	config: &ScriptingConfig,
) -> Result<Option<Response>, RunError> {
	let semaphore = slots(config.limits().max_concurrent);
	run_script_in(&semaphore, TIMEOUT_GRACE, engine, path, request, config).await
}

/// То же, что [`run_script`], но с явным семафором и запасом по времени: тесты
/// не делят глобальное состояние процесса.
async fn run_script_in(
	semaphore: &Arc<Semaphore>,
	grace: Duration,
	engine: Arc<dyn ScriptEngine>,
	path: String,
	request: Request,
	config: &ScriptingConfig,
) -> Result<Option<Response>, RunError> {
	let limits = config.limits();

	let permit =
		match tokio::time::timeout(limits.queue_timeout, semaphore.clone().acquire_owned()).await {
			Ok(Ok(permit)) => permit,
			_ => return Err(RunError::Busy),
		};

	let wait = limits.deadline.saturating_add(grace);
	let handle = tokio::task::spawn_blocking(move || {
		let _permit = permit;
		engine.execute(&path, &request, &limits)
	});

	match tokio::time::timeout(wait, handle).await {
		Ok(joined) => joined
			.map_err(|e| RunError::Failed(format!("join error: {}", e)))?
			.map_err(RunError::Failed),
		Err(_) => {
			tracing::warn!(
				wait_ms = wait.as_millis() as u64,
				"script exceeded its deadline; slot stays held until the thread exits"
			);
			Err(RunError::Failed("script timed out".to_string()))
		}
	}
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
