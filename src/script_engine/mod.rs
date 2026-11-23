use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

pub mod fs;
pub mod guard;
pub mod lua;
pub mod rhai;

use fs::Sandbox;

/// Лимит времени выполнения скрипта по умолчанию.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;
/// Лимит памяти Lua-состояния по умолчанию (МиБ).
pub const DEFAULT_MEMORY_LIMIT_MB: usize = 64;
/// Число одновременно выполняемых скриптов по умолчанию.
pub const DEFAULT_MAX_CONCURRENT: usize = 32;
/// Сколько ждать свободный слот выполнения, прежде чем ответить 42.
pub const DEFAULT_QUEUE_TIMEOUT_MS: u64 = 5_000;

/// Допустимый диапазон кодов статуса, которые может вернуть скрипт.
pub const STATUS_RANGE: std::ops::RangeInclusive<i64> = 20..=55;

/// Запрос к скрипту
#[derive(Debug, Clone)]
pub struct Request {
	pub protocol: String,
	pub method: String,
	pub path: String,
	pub query: HashMap<String, String>,
	pub body: Vec<u8>,
	pub form: HashMap<String, String>,
	pub headers: HashMap<String, String>,
}

/// Ответ от скрипта
#[derive(Debug, Clone)]
pub struct Response {
	pub status: u16,
	pub headers: HashMap<String, String>,
	pub body: Option<Vec<u8>>,
}

/// Ресурсные лимиты одного выполнения скрипта.
#[derive(Debug, Clone)]
pub struct ScriptLimits {
	pub deadline: Duration,
	pub memory_bytes: usize,
	pub max_concurrent: usize,
	pub queue_timeout: Duration,
}

impl Default for ScriptLimits {
	fn default() -> Self {
		ScriptLimits {
			deadline: Duration::from_millis(DEFAULT_TIMEOUT_MS),
			memory_bytes: DEFAULT_MEMORY_LIMIT_MB * 1024 * 1024,
			max_concurrent: DEFAULT_MAX_CONCURRENT,
			queue_timeout: Duration::from_millis(DEFAULT_QUEUE_TIMEOUT_MS),
		}
	}
}

/// Трейт для движка скриптов
pub trait ScriptEngine: Send + Sync {
	fn has_script(&self, path: &str) -> bool;
	fn execute(
		&self,
		path: &str,
		req: &Request,
		limits: &ScriptLimits,
	) -> Result<Option<Response>, String>;
}

/// Конфигурация скриптов.
///
/// Все поля, кроме `enabled`, необязательны. `hot_reload = true` (по умолчанию)
/// читает скрипт с диска на каждый запрос; `false` кэширует исходник по (mtime, size).
#[derive(Debug, Deserialize, Clone)]
pub struct ScriptingConfig {
	pub enabled: bool,
	pub lua_extension: Option<String>,
	pub rhai_extension: Option<String>,
	pub order: Option<Vec<String>>,
	pub hot_reload: Option<bool>,
	pub hide_scripts_behind: Option<bool>,
	/// Лимит времени выполнения одного скрипта, мс.
	#[serde(default)]
	pub timeout_ms: Option<u64>,
	/// Лимит памяти Lua, МиБ.
	#[serde(default)]
	pub memory_limit_mb: Option<usize>,
	/// Максимум одновременно выполняемых скриптов (глобально на процесс).
	#[serde(default)]
	pub max_concurrent: Option<usize>,
	/// Таймаут ожидания свободного слота, мс.
	#[serde(default)]
	pub queue_timeout_ms: Option<u64>,
}

impl Default for ScriptingConfig {
	fn default() -> Self {
		ScriptingConfig {
			enabled: false,
			lua_extension: Some(".script.lua".to_string()),
			rhai_extension: Some(".script.rhai".to_string()),
			order: Some(vec!["lua".to_string(), "rhai".to_string()]),
			hot_reload: Some(true),
			hide_scripts_behind: Some(true),
			timeout_ms: None,
			memory_limit_mb: None,
			max_concurrent: None,
			queue_timeout_ms: None,
		}
	}
}

impl ScriptingConfig {
	pub fn limits(&self) -> ScriptLimits {
		let defaults = ScriptLimits::default();
		ScriptLimits {
			deadline: self
				.timeout_ms
				.map(Duration::from_millis)
				.unwrap_or(defaults.deadline),
			memory_bytes: self
				.memory_limit_mb
				.map(|mb| mb.saturating_mul(1024 * 1024))
				.unwrap_or(defaults.memory_bytes),
			max_concurrent: self
				.max_concurrent
				.unwrap_or(defaults.max_concurrent)
				.max(1),
			queue_timeout: self
				.queue_timeout_ms
				.map(Duration::from_millis)
				.unwrap_or(defaults.queue_timeout),
		}
	}
}

/// Проверяет суффикс скриптов: начинается с '.', длина > 1, без разделителей пути.
pub fn validate_extension(extension: &str) -> Result<(), String> {
	if extension.len() < 2 || !extension.starts_with('.') || extension.contains(['/', '\\', '\0']) {
		return Err(format!("invalid script extension {:?}", extension));
	}

	Ok(())
}

/// Приводит код статуса скрипта к u16 в диапазоне 20..=55.
pub fn check_status(status: i64) -> Result<u16, String> {
	if !STATUS_RANGE.contains(&status) {
		return Err(format!("status {} is outside 20..=55", status));
	}

	u16::try_from(status).map_err(|e| e.to_string())
}

/// Относительный путь скрипта: суффикс ДОБАВЛЯЕТСЯ к имени
/// (`/api.v2` -> `api.v2<ext>`, `/docs/` -> `docs/index<ext>`).
pub fn script_relative(path: &str, extension: &str) -> String {
	let relative = path.trim_start_matches('/');

	let base = if relative.is_empty() {
		"index".to_string()
	} else if path.ends_with('/') {
		format!("{}index", relative)
	} else {
		relative.to_string()
	};

	let mut name = std::ffi::OsString::from(base);
	name.push(extension);
	name.to_string_lossy().into_owned()
}

/// Ищет существующий файл скрипта внутри root.
pub fn find_script(sandbox: &Sandbox, path: &str, extension: &str) -> Option<PathBuf> {
	sandbox
		.resolve_existing(&script_relative(path, extension))
		.ok()
		.filter(|p| p.is_file())
}

/// Суффиксы, запись/удаление которых запрещены скриптам.
pub fn protected_suffixes(own_extension: &str) -> Vec<String> {
	let mut suffixes = vec![own_extension.to_string()];
	for extra in [".script.lua", ".script.rhai", ".lua", ".rhai"] {
		if !suffixes.iter().any(|s| s == extra) {
			suffixes.push(extra.to_string());
		}
	}
	suffixes
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
