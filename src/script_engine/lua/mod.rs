use super::fs::Sandbox;
use super::fs::source::SourceCache;
use super::{
	Request, Response, ScriptEngine, ScriptLimits, check_status, find_script, protected_suffixes,
	validate_extension,
};
use mlua::{Function, Value};
use std::collections::HashMap;
use std::path::PathBuf;

mod helpers;
mod patterns;

const DEFAULT_EXTENSION: &str = ".script.lua";

pub struct LuaEngine {
	extension: String,
	sandbox: Sandbox,
	sources: SourceCache,
}

impl LuaEngine {
	/// Создаёт движок. Некорректное расширение заменяется на `.script.lua` с записью в лог;
	/// для явной обработки ошибки используйте [`LuaEngine::try_new`].
	pub fn new(root: impl Into<PathBuf>, extension: Option<String>, hot_reload: bool) -> Self {
		let root = root.into();
		Self::try_new(root.clone(), extension, hot_reload).unwrap_or_else(|error| {
			tracing::error!(%error, "invalid lua extension, using default");
			Self::build(root, DEFAULT_EXTENSION.to_string(), hot_reload)
		})
	}

	pub fn try_new(
		root: impl Into<PathBuf>,
		extension: Option<String>,
		hot_reload: bool,
	) -> Result<Self, String> {
		let extension = extension.unwrap_or_else(|| DEFAULT_EXTENSION.to_string());
		validate_extension(&extension)?;
		Ok(Self::build(root.into(), extension, hot_reload))
	}

	fn build(root: PathBuf, extension: String, hot_reload: bool) -> Self {
		let sandbox = Sandbox::new(root, protected_suffixes(&extension));
		Self {
			extension,
			sandbox,
			sources: SourceCache::new(hot_reload),
		}
	}
}

fn extract_response(result: Value) -> Result<Option<Response>, String> {
	let table = match result {
		Value::Nil => return Ok(None),
		Value::Table(table) => table,
		_ => return Err("Expected table".to_string()),
	};

	let status: i64 = table.get("status").map_err(|e| e.to_string())?;
	let status = check_status(status)?;

	let mut headers = HashMap::new();
	if let Some(headers_tbl) = table
		.get::<_, Option<mlua::Table>>("headers")
		.map_err(|e| e.to_string())?
	{
		for pair in headers_tbl.pairs::<String, String>() {
			let (k, v) = pair.map_err(|e| e.to_string())?;
			headers.insert(k, v);
		}
	}

	let body = table
		.get::<_, Option<mlua::String>>("body")
		.map_err(|e| e.to_string())?
		.map(|s| s.as_bytes().to_vec());

	Ok(Some(Response {
		status,
		headers,
		body,
	}))
}

impl ScriptEngine for LuaEngine {
	fn has_script(&self, path: &str) -> bool {
		find_script(&self.sandbox, path, &self.extension).is_some()
	}

	fn execute(
		&self,
		path: &str,
		req: &Request,
		limits: &ScriptLimits,
	) -> Result<Option<Response>, String> {
		let script_path =
			find_script(&self.sandbox, path, &self.extension).ok_or("Script not found")?;
		let script = self
			.sources
			.load(&script_path)
			.map_err(|e| format!("Failed to read script: {}", e))?;

		let lua = helpers::new_sandboxed(limits)?;
		helpers::register_responses(&lua)?;
		helpers::register_files(&lua, &self.sandbox)?;
		patterns::restrict_patterns(&lua)?;

		lua.load(&*script).exec().map_err(|e| e.to_string())?;

		let req_table = helpers::request_table(&lua, req).map_err(|e| e.to_string())?;
		let handle: Function = lua.globals().get("handle").map_err(|e| e.to_string())?;
		let result: Value = handle.call(req_table).map_err(|e| e.to_string())?;

		extract_response(result)
	}
}

#[cfg(test)]
#[path = "lua_tests.rs"]
mod tests;
