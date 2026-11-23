use super::fs::Sandbox;
use super::fs::source::SourceCache;
use super::{
	Request, Response, ScriptEngine, ScriptLimits, check_status, find_script, protected_suffixes,
	validate_extension,
};
use ::rhai::{Dynamic, Map, Scope};
use std::collections::HashMap;
use std::path::PathBuf;

mod helpers;

const DEFAULT_EXTENSION: &str = ".script.rhai";

pub struct RhaiEngine {
	extension: String,
	sandbox: Sandbox,
	sources: SourceCache,
}

impl RhaiEngine {
	/// Создаёт движок. Некорректное расширение заменяется на `.script.rhai` с записью в лог;
	/// для явной обработки ошибки используйте [`RhaiEngine::try_new`].
	pub fn new(root: impl Into<PathBuf>, extension: Option<String>, hot_reload: bool) -> Self {
		let root = root.into();
		Self::try_new(root.clone(), extension, hot_reload).unwrap_or_else(|error| {
			tracing::error!(%error, "invalid rhai extension, using default");
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

fn extract_response(result: Dynamic) -> Result<Option<Response>, String> {
	if result.is_unit() {
		return Ok(None);
	}

	let map = result.try_cast::<Map>().ok_or("Expected Map")?;
	let status = map
		.get("status")
		.and_then(|v| v.as_int().ok())
		.ok_or("Missing status")?;
	let status = check_status(status)?;

	let mut headers = HashMap::new();
	if let Some(headers_map) = map.get("headers").and_then(|v| v.clone().try_cast::<Map>()) {
		for (k, v) in headers_map.iter() {
			let value = v
				.clone()
				.into_string()
				.map_err(|_| format!("header {} must be a string", k))?;
			headers.insert(k.to_string(), value);
		}
	}

	let body = match map.get("body") {
		None => None,
		Some(v) if v.is_unit() => None,
		Some(v) if v.is_blob() => v.clone().into_blob().ok(),
		Some(v) => Some(
			v.clone()
				.into_string()
				.map_err(|_| "body must be string or blob")?
				.into_bytes(),
		),
	};

	Ok(Some(Response {
		status,
		headers,
		body,
	}))
}

impl ScriptEngine for RhaiEngine {
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

		let mut engine = helpers::new_limited(limits);
		helpers::register_helpers(&mut engine, &self.sandbox);

		let ast = engine.compile(&*script).map_err(|e| e.to_string())?;
		engine.run_ast(&ast).map_err(|e| e.to_string())?;

		let mut scope = Scope::new();
		let result: Dynamic = engine
			.call_fn(&mut scope, &ast, "handle", (helpers::request_map(req),))
			.map_err(|e| e.to_string())?;

		extract_response(result)
	}
}

#[cfg(test)]
#[path = "rhai_tests.rs"]
mod tests;
