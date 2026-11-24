use crate::config::{AppState, METHOD_NOT_ALLOWED, SERVER_ERROR};
use crate::handler::response::{make_empty_response, make_error_response};
use crate::script_engine::guard::{RunError, run_script, validate_response};
use crate::script_engine::lua::LuaEngine;
use crate::script_engine::rhai::RhaiEngine;
use crate::script_engine::{Request, Response as ScriptResponse, ScriptEngine};
use std::fmt::Write;
use std::sync::Arc;
use tokio::task;

pub fn normalize_script_path(
	scripting_config: &crate::script_engine::ScriptingConfig,
	decoded_path: &str,
) -> String {
	let mut script_path = decoded_path.to_string();

	if scripting_config.hide_scripts_behind.unwrap_or(true) {
		let lua_ext = scripting_config
			.lua_extension
			.clone()
			.unwrap_or_else(|| ".script.lua".to_string());

		let rhai_ext = scripting_config
			.rhai_extension
			.clone()
			.unwrap_or_else(|| ".script.rhai".to_string());

		let stripped = [&lua_ext, &rhai_ext]
			.into_iter()
			.filter(|ext| !ext.is_empty())
			.find_map(|ext| script_path.strip_suffix(ext.as_str()));

		if let Some(stripped) = stripped {
			script_path = stripped.to_string();
		}

		if script_path.is_empty() {
			script_path = "/".to_string();
		}
	}

	script_path
}

fn script_failure_response(status: &str) -> Vec<u8> {
	make_error_response(status, "Script error", "The script could not be executed.")
}

/// Параметры ответа, не зависящие от выбранного движка.
struct ReplyParams<'a> {
	method: &'a str,
	compression: Option<&'a str>,
	accept_compression_present: bool,
}

async fn try_engine(
	engine: Arc<dyn ScriptEngine>,
	label: &'static str,
	state: &AppState,
	script_path: &str,
	request: &Request,
	reply: ReplyParams<'_>,
) -> Option<Vec<u8>> {
	let has_script = task::spawn_blocking({
		let engine = engine.clone();
		let sp = script_path.to_string();
		move || engine.has_script(&sp)
	})
	.await
	.unwrap_or(false);

	if !has_script {
		return None;
	}

	let exec_result = run_script(
		engine,
		script_path.to_string(),
		request.clone(),
		&state.scripting_config,
	)
	.await;

	Some(match exec_result {
		Ok(Some(response)) => make_script_response(
			response,
			reply.method,
			reply.compression,
			state,
			reply.accept_compression_present,
		),
		Ok(None) => make_empty_response(),
		Err(RunError::Busy) => {
			tracing::warn!(engine = label, "script slots exhausted");
			script_failure_response("42 SERVICE UNAVAILABLE")
		}
		Err(RunError::Failed(err)) => {
			tracing::error!(engine = label, ?err, "script error");
			script_failure_response(SERVER_ERROR)
		}
	})
}

pub async fn try_lua(
	engine: &Arc<LuaEngine>,
	state: &AppState,
	script_path: &str,
	request: &Request,
	method: &str,
	compression: Option<&str>,
	accept_compression_present: bool,
) -> Option<Vec<u8>> {
	try_engine(
		engine.clone(),
		"Lua",
		state,
		script_path,
		request,
		ReplyParams {
			method,
			compression,
			accept_compression_present,
		},
	)
	.await
}

pub async fn try_rhai(
	engine: &Arc<RhaiEngine>,
	state: &AppState,
	script_path: &str,
	request: &Request,
	method: &str,
	compression: Option<&str>,
	accept_compression_present: bool,
) -> Option<Vec<u8>> {
	try_engine(
		engine.clone(),
		"Rhai",
		state,
		script_path,
		request,
		ReplyParams {
			method,
			compression,
			accept_compression_present,
		},
	)
	.await
}

pub fn make_script_response(
	response: ScriptResponse,
	method: &str,
	compression: Option<&str>,
	state: &AppState,
	announce_compression: bool,
) -> Vec<u8> {
	use crate::common::compress_body;
	use crate::config::{SUPPORTED_COMPRESSION, TBIP_VERSION, status_code_to_text};

	if let Err(reason) = validate_response(&response, |code| status_code_to_text(code) != "UNKNOWN")
	{
		tracing::error!(reason, "rejected invalid script response");
		return script_failure_response(METHOD_NOT_ALLOWED);
	}

	let status_text = status_code_to_text(response.status);

	let mut output = String::new();
	let _ = writeln!(
		output,
		"{} {} {}",
		TBIP_VERSION, response.status, status_text
	);

	for (key, value) in &response.headers {
		let _ = writeln!(output, "{}: {}", key, value);
	}

	if announce_compression {
		let _ = writeln!(
			output,
			"Supported-Compression: {}",
			SUPPORTED_COMPRESSION.join(", ")
		);
	}

	let original_body = response.body.as_deref().unwrap_or(&[]);

	let (body, content_encoding) = match compression {
		Some(alg) if method != "HEAD" && original_body.len() >= state.compression_minimum => {
			match compress_body(original_body, alg) {
				Some(data) => (data, Some(alg)),
				None => (original_body.to_vec(), None),
			}
		}
		_ => (original_body.to_vec(), None),
	};

	if let Some(alg) = content_encoding {
		let _ = writeln!(output, "Content-Encoding: {}", alg);
	}

	let _ = write!(output, "Content-Length: {}\n\n", body.len());

	let mut bytes = output.into_bytes();

	if method == "GET" {
		bytes.extend_from_slice(&body);
	}

	bytes
}
