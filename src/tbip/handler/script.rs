use crate::config::{AppState, SERVER_ERROR};
use crate::handler::response::{make_empty_response, make_error_response};
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

		if script_path.ends_with(&lua_ext) {
			script_path = script_path.trim_end_matches(&lua_ext).to_string();
		} else if script_path.ends_with(&rhai_ext) {
			script_path = script_path.trim_end_matches(&rhai_ext).to_string();
		}

		if script_path.is_empty() {
			script_path = "/".to_string();
		}
	}

	script_path
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
	let engine_clone = engine.clone();
	let sp = script_path.to_string();
	let has_script = task::spawn_blocking({
		let engine = engine_clone.clone();
		let sp = sp.clone();
		move || engine.has_script(&sp)
	})
	.await
	.unwrap_or(false);

	if !has_script {
		return None;
	}

	let exec_result = task::spawn_blocking({
		let engine = engine_clone.clone();
		let sp = script_path.to_string();
		let rq = request.clone();
		move || engine.execute(&sp, &rq)
	})
	.await
	.unwrap_or_else(|_| Err("join error".to_string()));

	Some(match exec_result {
		Ok(Some(response)) => make_script_response(
			response,
			method,
			compression,
			state,
			accept_compression_present,
		),
		Ok(None) => make_empty_response(),
		Err(error) => {
			tracing::error!(error = %error, "lua script error");

			make_error_response(
				SERVER_ERROR,
				"40 Server error",
				&format!("Lua script error: {}", error),
			)
		}
	})
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
	let engine_clone = engine.clone();
	let sp = script_path.to_string();
	let has_script = task::spawn_blocking({
		let engine = engine_clone.clone();
		let sp = sp.clone();
		move || engine.has_script(&sp)
	})
	.await
	.unwrap_or(false);

	if !has_script {
		return None;
	}

	let exec_result = task::spawn_blocking({
		let engine = engine_clone.clone();
		let sp = script_path.to_string();
		let rq = request.clone();
		move || engine.execute(&sp, &rq)
	})
	.await
	.unwrap_or_else(|_| Err("join error".to_string()));

	Some(match exec_result {
		Ok(Some(response)) => make_script_response(
			response,
			method,
			compression,
			state,
			accept_compression_present,
		),
		Ok(None) => make_empty_response(),
		Err(error) => {
			tracing::error!(error = %error, "rhai script error");

			make_error_response(
				SERVER_ERROR,
				"40 Server error",
				&format!("Rhai script error: {}", error),
			)
		}
	})
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

	let status_text = status_code_to_text(response.status);

	let mut output = String::new();
	writeln!(
		output,
		"{} {} {}",
		TBIP_VERSION, response.status, status_text
	)
	.unwrap();

	let mut has_content_encoding = false;

	for (key, value) in &response.headers {
		if key.eq_ignore_ascii_case("content-encoding") {
			has_content_encoding = true;
		}

		writeln!(output, "{}: {}", key, value).unwrap();
	}

	if announce_compression {
		writeln!(
			output,
			"Supported-Compression: {}",
			SUPPORTED_COMPRESSION.join(", ")
		)
		.unwrap();
	}

	let original_body = response.body.as_deref().unwrap_or(&[]);

	let (body, content_encoding) = if method == "HEAD" || has_content_encoding {
		(original_body.to_vec(), None)
	} else if let Some(alg) = compression {
		if original_body.len() >= state.compression_minimum {
			match compress_body(original_body, alg) {
				Some(data) => (data, Some(alg)),
				None => (original_body.to_vec(), None),
			}
		} else {
			(original_body.to_vec(), None)
		}
	} else {
		(original_body.to_vec(), None)
	};

	if let Some(alg) = content_encoding {
		writeln!(output, "Content-Encoding: {}", alg).unwrap();
	}

	write!(output, "Content-Length: {}\n\n", body.len()).unwrap();

	let mut bytes = output.into_bytes();

	if method == "GET" {
		bytes.extend_from_slice(&body);
	}

	bytes
}
