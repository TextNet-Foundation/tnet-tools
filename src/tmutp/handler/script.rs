use crate::common::compress_body;
use crate::config::*;
use crate::script_engine::{Request, Response, ScriptEngine};
use std::fmt::Write;
use std::sync::Arc;

pub fn normalize_script_path(decoded_path: &str, state: &crate::config::AppState) -> String {
	let mut script_path = decoded_path.to_string();

	if state.scripting_config.hide_scripts_behind.unwrap_or(true) {
		let lua_ext = state
			.scripting_config
			.lua_extension
			.clone()
			.unwrap_or_else(|| ".script.lua".to_string());

		let rhai_ext = state
			.scripting_config
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

pub fn make_script_response(
	response: Response,
	compression: Option<&str>,
	compression_minimum: usize,
	announce_compression: bool,
) -> Vec<u8> {
	let status_text = status_code_to_text(response.status);
	let mut output = String::new();
	writeln!(
		output,
		"{} {} {}",
		TMUTP_VERSION, response.status, status_text
	)
	.unwrap();

	let mut has_content_type = false;
	let mut has_content_encoding = false;

	for (key, value) in &response.headers {
		if key.eq_ignore_ascii_case("content-type") {
			has_content_type = true;
		}

		if key.eq_ignore_ascii_case("content-encoding") {
			has_content_encoding = true;
		}

		writeln!(output, "{}: {}", key, value).unwrap();
	}

	if !has_content_type {
		output.push_str("Content-Type: text/tmkup\n");
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

	let (body, content_encoding) = if !has_content_encoding {
		if let Some(alg) = compression {
			if original_body.len() >= compression_minimum {
				match compress_body(original_body, alg) {
					Some(data) => (data, Some(alg)),
					None => (original_body.to_vec(), None),
				}
			} else {
				(original_body.to_vec(), None)
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
	bytes.extend_from_slice(&body);
	bytes
}

pub async fn try_handle_script(
	state: &crate::config::AppState,
	script_path: &str,
	request: &Request,
	compression: Option<&str>,
	compression_minimum: usize,
	accept_compression_present: bool,
) -> Option<Vec<u8>> {
	if !state.scripting_config.enabled {
		return None;
	}

	let order = state
		.scripting_config
		.order
		.clone()
		.unwrap_or_else(|| vec!["lua".to_string(), "rhai".to_string()]);

	for engine_name in &order {
		let (engine, label) = match engine_name.as_str() {
			"lua" => (
				state
					.lua_engine
					.clone()
					.map(|engine| engine as Arc<dyn ScriptEngine>),
				"Lua",
			),
			"rhai" => (
				state
					.rhai_engine
					.clone()
					.map(|engine| engine as Arc<dyn ScriptEngine>),
				"Rhai",
			),
			_ => (None, ""),
		};

		let Some(engine) = engine else {
			continue;
		};

		let has_script = tokio::task::spawn_blocking({
			let engine = engine.clone();
			let sp = script_path.to_string();
			move || engine.has_script(&sp)
		})
		.await
		.unwrap_or(false);

		if !has_script {
			continue;
		}

		let exec_result = tokio::task::spawn_blocking({
			let engine = engine.clone();
			let sp = script_path.to_string();
			let rq = request.clone();
			move || engine.execute(&sp, &rq)
		})
		.await
		.unwrap_or_else(|_| Err("join error".to_string()));

		return Some(match exec_result {
			Ok(Some(response)) => make_script_response(
				response,
				compression,
				compression_minimum,
				accept_compression_present,
			),
			Ok(None) => crate::handler::response::make_empty_response(),
			Err(error) => {
				tracing::error!(engine = label, error = %error, "script error");

				crate::handler::response::make_error_response(
					SERVER_ERROR,
					"40 Server error",
					&format!("{} script error: {}", label, error),
				)
			}
		});
	}

	None
}
