use crate::common::{ParseResult, parse_request, resolve_path, script_extensions};
use crate::config::{
	AppState, BAD_REQUEST, FORBIDDEN, METHOD_NOT_ALLOWED, NOT_FOUND, SERVER_ERROR,
	TBIP_FIRST_VERSION, TBIP_VERSION,
};
use crate::handler::response::{
	make_error_response, make_file_response, make_head_response, make_range_response,
	make_version_error_response, replace_response_version,
};
use crate::handler::script::normalize_script_path;
use crate::script_engine::Request;
use std::collections::HashMap;
use std::io;

/// TBIP-запросы не несут тела: любой ненулевой Content-Length отклоняется.
pub const MAX_REQUEST_BODY: usize = 0;

fn bad_request(message: &str) -> Vec<u8> {
	make_error_response(BAD_REQUEST, "30 Bad request", message)
}

fn forbidden_response() -> Vec<u8> {
	make_error_response(
		FORBIDDEN,
		"32 Forbidden",
		"Access to the requested path is forbidden",
	)
}

pub async fn process_request(raw: &[u8], state: &AppState) -> Vec<u8> {
	let parsed = match parse_request(raw, MAX_REQUEST_BODY) {
		ParseResult::Ok(p) => p,
		ParseResult::BadRequest(msg) => return bad_request(msg),
		ParseResult::Forbidden => return forbidden_response(),
	};

	let response_version = match parsed.version.as_str() {
		"TBIP/2.0" => TBIP_VERSION,
		"TBIP/1.0" if state.support_first_version => TBIP_FIRST_VERSION,
		"TBIP/1.0" => {
			return make_version_error_response(
				TBIP_VERSION,
				"TBIP/1.0 support is disabled on this server",
			);
		}
		_ => {
			return make_version_error_response(TBIP_VERSION, "Server supports TBIP/2.0");
		}
	};

	let mut response = process_request_inner(&parsed, state).await;

	replace_response_version(&mut response, response_version);

	response
}

async fn process_request_inner(parsed: &crate::common::ParsedRequest, state: &AppState) -> Vec<u8> {
	let method = parsed.method.as_str();

	if method != "GET" && method != "HEAD" {
		return make_error_response(
			METHOD_NOT_ALLOWED,
			"50 Method not allowed",
			"TBIP supports only GET and HEAD",
		);
	}

	let request_path = &parsed.path;
	let range_header = parsed.headers.get("range").cloned();
	let accept_compression_header = parsed.headers.get("accept-compression").cloned();
	let accept_compression_present = accept_compression_header.is_some();
	let compression = crate::common::negotiate_compression(accept_compression_header.as_deref());

	let script_path = normalize_script_path(&state.scripting_config, request_path);
	let request = Request {
		protocol: "tbip".to_string(),
		method: method.to_string(),
		path: request_path.clone(),
		query: parsed.query.clone(),
		body: Vec::new(),
		form: HashMap::new(),
		headers: parsed.headers.clone(),
	};

	// Script engines
	if state.scripting_config.enabled {
		let order = state
			.scripting_config
			.order
			.clone()
			.unwrap_or_else(|| vec!["lua".to_string(), "rhai".to_string()]);
		for engine_name in &order {
			if engine_name == "lua" {
				if let Some(engine) = &state.lua_engine
					&& let Some(response) = crate::handler::script::try_lua(
						engine,
						state,
						&script_path,
						&request,
						method,
						compression,
						accept_compression_present,
					)
					.await
				{
					return response;
				}
			} else if engine_name == "rhai"
				&& let Some(engine) = &state.rhai_engine
				&& let Some(response) = crate::handler::script::try_rhai(
					engine,
					state,
					&script_path,
					&request,
					method,
					compression,
					accept_compression_present,
				)
				.await
			{
				return response;
			}
		}
	}

	// Static files
	let script_exts = script_extensions(
		state.scripting_config.lua_extension.as_deref(),
		state.scripting_config.rhai_extension.as_deref(),
	);
	match tokio::task::spawn_blocking({
		let root = state.root.clone();
		let p = request_path.clone();
		move || resolve_path(&root, &p, &script_exts)
	})
	.await
	.unwrap_or_else(|_| Err(io::Error::other("join error")))
	{
		Ok(Some(full_path)) => match crate::common::read_file_cached(&full_path).await {
			Ok(cached) => {
				let data = &cached.bytes;
				let modified = cached.modified;
				if method == "HEAD" {
					make_head_response(
						data,
						modified,
						compression,
						state,
						&full_path,
						accept_compression_present,
					)
					.await
				} else if let Some(range_value) = range_header.as_deref() {
					make_range_response(
						data,
						modified,
						range_value,
						compression,
						state,
						&full_path,
						accept_compression_present,
					)
				} else {
					make_file_response(
						data,
						modified,
						compression,
						state,
						&full_path,
						accept_compression_present,
					)
					.await
				}
			}
			Err(error) => {
				tracing::error!(path = ?full_path, error = %error, "failed to read file");
				make_error_response(
					SERVER_ERROR,
					"40 Server error",
					"Failed to read requested file",
				)
			}
		},
		Ok(None) => make_error_response(NOT_FOUND, "31 Not found", "Requested file was not found"),
		Err(error) if error.kind() == io::ErrorKind::PermissionDenied => forbidden_response(),
		Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
			bad_request("Invalid request path")
		}
		Err(error) => {
			tracing::error!(path = ?request_path, error = %error, "path resolution failed");
			make_error_response(
				SERVER_ERROR,
				"40 Server error",
				"Failed to resolve requested path",
			)
		}
	}
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
