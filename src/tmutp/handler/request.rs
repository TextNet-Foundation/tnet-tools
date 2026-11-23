use crate::common::frame::DEFAULT_MAX_BODY;
use crate::common::negotiate_compression;
use crate::common::{ParseResult, parse_request, resolve_path, script_extensions};
use crate::config::*;
use crate::handler::response::*;
use crate::script_engine::Request;
use std::collections::HashMap;
use std::io;

pub use super::response::replace_response_version;

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
	let parsed = match parse_request(raw, DEFAULT_MAX_BODY) {
		ParseResult::Ok(p) => p,
		ParseResult::BadRequest(msg) => return bad_request(msg),
		ParseResult::Forbidden => return forbidden_response(),
	};

	let response_version = match parsed.version.as_str() {
		"TMUTP/2.0" => TMUTP_VERSION,
		"TMUTP/1.0" if state.support_first_version => TMUTP_FIRST_VERSION,
		"TMUTP/1.0" => {
			return make_version_error_response(
				TMUTP_VERSION,
				"TMUTP/1.0 support is disabled on this server",
			);
		}
		_ => {
			return make_version_error_response(TMUTP_VERSION, "Server supports TMUTP/2.0");
		}
	};

	let mut response = process_request_inner(&parsed, state).await;

	replace_response_version(&mut response, response_version);

	response
}

async fn process_request_inner(parsed: &crate::common::ParsedRequest, state: &AppState) -> Vec<u8> {
	let method = parsed.method.as_str();

	if method != "GET" && method != "POST" {
		return make_error_response(
			METHOD_NOT_ALLOWED,
			"50 Method not allowed",
			"TMUTP supports only GET and POST",
		);
	}

	if method == "POST" && !parsed.headers.contains_key("content-length") {
		return bad_request("POST request must include Content-Length header");
	}

	let range_header = parsed.headers.get("range").cloned();
	let accept_compression_header = parsed.headers.get("accept-compression").cloned();
	let accept_compression_present = accept_compression_header.is_some();
	let compression = negotiate_compression(accept_compression_header.as_deref());

	let form_params = if method == "POST" && !parsed.body.is_empty() {
		match crate::common::request::parse_fields(&String::from_utf8_lossy(&parsed.body)) {
			Some(fields) => fields,
			None => return bad_request("Too many form fields"),
		}
	} else {
		HashMap::new()
	};

	let request_path = &parsed.path;
	let script_path = crate::handler::script::normalize_script_path(request_path, state);

	let request = Request {
		protocol: "tmutp".to_string(),
		method: method.to_string(),
		path: request_path.clone(),
		query: parsed.query.clone(),
		body: parsed.body.clone(),
		form: form_params,
		headers: parsed.headers.clone(),
	};

	if let Some(response) = crate::handler::script::try_handle_script(
		state,
		&script_path,
		&request,
		compression,
		state.compression_minimum,
		accept_compression_present,
	)
	.await
	{
		return response;
	}

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
		Ok(Some(full_path)) => {
			crate::handler::response::serve_static_file(
				full_path,
				method,
				range_header.as_deref(),
				compression,
				state.compression_minimum,
				&state.compression_cache,
				accept_compression_present,
			)
			.await
		}

		Ok(None) => make_error_response(
			NOT_FOUND,
			"31 Not found",
			"The requested path was not found",
		),

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
