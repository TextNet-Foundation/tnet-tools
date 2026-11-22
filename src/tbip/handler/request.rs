use crate::common::{percent_decode, resolve_path};
use crate::config::{
    AppState, BAD_REQUEST, FORBIDDEN, METHOD_NOT_ALLOWED, NOT_FOUND, SERVER_ERROR,
    TBIP_FIRST_VERSION, TBIP_VERSION,
};
use crate::handler::response::{
    make_error_response, make_file_response, make_head_response, make_range_response,
    make_version_error_response, replace_response_version,
};
use crate::handler::script::normalize_script_path;
use crate::path::validate_relative_path;
use crate::script_engine::Request;
use std::collections::HashMap;
use std::io;
pub async fn process_request(raw: &[u8], state: &AppState) -> Vec<u8> {
    let header_end = match find_header_end(raw) {
        Some(end) => end,
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Request headers are incomplete",
            );
        }
    };
    let request_line = raw[..header_end]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let request_version = match std::str::from_utf8(request_line) {
        Ok(line) => line.split_whitespace().next(),
        Err(_) => None,
    };
    let response_version = match request_version {
        Some("TBIP/2.0") => TBIP_VERSION,
        Some("TBIP/1.0") if state.support_first_version => TBIP_FIRST_VERSION,
        Some("TBIP/1.0") => {
            return make_version_error_response(
                TBIP_VERSION,
                "TBIP/1.0 support is disabled on this server",
            );
        }
        Some(_) => {
            return make_version_error_response(TBIP_VERSION, "Server supports TBIP/2.0");
        }
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Request line is missing or invalid",
            );
        }
    };
    let mut response = process_request_inner(raw, state).await;
    replace_response_version(&mut response, response_version);
    response
}
pub async fn process_request_inner(raw: &[u8], state: &AppState) -> Vec<u8> {
    let header_end = match find_header_end(raw) {
        Some(end) => end,
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Request headers are incomplete",
            );
        }
    };
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = match lines.next() {
        Some(line) => line.trim(),
        None => {
            return make_error_response(BAD_REQUEST, "30 Bad request", "Request line is missing");
        }
    };
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 {
        return make_error_response(
            BAD_REQUEST,
            "30 Bad request",
            "Request must contain version, method and path",
        );
    }
    let method = parts[1];
    let raw_path = parts[2];
    if method != "GET" && method != "HEAD" {
        return make_error_response(
            METHOD_NOT_ALLOWED,
            "50 Method not allowed",
            "TBIP supports only GET and HEAD",
        );
    }
    let (path, query_str) = if let Some(pos) = raw_path.find('?') {
        let (path, query) = raw_path.split_at(pos);
        (path, Some(&query[1..]))
    } else {
        (raw_path, None)
    };
    let decoded_path = percent_decode(path);
    let query_params = if let Some(query) = query_str {
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>()
    } else {
        HashMap::new()
    };
    let mut request_headers = HashMap::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            request_headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }
    if let Err(error) = validate_relative_path(&decoded_path) {
        if error.kind() == io::ErrorKind::PermissionDenied {
            return make_error_response(
                FORBIDDEN,
                "32 Forbidden",
                "Access to the requested path is forbidden",
            );
        }
        return make_error_response(
            SERVER_ERROR,
            "40 Server error",
            "Failed to validate requested path",
        );
    }
    let range_header = request_headers.get("range").cloned();
    let accept_compression_header = request_headers.get("accept-compression").cloned();
    let accept_compression_present = accept_compression_header.is_some();
    let compression = crate::common::negotiate_compression(accept_compression_header.as_deref());
    let body_bytes = Vec::new();
    let form_params = HashMap::new();
    let script_path = normalize_script_path(&state.scripting_config, &decoded_path);
    let request = Request {
        protocol: "tbip".to_string(),
        method: method.to_string(),
        path: decoded_path.clone(),
        query: query_params,
        body: body_bytes,
        form: form_params,
        headers: request_headers,
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
    match tokio::task::spawn_blocking({
        let root = state.root.clone();
        let p = decoded_path.clone();
        move || resolve_path(&root, &p)
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
                tracing::error!(path = %full_path.display(), error = %error, "failed to read file");
                make_error_response(
                    SERVER_ERROR,
                    "40 Server error",
                    "Failed to read requested file",
                )
            }
        },
        Ok(None) => make_error_response(NOT_FOUND, "31 Not found", "Requested file was not found"),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => make_error_response(
            FORBIDDEN,
            "32 Forbidden",
            "Access to the requested path is forbidden",
        ),
        Err(error) => {
            tracing::error!(path = %decoded_path, error = %error, "path resolution failed");
            make_error_response(
                SERVER_ERROR,
                "40 Server error",
                "Failed to resolve requested path",
            )
        }
    }
}
pub use crate::path::find_header_end;
