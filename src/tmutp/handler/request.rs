use crate::compression::negotiate_compression;
use crate::config::*;
use crate::handler::response::*;
use crate::path::{percent_decode, resolve_path};
use crate::script_engine::Request;
use std::collections::HashMap;
use std::io;
use url::form_urlencoded;

pub use super::response::{find_header_end, replace_response_version};

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
        Some("TMUTP/2.0") => TMUTP_VERSION,
        Some("TMUTP/1.0") if state.support_first_version => TMUTP_FIRST_VERSION,
        Some("TMUTP/1.0") => {
            return make_version_error_response(
                TMUTP_VERSION,
                "TMUTP/1.0 support is disabled on this server",
            );
        }
        Some(_) => {
            return make_version_error_response(TMUTP_VERSION, "Server supports TMUTP/2.0");
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

    if method != "GET" && method != "POST" {
        return make_error_response(
            METHOD_NOT_ALLOWED,
            "50 Method not allowed",
            "TMUTP supports only GET and POST",
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
        form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>()
    } else {
        HashMap::new()
    };

    let mut request_headers = HashMap::new();
    let mut content_length = 0usize;
    let mut content_length_found = false;

    for line in lines {
        let line = line.trim();

        if line.is_empty() {
            break;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();

            if key == "content-length" {
                content_length = match value.parse::<usize>() {
                    Ok(value) => value,
                    Err(_) => {
                        return make_error_response(
                            BAD_REQUEST,
                            "30 Bad request",
                            "Invalid Content-Length header",
                        );
                    }
                };

                content_length_found = true;
            }

            request_headers.insert(key, value);
        }
    }

    if method == "POST" && !content_length_found {
        return make_error_response(
            BAD_REQUEST,
            "30 Bad request",
            "POST request must include Content-Length header",
        );
    }

    let range_header = request_headers.get("range").cloned();

    let accept_compression_header = request_headers.get("accept-compression").cloned();
    let accept_compression_present = accept_compression_header.is_some();
    let compression = negotiate_compression(accept_compression_header.as_deref());

    let body_start = header_end;
    let body_end = match body_start.checked_add(content_length) {
        Some(end) => end,
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Invalid request body length",
            );
        }
    };

    if raw.len() < body_end {
        return make_error_response(BAD_REQUEST, "30 Bad request", "Request body is incomplete");
    }

    let body_bytes = raw[body_start..body_end].to_vec();

    let form_params = if method == "POST" && !body_bytes.is_empty() {
        let body = String::from_utf8_lossy(&body_bytes);

        form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>()
    } else {
        HashMap::new()
    };

    let script_path = crate::handler::script::normalize_script_path(&decoded_path, state);

    let request = Request {
        protocol: "tmutp".to_string(),
        method: method.to_string(),
        path: decoded_path.clone(),
        query: query_params,
        body: body_bytes,
        form: form_params,
        headers: request_headers,
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

    match tokio::task::spawn_blocking({
        let root = state.root.clone();
        let p = decoded_path.clone();
        move || resolve_path(&root, &p)
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
            &format!("Path '{}' not found", decoded_path),
        ),

        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => make_error_response(
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
