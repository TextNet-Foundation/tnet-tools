//! Общий парсинг HTTP-подобного запроса для TMUTP/TBIP.
//!
//! Извлекает из сырых байтов: версию протокола, метод, путь, query, заголовки,
//! Content-Length и тело. Протокольные проверки (версия, метод) — на вызывающей стороне.

use crate::common::frame::find_header_end;
use crate::common::path::{
	MAX_FIELDS, MAX_HEADER_LINE, MAX_HEADERS, PathError, normalize_request_path,
};
use std::collections::HashMap;
use url::form_urlencoded;

/// Распарсенный запрос.
#[derive(Debug)]
pub struct ParsedRequest {
	/// Версия из request line (например, "TMUTP/2.0").
	pub version: String,
	pub method: String,
	/// Нормализованный путь (после `normalize_request_path`).
	pub path: String,
	pub query: HashMap<String, String>,
	pub headers: HashMap<String, String>,
	pub body: Vec<u8>,
}

/// Результат парсинга: либо успех, либо ошибка с сообщением для ответа 30.
#[derive(Debug)]
pub enum ParseResult {
	Ok(Box<ParsedRequest>),
	BadRequest(&'static str),
	Forbidden,
}

/// Parses `key=value` pairs with a hard cap on the number of fields.
pub fn parse_fields(input: &str) -> Option<HashMap<String, String>> {
	let mut fields = HashMap::new();

	for (index, (key, value)) in form_urlencoded::parse(input.as_bytes())
		.into_owned()
		.enumerate()
	{
		if index >= MAX_FIELDS {
			return None;
		}

		fields.insert(key, value);
	}

	Some(fields)
}

/// Longest client-supplied value echoed back in a response header.
pub const MAX_ECHOED_HEADER: usize = 200;

/// Makes a client-supplied string safe to put into a response header: control characters
/// (< 0x20 and 0x7f) become `?` and the length is capped at `MAX_ECHOED_HEADER` characters.
pub fn sanitize_header_value(raw: &str) -> String {
	raw.chars()
		.take(MAX_ECHOED_HEADER)
		.map(|c| if c < ' ' || c == '\x7f' { '?' } else { c })
		.collect()
}

/// Applies RFC 7233 semantics to a parsed `bytes=start-end` range over `len` bytes:
/// `None` (not satisfiable) when `start >= len`, otherwise `end` is clamped to `len - 1`.
pub fn resolve_byte_range(start: usize, end: usize, len: usize) -> Option<(usize, usize)> {
	if start >= len || start > end {
		return None;
	}

	Some((start, end.min(len - 1)))
}

/// Разбирает сырой запрос. `max_body` — лимит на размер тела (0 для TBIP).
pub fn parse_request(raw: &[u8], max_body: usize) -> ParseResult {
	let Some(header_end) = find_header_end(raw) else {
		return ParseResult::BadRequest("Request headers are incomplete");
	};

	let header_text = String::from_utf8_lossy(&raw[..header_end]);
	let request_line = header_text.lines().next().unwrap_or_default().trim();

	if request_line.len() > MAX_HEADER_LINE {
		return ParseResult::BadRequest("Request line is too long");
	}

	let parts: Vec<&str> = request_line.split_whitespace().collect();

	let (Some(version), Some(method), Some(raw_path)) = (
		parts.first().copied(),
		parts.get(1).copied(),
		parts.get(2).copied(),
	) else {
		return ParseResult::BadRequest("Request must contain version, method and path");
	};

	if parts.len() > 3 {
		return ParseResult::BadRequest("Request line has too many parts");
	}

	let (path_part, query_str) = match raw_path.split_once('?') {
		Some((p, q)) => (p, Some(q)),
		None => (raw_path, None),
	};

	let request_path = match normalize_request_path(path_part) {
		Ok(p) => p,
		Err(PathError::OutsideRoot) => return ParseResult::Forbidden,
		Err(_) => return ParseResult::BadRequest("Invalid request path"),
	};

	let query_params = match query_str.map(parse_fields) {
		Some(Some(fields)) => fields,
		Some(None) => return ParseResult::BadRequest("Too many query fields"),
		None => HashMap::new(),
	};

	let mut request_headers = HashMap::new();
	let mut content_length: Option<usize> = None;
	let mut header_count = 0usize;

	for line in header_text.lines().skip(1) {
		if line.len() > MAX_HEADER_LINE {
			return ParseResult::BadRequest("Header line is too long");
		}

		let line = line.trim();

		if line.is_empty() {
			break;
		}

		header_count += 1;

		if header_count > MAX_HEADERS {
			return ParseResult::BadRequest("Too many headers");
		}

		let Some((key, value)) = line.split_once(':') else {
			return ParseResult::BadRequest("Malformed header line");
		};

		let key = key.trim().to_lowercase();
		let value = value.trim().to_string();

		if key == "transfer-encoding" {
			return ParseResult::BadRequest("Transfer-Encoding is not supported");
		}

		if key == "content-length" {
			let parsed = if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
				value.parse::<usize>().ok()
			} else {
				None
			};

			let Some(parsed) = parsed else {
				return ParseResult::BadRequest("Invalid Content-Length header");
			};

			if content_length.is_some_and(|prev| prev != parsed) {
				return ParseResult::BadRequest("Conflicting Content-Length headers");
			}

			content_length = Some(parsed);
		}

		request_headers.insert(key, value);
	}

	let content_length = content_length.unwrap_or(0);

	if content_length > max_body {
		return ParseResult::BadRequest("Request body exceeds the server limit");
	}

	let body_end = match header_end.checked_add(content_length) {
		Some(end) => end,
		None => return ParseResult::BadRequest("Invalid request body length"),
	};

	if raw.len() < body_end {
		return ParseResult::BadRequest("Request body is incomplete");
	}

	let body = raw[header_end..body_end].to_vec();

	ParseResult::Ok(Box::new(ParsedRequest {
		version: version.to_string(),
		method: method.to_string(),
		path: request_path,
		query: query_params,
		headers: request_headers,
		body,
	}))
}

#[cfg(test)]
#[path = "tests/request_tests.rs"]
mod tests;
