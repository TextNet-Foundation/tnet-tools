use crate::common::{FileBody, compress_body};
use crate::config::{
	AppState, INVALID_RANGE, OK, RANGE_NOT_SATISFIABLE, SUPPORTED_COMPRESSION, TBIP_VERSION,
	UNSUPPORTED_RANGE,
};
use crate::path::mime_type;
use std::fmt::Write;
use std::time::SystemTime;

/// Largest range that is compressed inline. `make_range_response` is synchronous (its caller
/// does not await it), so bigger ranges are sent uncompressed instead of blocking the reactor.
const RANGE_INLINE_COMPRESS_MAX: usize = 256 * 1024;

// -----------------------------------------------------------------------------
// Range support
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub enum RangeParseResult {
	Valid(usize, usize),
	Invalid(&'static str),
	Unsupported(&'static str),
}

pub fn parse_range(value: &str) -> RangeParseResult {
	let Some((unit, range)) = value.trim().split_once('=') else {
		return RangeParseResult::Invalid("malformed-range");
	};
	if !unit.trim().eq_ignore_ascii_case("bytes") {
		return RangeParseResult::Unsupported("unsupported-range-unit");
	}
	let range = range.trim();
	if range.contains(',') {
		return RangeParseResult::Unsupported("multiple-ranges-not-supported");
	}
	let Some((start, end)) = range.split_once('-') else {
		return RangeParseResult::Unsupported("unsupported-range-form");
	};
	if start.is_empty() || end.is_empty() {
		return RangeParseResult::Unsupported("unsupported-range-form");
	}
	let start = match start.parse::<usize>() {
		Ok(value) => value,
		Err(_) => return RangeParseResult::Invalid("malformed-range"),
	};
	let end = match end.parse::<usize>() {
		Ok(value) => value,
		Err(_) => return RangeParseResult::Invalid("malformed-range"),
	};
	if start > end {
		return RangeParseResult::Invalid("invalid-range-order");
	}
	RangeParseResult::Valid(start, end)
}

pub fn make_range_response(
	content: &FileBody,
	modified: Option<SystemTime>,
	range_header: &str,
	compression: Option<&str>,
	state: &AppState,
	source_path: &std::path::Path,
	announce_compression: bool,
) -> Vec<u8> {
	let source_length = content.len();
	let (start, end) = match parse_range(range_header) {
		RangeParseResult::Valid(start, end) => (start, end),
		RangeParseResult::Invalid(reason) => {
			return make_range_error_response(
				INVALID_RANGE,
				reason,
				range_header,
				Some(source_length),
			);
		}
		RangeParseResult::Unsupported(reason) => {
			return make_range_error_response(
				UNSUPPORTED_RANGE,
				reason,
				range_header,
				Some(source_length),
			);
		}
	};
	let Some((start, end)) = crate::common::request::resolve_byte_range(start, end, source_length)
	else {
		return make_range_error_response(
			RANGE_NOT_SATISFIABLE,
			"outside-source",
			range_header,
			Some(source_length),
		);
	};
	let range_content = &content[start..=end];

	let compressed = match compression {
		Some(alg)
			if range_content.len() >= state.compression_minimum
				&& range_content.len() <= RANGE_INLINE_COMPRESS_MAX =>
		{
			compress_body(range_content, alg).map(|data| (data, alg))
		}
		_ => None,
	};
	let (body, content_encoding): (&[u8], Option<&str>) = match &compressed {
		Some((data, alg)) => (data, Some(alg)),
		None => (range_content, None),
	};

	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: {}\nContent-Length: {}\nContent-Range: bytes {}-{}/{}\n",
		TBIP_VERSION,
		OK,
		mime_type(source_path),
		body.len(),
		start,
		end,
		source_length,
	);
	// The whole-file hash is taken from the cache, never recomputed per request.
	let _ = writeln!(header, "FILE-SHA256: {}", content.sha256_hex());
	let _ = writeln!(header, "SOURCE-CONTENT-LENGTH: {}", source_length);
	header.push_str("Accept-Ranges: bytes\n");
	if let Some(modified) = modified {
		let _ = writeln!(
			header,
			"Last-Modified: {}",
			crate::common::date::format_ymd(modified)
		);
	}
	if announce_compression {
		let _ = writeln!(
			header,
			"Supported-Compression: {}",
			SUPPORTED_COMPRESSION.join(", ")
		);
	}
	if let Some(alg) = content_encoding {
		let _ = writeln!(header, "Content-Encoding: {}", alg);
	}
	header.push('\n');

	let mut response = Vec::with_capacity(header.len() + body.len());
	response.extend_from_slice(header.as_bytes());
	response.extend_from_slice(body);
	response
}

pub fn make_range_error_response(
	status: &str,
	reason: &str,
	range_header: &str,
	source_length: Option<usize>,
) -> Vec<u8> {
	let message = match status {
		INVALID_RANGE => "The requested byte range is invalid.",
		RANGE_NOT_SATISFIABLE => "The requested range is not available.",
		UNSUPPORTED_RANGE => "The requested range form is not supported.",
		_ => "The requested range cannot be fulfilled.",
	};
	let mut body = String::new();
	let _ = writeln!(body, "{}", message);
	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: text/plain\nContent-Length: {}\n",
		TBIP_VERSION,
		status,
		body.len()
	);
	if let Some(length) = source_length {
		let _ = writeln!(header, "SOURCE-CONTENT-LENGTH: {}", length);
	}
	let _ = writeln!(
		header,
		"Range-Error: {}; {}",
		crate::common::request::sanitize_header_value(range_header),
		reason
	);
	header.push('\n');
	let mut response = header.into_bytes();
	response.extend_from_slice(body.as_bytes());
	response
}

#[cfg(test)]
#[path = "tests/compression_tests.rs"]
mod tests;
