use crate::common::{FileBody, get_compressed_cached};
use crate::config::{
	DiskCache, INVALID_RANGE, OK, OK_EMPTY, RANGE_NOT_SATISFIABLE, SUPPORTED_COMPRESSION,
	TMUTP_VERSION, UNSUPPORTED_RANGE,
};
use crate::handler::response::{RangeParseResult, make_range_error_response, parse_range};
use crate::range_cache::get_compressed_range_cached;
use bytes::Bytes;
use std::fmt::Write;
use std::time::SystemTime;

/// Appends the optional trailer headers shared by file and range responses.
fn append_trailer(
	header: &mut String,
	announce_compression: bool,
	content_encoding: Option<&str>,
	modified: Option<SystemTime>,
) {
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

	if let Some(modified) = modified {
		let _ = writeln!(
			header,
			"Last-Modified: {}",
			crate::common::date::format_ymd(modified)
		);
	}

	header.push('\n');
}

/// Joins header and body in a single allocation (the body is copied exactly once).
fn assemble(header: String, body: &[u8]) -> Vec<u8> {
	let mut response = Vec::with_capacity(header.len() + body.len());
	response.extend_from_slice(header.as_bytes());
	response.extend_from_slice(body);
	response
}

pub async fn make_range_response(
	content: &FileBody,
	modified: Option<SystemTime>,
	range_header: &str,
	compression: Option<&str>,
	compression_minimum: usize,
	announce_compression: bool,
) -> Vec<u8> {
	let source_length = content.len();

	let (start, end) = match parse_range(range_header) {
		RangeParseResult::Valid(start, end) => (start, end),

		RangeParseResult::Invalid => {
			return make_range_error_response(
				INVALID_RANGE,
				range_header,
				"invalid-range",
				source_length,
			);
		}

		RangeParseResult::Unsupported => {
			let reason = if range_header.contains(',') {
				"multiple-ranges-not-supported"
			} else {
				"range-form-not-supported"
			};

			return make_range_error_response(
				UNSUPPORTED_RANGE,
				range_header,
				reason,
				source_length,
			);
		}
	};

	let Some((start, end)) = crate::common::request::resolve_byte_range(start, end, source_length)
	else {
		return make_range_error_response(
			RANGE_NOT_SATISFIABLE,
			range_header,
			"outside-source",
			source_length,
		);
	};

	// Zero-copy view into the cached file.
	let range_content = content.bytes().slice(start..=end);

	let compressed = match compression {
		Some(alg) if range_content.len() >= compression_minimum => {
			get_compressed_range_cached(content, start, end, alg)
				.await
				.map(|data| (data, alg))
		}
		_ => None,
	};

	let (body, content_encoding) = match compressed {
		Some((data, alg)) => (data, Some(alg)),
		None => (range_content, None),
	};

	// The whole-file hash comes from the cache; a range request never re-hashes the file.
	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: text/tmkup\nContent-Length: {}\nContent-Range: bytes {}-{}/{}\nFILE-SHA256: {}\nSOURCE-CONTENT-LENGTH: {}\n",
		TMUTP_VERSION,
		OK,
		body.len(),
		start,
		end,
		source_length,
		content.sha256_hex(),
		source_length,
	);
	append_trailer(
		&mut header,
		announce_compression,
		content_encoding,
		modified,
	);

	assemble(header, &body)
}

pub async fn make_file_response(
	content: &FileBody,
	modified: Option<SystemTime>,
	compression: Option<&str>,
	compression_minimum: usize,
	cache: &DiskCache,
	announce_compression: bool,
) -> Vec<u8> {
	let status = if content.is_empty() { OK_EMPTY } else { OK };

	let compressed = match compression {
		Some(alg) if content.len() >= compression_minimum => {
			get_compressed_cached(&cache.dir, content, alg, cache.policy)
				.await
				.map(|data| (data, alg))
		}
		_ => None,
	};

	let (body, content_encoding): (Bytes, Option<&str>) = match compressed {
		Some((data, alg)) => (data, Some(alg)),
		None => (content.bytes().clone(), None),
	};

	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: text/tmkup\nContent-Length: {}\nFILE-SHA256: {}\nSOURCE-CONTENT-LENGTH: {}\n",
		TMUTP_VERSION,
		status,
		body.len(),
		content.sha256_hex(),
		content.len(),
	);
	append_trailer(
		&mut header,
		announce_compression,
		content_encoding,
		modified,
	);

	assemble(header, &body)
}
