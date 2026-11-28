use crate::common::{DiskCachePolicy, FileBody, get_compressed_cached};
use crate::config::{
	AppState, OK, OK_EMPTY, SUPPORTED_COMPRESSION, TBIP_VERSION, VERSION_NOT_SUPPORTED,
};
use crate::path::mime_type;
use bytes::Bytes;
use std::fmt::Write;
use std::path::Path;
use std::time::SystemTime;

// Re-exports for functions moved to other modules to keep file sizes under limit.
pub use crate::compression::make_range_response;

pub fn append_file_metadata(
	header: &mut String,
	hash_hex: &str,
	source_length: usize,
	modified: Option<SystemTime>,
) {
	let _ = writeln!(header, "FILE-SHA256: {}", hash_hex);
	let _ = writeln!(header, "SOURCE-CONTENT-LENGTH: {}", source_length);
	header.push_str("Accept-Ranges: bytes\n");

	if let Some(modified) = modified {
		let _ = writeln!(
			header,
			"Last-Modified: {}",
			crate::common::date::format_ymd(modified)
		);
	}
}

pub fn append_compression_headers(
	header: &mut String,
	announce: bool,
	content_encoding: Option<&str>,
) {
	if announce {
		let _ = writeln!(
			header,
			"Supported-Compression: {}",
			SUPPORTED_COMPRESSION.join(", ")
		);
	}

	if let Some(alg) = content_encoding {
		let _ = writeln!(header, "Content-Encoding: {}", alg);
	}
}

/// Single place that decides what a GET sends and what a HEAD announces.
///
/// HEAD and GET both go through here, so `Content-Length` and `Content-Encoding` always
/// agree. A HEAD with `Accept-Compression` may therefore trigger (and cache) the same
/// compression a GET would, which is shared with concurrent requests via singleflight.
async fn select_representation<'a>(
	content: &FileBody,
	compression: Option<&'a str>,
	state: &AppState,
) -> (Bytes, Option<&'a str>) {
	let compressed = match compression {
		Some(alg) if content.len() >= state.compression_minimum => {
			let policy = DiskCachePolicy {
				enable: state.compression_cache_enable,
				source_maximum: state.compression_cache_source_maximum,
			};

			get_compressed_cached(&state.compression_cache, content, alg, policy)
				.await
				.map(|data| (data, alg))
		}
		_ => None,
	};

	match compressed {
		Some((data, alg)) => (data, Some(alg)),
		None => (content.bytes().clone(), None),
	}
}

fn build_file_header(
	content: &FileBody,
	modified: Option<SystemTime>,
	source_path: &Path,
	body_length: usize,
	content_encoding: Option<&str>,
	announce_compression: bool,
) -> String {
	let status = if content.is_empty() { OK_EMPTY } else { OK };

	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: {}\nContent-Length: {}\n",
		TBIP_VERSION,
		status,
		mime_type(source_path),
		body_length,
	);

	append_file_metadata(&mut header, content.sha256_hex(), content.len(), modified);
	append_compression_headers(&mut header, announce_compression, content_encoding);
	header.push('\n');
	header
}

pub async fn make_file_response(
	content: &FileBody,
	modified: Option<SystemTime>,
	compression: Option<&str>,
	state: &AppState,
	source_path: &Path,
	announce_compression: bool,
) -> Vec<u8> {
	let (body, content_encoding) = select_representation(content, compression, state).await;

	let header = build_file_header(
		content,
		modified,
		source_path,
		body.len(),
		content_encoding,
		announce_compression,
	);

	let mut response = Vec::with_capacity(header.len() + body.len());
	response.extend_from_slice(header.as_bytes());
	response.extend_from_slice(&body);
	response
}

pub async fn make_head_response(
	content: &FileBody,
	modified: Option<SystemTime>,
	compression: Option<&str>,
	state: &AppState,
	source_path: &Path,
	announce_compression: bool,
) -> Vec<u8> {
	let (body, content_encoding) = select_representation(content, compression, state).await;

	build_file_header(
		content,
		modified,
		source_path,
		body.len(),
		content_encoding,
		announce_compression,
	)
	.into_bytes()
}

pub fn make_empty_response() -> Vec<u8> {
	let mut out = String::new();
	let _ = write!(out, "{} {}\nContent-Length: 0\n\n", TBIP_VERSION, OK_EMPTY);
	out.into_bytes()
}

pub fn make_error_response(status: &str, _title: &str, message: &str) -> Vec<u8> {
	let mut body = String::new();
	let _ = writeln!(body, "{}", message);

	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: text/plain\nContent-Length: {}\n\n",
		TBIP_VERSION,
		status,
		body.len()
	);
	let mut response = header.into_bytes();
	response.extend_from_slice(body.as_bytes());
	response
}

pub fn make_version_error_response(version: &str, _message: &str) -> Vec<u8> {
	let mut out = String::new();
	let _ = write!(
		out,
		"{} {}\nContent-Length: 0\n\n",
		version, VERSION_NOT_SUPPORTED
	);
	out.into_bytes()
}

pub fn replace_response_version(response: &mut Vec<u8>, version: &str) {
	let header_end = response.iter().position(|byte| *byte == b'\n');

	let Some(line_end) = header_end else {
		return;
	};

	let first_line = &response[..line_end];

	let Some(space_position) = first_line.iter().position(|byte| *byte == b' ') else {
		return;
	};

	response.splice(0..space_position, version.as_bytes().iter().copied());
}

#[cfg(test)]
#[path = "../tests/response_tests.rs"]
mod tests;
