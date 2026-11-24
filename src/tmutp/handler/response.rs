use crate::compression;
use crate::config::*;
use std::fmt::Write;
use std::path::PathBuf;

pub fn make_version_error_response(version: &str, message: &str) -> Vec<u8> {
	let mut body = String::new();
	let _ = write!(
		body,
		"---tmk-meta\ntitle: \"51 Version not supported\"\n---tmk-meta\n\n# 51 Version not supported\n\n{}\n",
		message
	);

	let mut header = String::new();
	let _ = write!(
		header,
		"{} 51 VERSION NOT SUPPORTED\nContent-Type: text/tmkup\nContent-Length: {}\n\n",
		version,
		body.len()
	);

	let mut response = header.into_bytes();
	response.extend_from_slice(body.as_bytes());
	response
}

pub enum RangeParseResult {
	Valid(usize, usize),
	Invalid,
	Unsupported,
}

pub fn parse_range(value: &str) -> RangeParseResult {
	let Some((unit, range)) = value.trim().split_once('=') else {
		return RangeParseResult::Invalid;
	};

	if !unit.trim().eq_ignore_ascii_case("bytes") {
		return RangeParseResult::Unsupported;
	}

	let range = range.trim();

	if range.contains(',') {
		return RangeParseResult::Unsupported;
	}

	let Some((start, end)) = range.split_once('-') else {
		return RangeParseResult::Unsupported;
	};

	if start.is_empty() || end.is_empty() {
		return RangeParseResult::Unsupported;
	}

	let start = match start.parse::<usize>() {
		Ok(value) => value,
		Err(_) => return RangeParseResult::Invalid,
	};

	let end = match end.parse::<usize>() {
		Ok(value) => value,
		Err(_) => return RangeParseResult::Invalid,
	};

	if start > end {
		return RangeParseResult::Invalid;
	}

	RangeParseResult::Valid(start, end)
}

pub fn make_range_error_response(
	status: &str,
	requested_range: &str,
	reason: &str,
	source_length: usize,
) -> Vec<u8> {
	let (title, heading, message) = match status {
		INVALID_RANGE => (
			"52 — Invalid Range",
			"52 Invalid Range",
			"The requested byte range is invalid.",
		),
		RANGE_NOT_SATISFIABLE => (
			"53 — Range Not Satisfiable",
			"53 Range Not Satisfiable",
			"The requested range is not available.",
		),
		UNSUPPORTED_RANGE => (
			"54 — Unsupported Range",
			"54 Unsupported Range",
			"The requested range form is not supported.",
		),
		_ => (
			"Range Error",
			"Range Error",
			"The requested byte range cannot be provided.",
		),
	};

	let mut body = String::new();
	let _ = write!(
		body,
		"---tmk-meta\ntitle: \"{}\"\n---tmk-meta\n\n# {}\n\n{}\n",
		title, heading, message,
	);

	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: text/tmkup\nContent-Length: {}\nSOURCE-CONTENT-LENGTH: {}\nRange-Error: {}; {}\n\n",
		TMUTP_VERSION,
		status,
		body.len(),
		source_length,
		crate::common::request::sanitize_header_value(requested_range),
		reason,
	);

	let mut response = header.into_bytes();
	response.extend_from_slice(body.as_bytes());

	response
}

pub fn make_response(status: &str, body: &[u8]) -> Vec<u8> {
	let mut header = String::new();
	let _ = write!(
		header,
		"{} {}\nContent-Type: text/tmkup\nContent-Length: {}\n\n",
		TMUTP_VERSION,
		status,
		body.len()
	);

	let mut response = header.into_bytes();
	response.extend_from_slice(body);
	response
}

pub fn make_empty_response() -> Vec<u8> {
	make_response(OK_EMPTY, &[])
}

pub fn make_error_response(status: &str, title: &str, message: &str) -> Vec<u8> {
	let mut body = String::new();
	let _ = write!(
		body,
		"---tmk-meta\ntitle: \"{}\"\n---tmk-meta\n\n# {}\n\n{}\n\n[Back to main](/index.tmkup)",
		title, title, message
	);

	make_response(status, body.as_bytes())
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

pub async fn serve_static_file(
	full_path: PathBuf,
	method: &str,
	range_header: Option<&str>,
	compression: Option<&str>,
	compression_minimum: usize,
	compression_cache: &crate::config::DiskCache,
	accept_compression_present: bool,
) -> Vec<u8> {
	match crate::common::read_file_cached(&full_path).await {
		Ok(cached) => {
			let content = &cached.bytes;
			let modified = cached.modified;

			if method == "GET"
				&& let Some(range_value) = range_header
			{
				return compression::make_range_response(
					content,
					modified,
					range_value,
					compression,
					compression_minimum,
					accept_compression_present,
				)
				.await;
			}

			compression::make_file_response(
				content,
				modified,
				compression,
				compression_minimum,
				compression_cache,
				accept_compression_present,
			)
			.await
		}

		Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
			tracing::warn!(path = %full_path.display(), "file exceeds max_file_size");

			make_error_response(
				SERVER_ERROR,
				"40 Server error",
				"Requested file exceeds the server's max_file_size limit",
			)
		}

		Err(error) => {
			tracing::error!(path = %full_path.display(), error = %error, "failed to read file");

			make_error_response(
				SERVER_ERROR,
				"40 Server error",
				"Failed to read requested file",
			)
		}
	}
}

#[cfg(test)]
#[path = "tests/response_tests.rs"]
mod tests;
