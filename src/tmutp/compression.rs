use crate::common::compress_body;
use crate::common::get_compressed_cached;
use crate::config::{OK, OK_EMPTY, SUPPORTED_COMPRESSION, TMUTP_VERSION};
use sha2::Digest;
use std::fmt::Write;

pub fn make_range_response(
	content: &[u8],
	modified: Option<std::time::SystemTime>,
	range_header: &str,
	compression: Option<&str>,
	compression_minimum: usize,
	announce_compression: bool,
	file_sha256_hex: Option<&str>,
) -> Vec<u8> {
	use crate::config::{
		INVALID_RANGE, OK, RANGE_NOT_SATISFIABLE, SUPPORTED_COMPRESSION, TMUTP_VERSION,
		UNSUPPORTED_RANGE,
	};

	let source_length = content.len();

	let (start, end) = match crate::handler::response::parse_range(range_header) {
		crate::handler::response::RangeParseResult::Valid(start, end) => (start, end),

		crate::handler::response::RangeParseResult::Invalid => {
			return crate::handler::response::make_range_error_response(
				INVALID_RANGE,
				range_header,
				"invalid-range",
				source_length,
			);
		}

		crate::handler::response::RangeParseResult::Unsupported => {
			let reason = if range_header.contains(',') {
				"multiple-ranges-not-supported"
			} else {
				"range-form-not-supported"
			};

			return crate::handler::response::make_range_error_response(
				UNSUPPORTED_RANGE,
				range_header,
				reason,
				source_length,
			);
		}
	};

	if start >= source_length || end >= source_length {
		return crate::handler::response::make_range_error_response(
			RANGE_NOT_SATISFIABLE,
			range_header,
			"outside-source",
			source_length,
		);
	}

	let range_content = &content[start..=end];

	let (body, content_encoding) = if let Some(alg) = compression {
		if range_content.len() >= compression_minimum {
			match compress_body(range_content, alg) {
				Some(data) => (data, Some(alg)),
				None => (range_content.to_vec(), None),
			}
		} else {
			(range_content.to_vec(), None)
		}
	} else {
		(range_content.to_vec(), None)
	};

	let hash_hex = match file_sha256_hex {
		Some(hex) => hex.to_string(),
		None => {
			let mut s = String::new();
			write!(s, "{:x}", sha2::Sha256::digest(content)).unwrap();
			s
		}
	};

	let mut header = String::new();
	write!(
        header,
        "{} {}\nContent-Type: text/tmkup\nContent-Length: {}\nContent-Range: bytes {}-{}/{}\nFILE-SHA256: {}\nSOURCE-CONTENT-LENGTH: {}\n",
        TMUTP_VERSION,
        OK,
        body.len(),
        start,
        end,
        source_length,
        hash_hex,
        source_length,
    )
    .unwrap();

	if announce_compression {
		writeln!(
			header,
			"Supported-Compression: {}",
			SUPPORTED_COMPRESSION.join(", ")
		)
		.unwrap();
	}

	if let Some(alg) = content_encoding {
		writeln!(header, "Content-Encoding: {}", alg).unwrap();
	}

	if let Some(modified) = modified {
		let date: chrono::DateTime<chrono::Utc> = modified.into();

		writeln!(header, "Last-Modified: {}", date.format("%Y-%m-%d")).unwrap();
	}

	header.push('\n');

	let mut response = header.into_bytes();
	response.extend_from_slice(&body);

	response
}

#[allow(clippy::too_many_arguments)]
pub async fn make_file_response(
	content: &[u8],
	modified: Option<std::time::SystemTime>,
	compression: Option<&str>,
	compression_minimum: usize,
	cache_dir: &std::path::Path,
	source_path: &std::path::Path,
	announce_compression: bool,
	file_sha256_hex: Option<&str>,
) -> Vec<u8> {
	let status = if content.is_empty() { OK_EMPTY } else { OK };

	let hash_hex = match file_sha256_hex {
		Some(hex) => hex.to_string(),
		None => {
			let mut s = String::new();
			write!(s, "{:x}", sha2::Sha256::digest(content)).unwrap();
			s
		}
	};

	let (body, content_encoding) = if let Some(alg) = compression {
		if content.len() >= compression_minimum {
			match get_compressed_cached(cache_dir, source_path, content, alg, true, u64::MAX).await
			{
				Some(data) => (data, Some(alg)),
				None => (content.to_vec(), None),
			}
		} else {
			(content.to_vec(), None)
		}
	} else {
		(content.to_vec(), None)
	};

	let mut header = String::new();
	write!(
        header,
        "{} {}\nContent-Type: text/tmkup\nContent-Length: {}\nFILE-SHA256: {}\nSOURCE-CONTENT-LENGTH: {}\n",
        TMUTP_VERSION,
        status,
        body.len(),
        hash_hex,
        content.len(),
    )
    .unwrap();

	if announce_compression {
		writeln!(
			header,
			"Supported-Compression: {}",
			SUPPORTED_COMPRESSION.join(", ")
		)
		.unwrap();
	}

	if let Some(alg) = content_encoding {
		writeln!(header, "Content-Encoding: {}", alg).unwrap();
	}

	if let Some(modified) = modified {
		let date: chrono::DateTime<chrono::Utc> = modified.into();

		writeln!(header, "Last-Modified: {}", date.format("%Y-%m-%d")).unwrap();
	}

	header.push('\n');

	let mut response = header.into_bytes();
	response.extend_from_slice(&body);

	response
}
