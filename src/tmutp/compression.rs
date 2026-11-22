use crate::common::compress_body;
use crate::common::get_compressed_cached;
use crate::config::{OK, OK_EMPTY, SUPPORTED_COMPRESSION, TMUTP_VERSION};
use sha2::Digest;

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
        None => format!("{:x}", sha2::Sha256::digest(content)),
    };

    let mut header = format!(
        "{} {}\n\
         Content-Type: text/tmkup\n\
         Content-Length: {}\n\
         Content-Range: bytes {}-{}/{}\n\
         FILE-SHA256: {}\n\
         SOURCE-CONTENT-LENGTH: {}\n",
        TMUTP_VERSION,
        OK,
        body.len(),
        start,
        end,
        source_length,
        hash_hex,
        source_length,
    );

    if announce_compression {
        header.push_str(&format!(
            "Supported-Compression: {}\n",
            SUPPORTED_COMPRESSION.join(", ")
        ));
    }

    if let Some(alg) = content_encoding {
        header.push_str(&format!("Content-Encoding: {}\n", alg));
    }

    if let Some(modified) = modified {
        let date: chrono::DateTime<chrono::Utc> = modified.into();

        header.push_str(&format!("Last-Modified: {}\n", date.format("%Y-%m-%d")));
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
        None => format!("{:x}", sha2::Sha256::digest(content)),
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

    let mut header = format!(
        "{} {}\n\
         Content-Type: text/tmkup\n\
         Content-Length: {}\n\
         FILE-SHA256: {}\n\
         SOURCE-CONTENT-LENGTH: {}\n",
        TMUTP_VERSION,
        status,
        body.len(),
        hash_hex,
        content.len(),
    );

    if announce_compression {
        header.push_str(&format!(
            "Supported-Compression: {}\n",
            SUPPORTED_COMPRESSION.join(", ")
        ));
    }

    if let Some(alg) = content_encoding {
        header.push_str(&format!("Content-Encoding: {}\n", alg));
    }

    if let Some(modified) = modified {
        let date: chrono::DateTime<chrono::Utc> = modified.into();

        header.push_str(&format!("Last-Modified: {}\n", date.format("%Y-%m-%d")));
    }

    header.push('\n');

    let mut response = header.into_bytes();
    response.extend_from_slice(&body);

    response
}
