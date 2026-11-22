use crate::config::{OK, OK_EMPTY, SUPPORTED_COMPRESSION, TMUTP_VERSION};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn negotiate_compression(accept: Option<&str>) -> Option<&'static str> {
    let value = accept?;

    for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let alg = token.to_ascii_lowercase();

        if let Some(&supported) = SUPPORTED_COMPRESSION.iter().find(|&&s| s == alg) {
            return Some(supported);
        }
    }

    None
}

pub fn compress_body(body: &[u8], alg: &str) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }

    match alg {
        "gzip" => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(body).ok()?;
            encoder.finish().ok()
        }
        "zstd" => {
            let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).ok()?;
            encoder.write_all(body).ok()?;
            encoder.finish().ok()
        }
        _ => None,
    }
}

pub fn cache_path(cache_dir: &Path, source_path: &Path, alg: &str) -> PathBuf {
    let path_hash = Sha256::digest(source_path.to_string_lossy().as_bytes());
    let hex = format!("{:x}", path_hash);
    cache_dir.join(format!("{}.{}", hex, alg))
}

pub async fn get_compressed_cached(
    cache_dir: &Path,
    source_path: &Path,
    body: &[u8],
    alg: &str,
) -> Option<Vec<u8>> {
    let cache_file = cache_path(cache_dir, source_path, alg);
    let current_hash = Sha256::digest(body);

    if let Ok(data) = tokio::fs::read(&cache_file).await {
        if data.len() >= 32 && data[..32] == current_hash[..] {
            return Some(data[32..].to_vec());
        }

        let _ = tokio::fs::remove_file(&cache_file).await;
    }

    let compressed = compress_body(body, alg)?;

    let mut cache_data = Vec::with_capacity(32 + compressed.len());
    cache_data.extend_from_slice(&current_hash);
    cache_data.extend_from_slice(&compressed);

    let _ = tokio::fs::write(&cache_file, &cache_data).await;

    Some(compressed)
}

pub fn make_range_response(
    content: &[u8],
    modified: Option<std::time::SystemTime>,
    range_header: &str,
    compression: Option<&str>,
    compression_minimum: usize,
    announce_compression: bool,
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

    let hash = sha2::Sha256::digest(content);
    let hash_hex = format!("{:x}", hash);

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

pub async fn make_file_response(
    content: &[u8],
    modified: Option<std::time::SystemTime>,
    compression: Option<&str>,
    compression_minimum: usize,
    cache_dir: &std::path::Path,
    source_path: &std::path::Path,
    announce_compression: bool,
) -> Vec<u8> {
    let status = if content.is_empty() { OK_EMPTY } else { OK };

    let hash = sha2::Sha256::digest(content);
    let hash_hex = format!("{:x}", hash);

    let (body, content_encoding) = if let Some(alg) = compression {
        if content.len() >= compression_minimum {
            match get_compressed_cached(cache_dir, source_path, content, alg).await {
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
