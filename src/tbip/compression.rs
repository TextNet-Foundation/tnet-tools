use crate::config::{
    AppState, INVALID_RANGE, OK, RANGE_NOT_SATISFIABLE, SUPPORTED_COMPRESSION, TBIP_VERSION,
    UNSUPPORTED_RANGE,
};
use crate::path::mime_type;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
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
    use std::io::Write;
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
pub async fn get_cached_only(
    cache_dir: &Path,
    source_path: &Path,
    body: &[u8],
    alg: &str,
) -> Option<Vec<u8>> {
    let cache_file = cache_path(cache_dir, source_path, alg);
    let current_hash = Sha256::digest(body);
    if let Ok(data) = tokio::fs::read(&cache_file).await
        && data.len() >= 32
        && data[..32] == current_hash[..]
    {
        return Some(data[32..].to_vec());
    }
    None
}
pub async fn get_compressed_cached(
    cache_dir: &Path,
    cache_enable: bool,
    source_maximum: u64,
    source_path: &Path,
    body: &[u8],
    alg: &str,
) -> Option<Vec<u8>> {
    let current_hash = Sha256::digest(body);
    let can_cache = cache_enable && (body.len() as u64) <= source_maximum;
    let cache_file = cache_path(cache_dir, source_path, alg);
    if can_cache && let Ok(data) = tokio::fs::read(&cache_file).await {
        if data.len() >= 32 && data[..32] == current_hash[..] {
            return Some(data[32..].to_vec());
        }
        let _ = tokio::fs::remove_file(&cache_file).await;
    }
    let compressed = compress_body(body, alg)?;
    if can_cache {
        let mut cache_data = Vec::with_capacity(32 + compressed.len());
        cache_data.extend_from_slice(&current_hash);
        cache_data.extend_from_slice(&compressed);
        let _ = tokio::fs::write(&cache_file, &cache_data).await;
    }
    Some(compressed)
}
// -----------------------------------------------------------------------------
// Range support (moved here to keep response.rs under 300 lines)
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
    content: &[u8],
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
    if start >= source_length {
        return make_range_error_response(
            RANGE_NOT_SATISFIABLE,
            "outside-source",
            range_header,
            Some(source_length),
        );
    }
    let end = end.min(source_length - 1);
    let range_content = &content[start..=end];
    let (body, content_encoding) = if let Some(alg) = compression {
        if range_content.len() >= state.compression_minimum {
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
    let hash = Sha256::digest(content);
    let hash_hex = format!("{:x}", hash);
    let mut header = format!(
        "{} {}\nContent-Type: {}\nContent-Length: {}\nContent-Range: bytes {}-{}/{}\n",
        TBIP_VERSION,
        OK,
        mime_type(source_path),
        body.len(),
        start,
        end,
        source_length,
    );
    // append metadata
    header.push_str(&format!("FILE-SHA256: {}\n", hash_hex));
    header.push_str(&format!("SOURCE-CONTENT-LENGTH: {}\n", source_length));
    header.push_str("Accept-Ranges: bytes\n");
    if let Some(modified) = modified {
        let date: DateTime<Utc> = modified.into();
        header.push_str(&format!("Last-Modified: {}\n", date.format("%Y-%m-%d")));
    }
    if announce_compression {
        header.push_str(&format!(
            "Supported-Compression: {}\n",
            SUPPORTED_COMPRESSION.join(", ")
        ));
    }
    if let Some(alg) = content_encoding {
        header.push_str(&format!("Content-Encoding: {}\n", alg));
    }
    header.push('\n');
    let mut response = header.into_bytes();
    response.extend_from_slice(&body);
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
    let body = format!("{}\n", message);
    let mut header = format!(
        "{} {}\nContent-Type: text/plain\nContent-Length: {}\n",
        TBIP_VERSION,
        status,
        body.len()
    );
    if let Some(length) = source_length {
        header.push_str(&format!("SOURCE-CONTENT-LENGTH: {}\n", length));
    }
    header.push_str(&format!(
        "Range-Error: {}; {}\n",
        range_header.trim(),
        reason
    ));
    header.push('\n');
    let mut response = header.into_bytes();
    response.extend_from_slice(body.as_bytes());
    response
}
