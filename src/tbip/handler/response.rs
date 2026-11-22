use crate::compression::{get_cached_only, get_compressed_cached};
use crate::config::{
    AppState, OK, OK_EMPTY, SUPPORTED_COMPRESSION, TBIP_VERSION, VERSION_NOT_SUPPORTED,
};
use crate::path::mime_type;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
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
    header.push_str(&format!("FILE-SHA256: {}\n", hash_hex));
    header.push_str(&format!("SOURCE-CONTENT-LENGTH: {}\n", source_length));
    header.push_str("Accept-Ranges: bytes\n");

    if let Some(modified) = modified {
        let date: DateTime<Utc> = modified.into();
        header.push_str(&format!("Last-Modified: {}\n", date.format("%Y-%m-%d")));
    }
}

pub fn append_compression_headers(
    header: &mut String,
    announce: bool,
    content_encoding: Option<&str>,
) {
    if announce {
        header.push_str(&format!(
            "Supported-Compression: {}\n",
            SUPPORTED_COMPRESSION.join(", ")
        ));
    }

    if let Some(alg) = content_encoding {
        header.push_str(&format!("Content-Encoding: {}\n", alg));
    }
}

pub async fn make_file_response(
    content: &[u8],
    modified: Option<SystemTime>,
    compression: Option<&str>,
    state: &AppState,
    source_path: &Path,
    announce_compression: bool,
) -> Vec<u8> {
    let status = if content.is_empty() { OK_EMPTY } else { OK };

    let hash = Sha256::digest(content);
    let hash_hex = format!("{:x}", hash);

    let (body, content_encoding) = if let Some(alg) = compression {
        if content.len() >= state.compression_minimum {
            match get_compressed_cached(
                &state.compression_cache,
                state.compression_cache_enable,
                state.compression_cache_source_maximum,
                source_path,
                content,
                alg,
            )
            .await
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
        "{} {}\nContent-Type: {}\nContent-Length: {}\n",
        TBIP_VERSION,
        status,
        mime_type(source_path),
        body.len(),
    );

    append_file_metadata(&mut header, &hash_hex, content.len(), modified);
    append_compression_headers(&mut header, announce_compression, content_encoding);
    header.push('\n');

    let mut response = header.into_bytes();
    response.extend_from_slice(&body);
    response
}

pub async fn make_head_response(
    content: &[u8],
    modified: Option<SystemTime>,
    compression: Option<&str>,
    state: &AppState,
    source_path: &Path,
    announce_compression: bool,
) -> Vec<u8> {
    let source_length = content.len();
    let status = if source_length == 0 { OK_EMPTY } else { OK };

    let hash = Sha256::digest(content);
    let hash_hex = format!("{:x}", hash);

    let cached = if let Some(alg) = compression {
        if source_length >= state.compression_minimum
            && state.compression_cache_enable
            && (source_length as u64) <= state.compression_cache_source_maximum
        {
            get_cached_only(&state.compression_cache, source_path, content, alg).await
        } else {
            None
        }
    } else {
        None
    };

    let (content_length, content_encoding) = match cached {
        Some(data) => (data.len(), compression),
        None => (source_length, None),
    };

    let mut header = format!(
        "{} {}\nContent-Type: {}\nContent-Length: {}\n",
        TBIP_VERSION,
        status,
        mime_type(source_path),
        content_length,
    );

    append_file_metadata(&mut header, &hash_hex, source_length, modified);
    append_compression_headers(&mut header, announce_compression, content_encoding);
    header.push('\n');

    header.into_bytes()
}

pub fn make_empty_response() -> Vec<u8> {
    format!("{} {}\nContent-Length: 0\n\n", TBIP_VERSION, OK_EMPTY).into_bytes()
}

pub fn make_error_response(status: &str, _title: &str, message: &str) -> Vec<u8> {
    let body = format!("{}\n", message);

    let mut response = format!(
        "{} {}\nContent-Type: text/plain\nContent-Length: {}\n\n",
        TBIP_VERSION,
        status,
        body.len()
    )
    .into_bytes();

    response.extend_from_slice(body.as_bytes());
    response
}

pub fn make_version_error_response(version: &str, _message: &str) -> Vec<u8> {
    format!(
        "{} {}\nContent-Length: 0\n\n",
        version, VERSION_NOT_SUPPORTED
    )
    .into_bytes()
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
