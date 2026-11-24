use super::headers::header_value;
use crate::types::MAX_RESPONSE_BODY;
use anyhow::{Context, Result, bail};
use std::borrow::Cow;
use std::io::Read;

/// A response body ready for output.
#[derive(Debug)]
pub struct Decoded<'a> {
	pub data: Cow<'a, [u8]>,
	/// FILE-SHA256 (hash of the original file) may be compared with `data`.
	pub verifiable: bool,
}

/// Decompresses a gzip/zstd body, refusing to expand beyond `MAX_RESPONSE_BODY`.
///
/// Partial (Content-Range) bodies are decompressed too (the server compresses each range
/// on its own) but cannot be checked against FILE-SHA256, which covers the whole file.
/// Unknown encodings are returned as received and are not verifiable.
pub fn decode_body<'a>(header: &str, body: &'a [u8]) -> Result<Decoded<'a>> {
	decode_body_limited(header, body, MAX_RESPONSE_BODY)
}

pub fn decode_body_limited<'a>(header: &str, body: &'a [u8], limit: usize) -> Result<Decoded<'a>> {
	let raw = |verifiable| Decoded {
		data: Cow::Borrowed(body),
		verifiable,
	};

	let partial = header_value(header, "Content-Range").is_some();
	let encoding = header_value(header, "Content-Encoding").map(str::to_ascii_lowercase);

	let Some(encoding) = encoding.filter(|value| value != "identity") else {
		return Ok(raw(!partial));
	};

	let data = match encoding.as_str() {
		"gzip" | "x-gzip" => read_limited(flate2::read::MultiGzDecoder::new(body), limit, "gzip")?,
		"zstd" => {
			let decoder =
				zstd::stream::read::Decoder::new(body).context("Cannot start zstd decoder")?;
			read_limited(decoder, limit, "zstd")?
		}
		other => {
			eprintln!(
				"WARN: unsupported Content-Encoding {:?}: body left as received, FILE-SHA256 not checked",
				other
			);
			return Ok(raw(false));
		}
	};

	Ok(Decoded {
		data: Cow::Owned(data),
		verifiable: !partial,
	})
}

fn read_limited(reader: impl Read, limit: usize, name: &str) -> Result<Vec<u8>> {
	let mut out = Vec::new();

	reader
		.take(limit as u64 + 1)
		.read_to_end(&mut out)
		.with_context(|| format!("Cannot decompress {name} body"))?;

	if out.len() > limit {
		bail!("decompression limit exceeded ({limit} bytes)");
	}

	Ok(out)
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
