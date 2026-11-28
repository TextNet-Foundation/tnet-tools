mod decode;
mod headers;
mod sanitize;

use crate::transport::response_header_end;
use anyhow::{Context, Result, anyhow, bail};
use decode::decode_body;
use headers::{header_value, is_success, status_code};
use sanitize::{render_body, sanitize_terminal};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::io::IsTerminal;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

pub struct OutputOptions<'a> {
	pub output: &'a Option<PathBuf>,
	pub output_header: &'a Option<PathBuf>,
	pub output_on_error: bool,
	/// Keep the body exactly as received: no decompression, no FILE-SHA256 check.
	pub raw: bool,
}

/// Process exit code for a response status: 0 for 2x, 1 for anything else.
pub fn exit_code_for(status: Option<u16>) -> u8 {
	u8::from(!is_success(status))
}

/// Compares FILE-SHA256 with the (already decompressed) body.
///
/// The server hashes the original file, so the check is impossible for partial
/// (Content-Range) responses. Returns `Ok(true)` when verified, `Ok(false)` when
/// it cannot be checked.
pub fn verify_file_sha256(header: &str, body: &[u8]) -> Result<bool> {
	let Some(expected) = header_value(header, "FILE-SHA256") else {
		return Ok(false);
	};

	if header_value(header, "Content-Range").is_some() {
		return Ok(false);
	}

	let actual = format!("{:x}", Sha256::digest(body));

	if !actual.eq_ignore_ascii_case(expected) {
		bail!(
			"FILE-SHA256 mismatch: server announced {expected}, received body hashes to {actual}"
		);
	}

	Ok(true)
}

/// Prints and saves the response. Returns the process exit code.
pub async fn handle_response(
	response: &[u8],
	head: bool,
	options: OutputOptions<'_>,
) -> Result<u8> {
	let header_end = response_header_end(response)
		.ok_or_else(|| anyhow!("Server returned an incomplete response"))?;

	let header = &response[..header_end];
	let body = if head {
		&response[header_end..header_end]
	} else {
		&response[header_end..]
	};

	let header_text = String::from_utf8_lossy(header);
	let status = status_code(&header_text);
	let success = is_success(status);
	let stderr_tty = std::io::stderr().is_terminal();

	for line in header_text.lines() {
		if stderr_tty {
			eprintln!("{}", sanitize_terminal(line));
		} else {
			eprintln!("{line}");
		}
	}

	let mut decompressed: Option<Vec<u8>> = None;

	if success && !head && !options.raw {
		let decoded = decode_body(&header_text, body)?;

		if decoded.verifiable && verify_file_sha256(&header_text, &decoded.data)? {
			eprintln!("FILE-SHA256 verified");
		}

		// A hash mismatch returned an error above, before anything is written.
		if let Cow::Owned(data) = decoded.data {
			decompressed = Some(data);
		}
	}

	let body = decompressed.as_deref().unwrap_or(body);

	if let Some(path) = options.output_header {
		tokio::fs::write(path, response)
			.await
			.with_context(|| format!("Cannot save complete response to {}", path.display()))?;
	}

	if let Some(path) = options.output {
		if success || options.output_on_error {
			tokio::fs::write(path, body)
				.await
				.with_context(|| format!("Cannot save response body to {}", path.display()))?;
		} else {
			eprintln!(
				"Status is not 2x: not writing the body to {} (use --output-on-error)",
				path.display()
			);
		}
	} else {
		let (rendered, changed) = render_body(body, std::io::stdout().is_terminal());

		if changed {
			eprintln!("WARN: control characters in the body were escaped for the terminal");
		}

		let mut stdout = tokio::io::stdout();
		stdout.write_all(&rendered).await?;
		stdout.flush().await?;
	}

	Ok(exit_code_for(status))
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
