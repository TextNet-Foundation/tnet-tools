use crate::types::{MAX_RESPONSE_BODY, MAX_RESPONSE_HEADER};
use anyhow::{Context, Result, bail};

pub fn parse_content_length(header: &[u8]) -> Result<usize> {
	let text = std::str::from_utf8(header).context("Response headers are not valid UTF-8")?;

	for line in text.lines().skip(1) {
		if let Some((name, value)) = line.split_once(':')
			&& name.trim().eq_ignore_ascii_case("content-length")
		{
			return value
				.trim()
				.parse::<usize>()
				.context("Invalid Content-Length in response");
		}
	}

	bail!("Response does not contain Content-Length")
}

/// Returns the end of the header block: the position right after the earliest
/// terminator among `\n\n`, `\r\n\r\n` and `\n\r\n`.
///
/// Every terminator is a line feed directly followed by an empty line, so the
/// first such line feed decides.
pub fn response_header_end(response: &[u8]) -> Option<usize> {
	response.iter().enumerate().find_map(|(index, byte)| {
		if *byte != b'\n' {
			return None;
		}

		let rest = &response[index + 1..];

		if rest.starts_with(b"\n") {
			Some(index + 2)
		} else if rest.starts_with(b"\r\n") {
			Some(index + 3)
		} else {
			None
		}
	})
}

/// Checks a partially received protocol response and cuts bytes that exceed
/// the announced Content-Length.
///
/// Returns `Ok(true)` once the whole response (headers, plus body unless
/// `head`) is present.
pub fn trim_and_check(response: &mut Vec<u8>, head: bool) -> Result<bool> {
	let Some(header_end) = response_header_end(response) else {
		if response.len() > MAX_RESPONSE_HEADER {
			bail!("Response headers exceed the size limit");
		}

		return Ok(false);
	};

	if header_end > MAX_RESPONSE_HEADER {
		bail!("Response headers exceed the size limit");
	}

	let content_length = parse_content_length(&response[..header_end])?;

	if content_length > MAX_RESPONSE_BODY {
		bail!("Response body exceeds the size limit");
	}

	let expected = header_end + if head { 0 } else { content_length };

	if response.len() >= expected {
		response.truncate(expected);
		return Ok(true);
	}

	Ok(false)
}
