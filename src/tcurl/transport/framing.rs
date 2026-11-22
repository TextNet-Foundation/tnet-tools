use crate::types::MAX_RESPONSE_BODY;
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

pub fn response_header_end(response: &[u8]) -> Option<usize> {
	response
		.windows(4)
		.position(|window| window == b"\r\n\r\n")
		.map(|position| position + 4)
		.or_else(|| {
			response
				.windows(2)
				.position(|window| window == b"\n\n")
				.map(|position| position + 2)
		})
}

pub fn expected_response_length(response: &[u8], head: bool) -> Result<Option<usize>> {
	let Some(header_end) = response_header_end(response) else {
		return Ok(None);
	};

	let content_length = parse_content_length(&response[..header_end])?;

	if content_length > MAX_RESPONSE_BODY {
		bail!("Response body exceeds the size limit");
	}

	Ok(Some(header_end + if head { 0 } else { content_length }))
}
