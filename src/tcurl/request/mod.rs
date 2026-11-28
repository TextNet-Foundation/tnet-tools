use crate::args::Args;
use crate::types::{Method, Protocol, Target};
use anyhow::{Result, anyhow, bail};
use std::fmt::Write;

pub fn build_request(
	target: &Target,
	method: Method,
	custom_headers: &[String],
	body: &[u8],
	data_was_text: bool,
	protocol_v1: bool,
) -> Result<Vec<u8>> {
	let mut headers = Vec::with_capacity(custom_headers.len() + 4);

	let host_header = if target.host.contains(':') {
		format!("[{}]", target.host)
	} else {
		target.host.clone()
	};

	headers.push(("Host".to_string(), host_header));
	headers.push(("User-Agent".to_string(), "tcurl/0.1.0".to_string()));

	let mut has_content_type = false;

	for header in custom_headers {
		if header.contains('\r') || header.contains('\n') {
			bail!("Request header contains a newline");
		}

		let (name, value) = header
			.split_once(':')
			.ok_or_else(|| anyhow!("Invalid header: {header}"))?;

		let name = name.trim();
		let value = value.trim();

		if name.is_empty() || value.contains('\0') {
			bail!("Invalid request header: {header}");
		}

		if name.eq_ignore_ascii_case("content-length") {
			bail!("Content-Length is managed automatically by tcurl");
		}

		if name.eq_ignore_ascii_case("host") {
			bail!("Host is determined by the URI");
		}

		if name.eq_ignore_ascii_case("content-type") {
			has_content_type = true;
		}

		headers.push((name.to_string(), value.to_string()));
	}

	if method == Method::Post && !has_content_type {
		let content_type = if data_was_text {
			"application/x-www-form-urlencoded"
		} else {
			"application/octet-stream"
		};

		headers.push(("Content-Type".to_string(), content_type.to_string()));
	}

	if target.protocol == Protocol::Tmutp {
		headers.push(("Content-Length".to_string(), body.len().to_string()));
	}

	let mut request = String::with_capacity(64);
	let _ = writeln!(
		request,
		"{} {} {}",
		target.protocol.version(protocol_v1),
		method.as_str(),
		target.path_query
	);

	for (name, value) in headers {
		let _ = writeln!(request, "{name}: {value}");
	}

	request.push('\n');

	let mut bytes = request.into_bytes();
	bytes.extend_from_slice(body);

	Ok(bytes)
}

pub fn protocol_uses_v1(target: &Target, args: &Args) -> bool {
	args.v1
		|| match target.protocol {
			Protocol::Tmutp => args.tv1,
			Protocol::Tbip => args.bv1,
		}
}
