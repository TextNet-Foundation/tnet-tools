use crate::types::{Protocol, Target};
use anyhow::{Context, Result, anyhow, bail};
use std::fmt::Write;
use url::Url;

pub fn parse_target(input: &str) -> Result<Target> {
	let (normalized, utnp_port) = normalize_u_port(input)?;

	let url = Url::parse(&normalized).with_context(|| format!("Invalid TextNet URI: {input}"))?;

	let protocol = match url.scheme() {
		"tmutp" => Protocol::Tmutp,
		"tbip" => Protocol::Tbip,
		other => bail!("Unsupported URI scheme: {other}"),
	};

	if !url.username().is_empty() || url.password().is_some() {
		bail!("User information in TextNet URIs is not supported");
	}

	// IPv6 literals are returned without brackets, so they can be used for
	// connect() and as a TLS ServerName (IpAddress).
	let host = match url.host() {
		Some(url::Host::Domain(domain)) => domain.to_string(),
		Some(url::Host::Ipv4(address)) => address.to_string(),
		Some(url::Host::Ipv6(address)) => address.to_string(),
		None => bail!("URI does not contain a host"),
	};

	let path = if url.path().is_empty() {
		"/"
	} else {
		url.path()
	};

	let mut path_query = path.to_string();

	if let Some(query) = url.query() {
		path_query.push('?');
		path_query.push_str(query);
	}

	let direct_port = if utnp_port.is_none() {
		url.port()
	} else {
		None
	};

	Ok(Target {
		protocol,
		host,
		path_query,
		direct_port,
		utnp_port,
	})
}

/// Converts host:u1234 into host:1234 for URL parsing,
/// while remembering that the port belongs to UTNP.
pub fn normalize_u_port(input: &str) -> Result<(String, Option<u16>)> {
	let (scheme, rest) = input
		.split_once("://")
		.ok_or_else(|| anyhow!("URI must contain ://"))?;

	let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());

	let authority = &rest[..authority_end];
	let suffix = &rest[authority_end..];

	// The colons inside an IPv6 literal "[::1]" are not port separators.
	let port_search_from = authority.rfind(']').map_or(0, |index| index + 1);

	let Some(colon) = authority[port_search_from..].rfind(':') else {
		return Ok((input.to_string(), None));
	};

	let (host_part, port_part) = (
		&authority[..port_search_from + colon],
		&authority[port_search_from + colon + 1..],
	);

	if !port_part.starts_with('u') {
		return Ok((input.to_string(), None));
	}

	let digits = &port_part[1..];

	if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
		bail!("Invalid UTNP port: {port_part}");
	}

	let port: u16 = digits
		.parse()
		.context("UTNP port is outside the valid range")?;

	if port == 0 {
		bail!("UTNP port cannot be zero");
	}

	let mut normalized = String::with_capacity(
		scheme.len() + host_part.len() + suffix.len() + port.to_string().len() + 3,
	);
	let _ = write!(normalized, "{scheme}://{host_part}:{port}{suffix}");

	Ok((normalized, Some(port)))
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
