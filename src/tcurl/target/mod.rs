use crate::types::{Protocol, Target};
use anyhow::{Context, Result, anyhow, bail};
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

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URI does not contain a host"))?
        .to_string();

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

    let Some((host_part, port_part)) = authority.rsplit_once(':') else {
        return Ok((input.to_string(), None));
    };

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

    let normalized = format!("{scheme}://{host_part}:{port}{suffix}");

    Ok((normalized, Some(port)))
}
