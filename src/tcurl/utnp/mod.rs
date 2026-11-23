use crate::args::Args;
use crate::transport::exchange_with_fallback;
use crate::types::{Endpoint, Target, TransportMode};
use anyhow::{Context, Result, anyhow, bail};
use std::fmt::Write;

pub fn parse_utnp_security(response: &str) -> Vec<String> {
	response
		.lines()
		.skip(1)
		.take_while(|line| !line.trim().is_empty())
		.find_map(|line| {
			let (name, value) = line.split_once(':')?;

			if !name.trim().eq_ignore_ascii_case("Security") {
				return None;
			}

			Some(
				value
					.split(',')
					.map(str::trim)
					.filter(|value| !value.is_empty())
					.map(str::to_ascii_lowercase)
					.collect(),
			)
		})
		.unwrap_or_default()
}

/// Hostnames and IP literals only: the value comes from the network and is
/// printed to the terminal and used for connect().
pub fn is_valid_host(host: &str) -> bool {
	!host.is_empty()
		&& host.len() <= 253
		&& host
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

/// Chooses the host for the protocol connection.
///
/// A host announced over an unprotected UTNP exchange can be forged by anyone
/// on the path, so it is ignored (only the port is taken) unless the user
/// passed `--trust-utnp-host`. After a TLS/SSH-protected exchange the announced
/// host is accepted.
pub fn choose_host(original: &str, announced: &str, secure: bool, trusted: bool) -> String {
	if announced.eq_ignore_ascii_case(original) {
		return original.to_string();
	}

	if secure {
		return announced.to_string();
	}

	if trusted {
		eprintln!(
			"WARN: --trust-utnp-host: using host {announced} announced over an unprotected UTNP exchange"
		);
		return announced.to_string();
	}

	eprintln!(
		"WARN: UTNP (unprotected) announced host {announced}; ignoring it and keeping {original} \
		 (use --trust-utnp-host to accept)"
	);

	original.to_string()
}

pub async fn negotiate_endpoint(
	target: &Target,
	utnp_port: u16,
	mode: TransportMode,
	args: &Args,
) -> Result<Endpoint> {
	let utnp_v1 = args.v1 || args.uv1;
	let protocol_v1 = crate::request::protocol_uses_v1(target, args);
	let protocol_version = crate::types::Protocol::version_number(protocol_v1);

	let request = if utnp_v1 {
		let mut output = String::with_capacity(32);
		let _ = writeln!(output, "UTNP/1.0 NEGOTIATE {}", target.protocol.name());
		output
	} else {
		let mut output = String::with_capacity(64);
		let _ = write!(
			output,
			"UTNP/2.0 NEGOTIATE {}\nSupported-Versions: {}\n\n",
			target.protocol.name(),
			protocol_version
		);
		output
	};

	// UTNP/1.0 is TCP-only. This does not force the later protocol
	// connection to TCP unless the global --v1 option was selected.
	let negotiation_mode = if utnp_v1 {
		TransportMode::TcpOnly
	} else {
		mode
	};

	let frame = crate::types::FrameKind::Utnp;

	let exchanged = exchange_with_fallback(
		&target.host,
		utnp_port,
		request.as_bytes(),
		frame,
		negotiation_mode,
		args,
	)
	.await
	.context("UTNP negotiation failed")?;

	let secure_channel = exchanged.transport.is_secure();
	let response = exchanged.data;

	let response_text = String::from_utf8_lossy(&response);
	let first_line = response_text
		.lines()
		.next()
		.ok_or_else(|| anyhow!("UTNP returned an empty response"))?;

	let parts: Vec<&str> = first_line.split_whitespace().collect();
	let expected_utnp_version = if utnp_v1 { "UTNP/1.0" } else { "UTNP/2.0" };

	if parts.len() != 7
		|| parts[0] != expected_utnp_version
		|| parts[1] != "START"
		|| parts[2] != "PROTOCOL"
	{
		bail!("UTNP negotiation was rejected: {}", response_text.trim());
	}

	if !parts[3].eq_ignore_ascii_case(target.protocol.name()) {
		bail!("UTNP returned an unexpected protocol: {}", parts[3]);
	}

	if parts[4] != protocol_version {
		bail!(
			"UTNP selected unsupported version {} (expected {})",
			parts[4],
			protocol_version
		);
	}

	let port: u16 = parts[6]
		.parse()
		.context("UTNP returned an invalid protocol port")?;

	if port == 0 {
		bail!("UTNP returned port 0");
	}

	let announced_host = parts[5].trim_start_matches('[').trim_end_matches(']');

	if !is_valid_host(announced_host) {
		bail!("UTNP returned an invalid protocol host");
	}

	let host = choose_host(
		&target.host,
		announced_host,
		secure_channel,
		args.trust_utnp_host,
	);

	let supported_security = if utnp_v1 {
		Vec::new()
	} else {
		parse_utnp_security(&response_text)
	};

	let required_security: &[&str] = if utnp_v1 {
		&[]
	} else {
		match mode {
			TransportMode::TlsThenTcp => &["tls"],
			TransportMode::SshThenTlsThenTcp => &["ssh", "tls"],
			TransportMode::TcpOnly => &[],
		}
	};

	let security_list = if supported_security.is_empty() {
		"none".to_string()
	} else {
		supported_security.join(", ")
	};

	eprintln!("UTNP Security: {}", security_list);

	if !secure_channel {
		eprintln!(
			"WARN: UTNP exchange was not protected by TLS/SSH; the Security header \
			 and the announced host are not authenticated"
		);
	}

	if !required_security.is_empty() {
		let security_supported = required_security.iter().any(|required| {
			supported_security
				.iter()
				.any(|supported| supported.eq_ignore_ascii_case(required))
		});

		if !security_supported {
			let required = required_security.join(" or ");

			if !args.ignore_utnp_security {
				bail!(
					"UTNP security mismatch: client requires {}, \
                     but server supports: {}. \
                     Use --ignore-utnp-security to override.",
					required,
					security_list
				);
			}

			eprintln!("WARN: UTNP returned Security: {}", security_list);
			eprintln!(
				"WARN: --ignore-utnp-security is enabled; \
                 attempting connection anyway."
			);
		}
	}

	eprintln!(
		"UTNP selected {} {} at {}:{}",
		target.protocol.name(),
		target.protocol.version(protocol_v1),
		host,
		port
	);

	Ok(Endpoint { host, port })
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
