mod discovery;
mod frame;

pub use discovery::*;
pub use frame::*;

use crate::config::{AppState, Protocol};
use std::fmt::Write;

pub fn process_request(frame: &[u8], state: &AppState) -> Vec<u8> {
	let text = match std::str::from_utf8(frame) {
		Ok(value) => value,
		Err(_) => return error_response("2.0", "Invalid request"),
	};

	let mut lines = text.lines();

	let request_line = lines.next().unwrap_or("").trim_end_matches('\r');

	let parts: Vec<&str> = request_line.split_whitespace().collect();

	if parts.is_empty() {
		return error_response("2.0", "Invalid request");
	}

	let (version, legacy) = match parts[0] {
		"UTNP/2.0" => ("2.0", false),
		"UTNP/1.0" if state.support_first_version => ("1.0", true),
		"UTNP/1.0" => return unsupported_utnp_version_response(state),
		_ => return unsupported_utnp_version_response(state),
	};

	let mut headers: Vec<(String, String)> = Vec::new();

	if !legacy {
		for line in lines {
			let line = line.trim_end_matches('\r');

			if line.is_empty() {
				break;
			}

			if let Some((name, value)) = line.split_once(':') {
				headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
			} else {
				return error_response(version, "Invalid header");
			}
		}
	}

	if parts.len() < 2 {
		return error_response(version, "Invalid request");
	}

	match parts[1] {
		"LIST" if parts.len() == 2 => {
			if legacy {
				available_v1(&state.protocols)
			} else {
				available_v2(&state.protocols, &state.enabled_security)
			}
		}

		"NEGOTIATE" if parts.len() == 3 => {
			if legacy {
				negotiate_v1(parts[2], &state.protocols)
			} else {
				let values: Vec<&str> = headers
					.iter()
					.filter(|(name, _)| name == "supported-versions")
					.map(|(_, value)| value.as_str())
					.collect();

				if values.len() > 1 {
					error_response(version, "Invalid request")
				} else {
					negotiate_v2(
						parts[2],
						values.first().copied(),
						&state.protocols,
						&state.enabled_security,
					)
				}
			}
		}

		"EXPLORE" if !legacy && parts.len() == 2 => explore_response(&state.explore_nodes),

		_ => error_response(version, "Invalid request"),
	}
}

pub fn unsupported_utnp_version_response(state: &AppState) -> Vec<u8> {
	let mut supported = Vec::with_capacity(2);
	supported.push("UTNP/2.0");

	if state.support_first_version {
		supported.push("UTNP/1.0");
	}

	let mut output = String::with_capacity(64);
	let _ = writeln!(
		output,
		"UTNP ERROR - UNSUPPORTED UTNP VERSION, SUPPORTED {}",
		supported.join(", ")
	);
	output.into_bytes()
}

pub fn error_response(version: &str, message: &str) -> Vec<u8> {
	let mut output = String::with_capacity(version.len() + message.len() + 12);
	let _ = writeln!(output, "UTNP/{version} ERROR {message}");
	output.into_bytes()
}

pub fn version_rank(version: &str) -> (u32, u32) {
	let mut parts = version.split('.');

	(
		parts.next().and_then(|s| s.parse().ok()).unwrap_or(0),
		parts.next().and_then(|s| s.parse().ok()).unwrap_or(0),
	)
}

pub fn default_protocol_version(protocol: &Protocol) -> &str {
	&protocol.version[protocol.default_version - 1]
}

pub fn enabled_security_for_protocol(configured: &[String], enabled: &[String]) -> Vec<String> {
	configured
		.iter()
		.filter(|mechanism| {
			enabled
				.iter()
				.any(|value| value.eq_ignore_ascii_case(mechanism))
		})
		.cloned()
		.collect()
}

pub fn append_security(output: &mut String, mechanisms: &[String]) {
	if !mechanisms.is_empty() {
		let _ = writeln!(output, "Security: {}", mechanisms.join(","));
	}
}
