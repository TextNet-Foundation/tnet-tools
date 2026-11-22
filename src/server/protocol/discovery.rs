use crate::config::{ExploreNode, Protocol};
use std::fmt::Write;

use crate::protocol::{
    append_security, default_protocol_version, enabled_security_for_protocol, error_response,
    version_rank,
};

pub fn available_v1(protocols: &[Protocol]) -> Vec<u8> {
    let mut output = String::from("UTNP/1.0 AVAILABLE\n");

    for protocol in protocols {
        for version in &protocol.version {
            let _ = writeln!(
                output,
                "{} {} {} {}",
                protocol.name, version, protocol.host, protocol.port
            );
        }
    }

    output.into_bytes()
}

pub fn available_v2(protocols: &[Protocol], enabled: &[String]) -> Vec<u8> {
    let mut output = String::from("UTNP/2.0 AVAILABLE\n");

    for protocol in protocols {
        for version in &protocol.version {
            let _ = writeln!(
                output,
                "{} {} {} {}",
                protocol.name, version, protocol.host, protocol.port
            );

            append_security(
                &mut output,
                &enabled_security_for_protocol(&protocol.security, enabled),
            );
        }
    }

    output.into_bytes()
}

pub fn negotiate_v1(requested: &str, protocols: &[Protocol]) -> Vec<u8> {
    for name in requested.split(',').map(str::trim) {
        if let Some(protocol) = protocols.iter().find(|protocol| protocol.name == name) {
            let mut output = String::with_capacity(64);
            let _ = writeln!(
                output,
                "UTNP/1.0 START PROTOCOL {} {} {} {}",
                protocol.name,
                default_protocol_version(protocol),
                protocol.host,
                protocol.port
            );
            return output.into_bytes();
        }
    }

    let mut output = String::from("UTNP/1.0 ERROR Unsupported protocol\n");

    output.push_str(&String::from_utf8_lossy(&available_v1(protocols)));

    output.into_bytes()
}

pub fn negotiate_v2(
    requested: &str,
    client_versions: Option<&str>,
    protocols: &[Protocol],
    enabled: &[String],
) -> Vec<u8> {
    if requested.is_empty() || requested.contains(',') {
        return error_response("2.0", "Invalid request");
    }

    let Some(protocol) = protocols.iter().find(|protocol| protocol.name == requested) else {
        let mut output = b"UTNP/2.0 ERROR Unsupported protocol\n".to_vec();

        output.extend_from_slice(&available_v2(protocols, enabled));

        return output;
    };

    let selected_version = match client_versions {
        // No Supported-Versions header: use the configured default.
        None => default_protocol_version(protocol),

        // Explicit version negotiation.
        Some(client_versions) => {
            if client_versions.trim().is_empty() {
                return error_response("2.0", "Invalid request");
            }

            let client: Vec<&str> = client_versions
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect();

            if client.is_empty() {
                return error_response("2.0", "Invalid request");
            }

            let selected = protocol
                .version
                .iter()
                .filter(|version| client.contains(&version.as_str()))
                .max_by_key(|version| version_rank(version));

            let Some(selected) = selected else {
                return error_response("2.0", "Unsupported protocol version");
            };

            selected.as_str()
        }
    };

    let mut output = String::with_capacity(64);
    let _ = writeln!(
        output,
        "UTNP/2.0 START PROTOCOL {} {} {} {}",
        protocol.name, selected_version, protocol.host, protocol.port
    );

    append_security(
        &mut output,
        &enabled_security_for_protocol(&protocol.security, enabled),
    );

    output.into_bytes()
}

pub fn explore_response(nodes: &[ExploreNode]) -> Vec<u8> {
    let mut output = String::from("UTNP/2.0 EXPLORE AVAILABLE\n");

    for node in nodes {
        let _ = writeln!(
            output,
            "utnp {} {} {}",
            node.version, node.host, node.description
        );
    }

    output.into_bytes()
}
