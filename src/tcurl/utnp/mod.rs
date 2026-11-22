use crate::args::Args;
use crate::transport::exchange_with_fallback;
use crate::types::{Endpoint, Target, TransportMode};
use anyhow::{Context, Result, anyhow, bail};

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
        format!("UTNP/1.0 NEGOTIATE {}\n", target.protocol.name())
    } else {
        format!(
            "UTNP/2.0 NEGOTIATE {}\nSupported-Versions: {}\n\n",
            target.protocol.name(),
            protocol_version
        )
    };

    // UTNP/1.0 is TCP-only. This does not force the later protocol
    // connection to TCP unless the global --v1 option was selected.
    let negotiation_mode = if utnp_v1 {
        TransportMode::TcpOnly
    } else {
        mode
    };

    let frame = crate::types::FrameKind::Utnp;

    let response = exchange_with_fallback(
        &target.host,
        utnp_port,
        request.as_bytes(),
        frame,
        negotiation_mode,
        args,
    )
    .await
    .context("UTNP negotiation failed")?;

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

    let host = parts[5].to_string();

    if host.is_empty() {
        bail!("UTNP returned an empty protocol host");
    }

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
