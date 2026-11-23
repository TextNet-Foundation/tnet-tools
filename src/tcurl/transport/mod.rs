pub mod framing;
mod native_roots;
mod ssh;
mod tcp;
mod tls;

pub use framing::response_header_end;
pub use ssh::exchange_ssh;
pub use tcp::exchange_tcp;
pub use tls::exchange_tls;

use crate::args::Args;
use crate::types::{
	AttemptError, Exchanged, FrameKind, Policy, SECURE_FAILED, SshAttemptError, Transport,
	TransportMode,
};
use anyhow::Context;
use std::time::Duration;

pub fn policy_from_args(args: &Args) -> Policy {
	Policy {
		allow_insecure: args.allow_insecure_fallback,
		connect_timeout: Duration::from_secs(args.timeout.max(1)),
	}
}

/// Decides whether the transport may drop to plaintext TCP after the secure
/// attempts were unavailable. Plaintext that was selected explicitly
/// (`TcpOnly`) never reaches this check with a reason.
pub fn plaintext_fallback_allowed(
	mode: TransportMode,
	allow_insecure: bool,
	reason: &str,
) -> anyhow::Result<()> {
	if matches!(mode, TransportMode::TcpOnly) || allow_insecure {
		return Ok(());
	}

	anyhow::bail!("{SECURE_FAILED} ({reason})")
}

pub async fn exchange_with_fallback(
	host: &str,
	port: u16,
	request: &[u8],
	frame: FrameKind,
	mode: TransportMode,
	args: &Args,
) -> anyhow::Result<Exchanged> {
	let policy = policy_from_args(args);
	#[allow(unused_assignments)]
	let mut reason = String::from("no secure transport was attempted");

	if matches!(mode, TransportMode::SshThenTlsThenTcp) {
		eprintln!("Trying SSH...");

		match exchange_ssh(host, port, request, frame, policy).await {
			Ok(data) => {
				eprintln!("Transport: SSH");
				return Ok(Exchanged {
					data,
					transport: Transport::Ssh,
				});
			}

			Err(SshAttemptError::Untrusted(message)) => {
				anyhow::bail!("SSH host key is not trusted; refusing fallback: {message}");
			}

			Err(SshAttemptError::Failed(error)) => {
				return Err(error);
			}

			Err(SshAttemptError::Unavailable(message)) => {
				eprintln!("SSH unavailable: {message}");
			}
		}
	}

	if !matches!(mode, TransportMode::TcpOnly) {
		eprintln!("Trying TLS...");

		match exchange_tls(
			host,
			port,
			request,
			frame,
			args.ca_cert.as_deref(),
			args.verify_for_sni.as_deref(),
			policy,
		)
		.await
		{
			Ok(data) => {
				eprintln!("Transport: TLS");
				return Ok(Exchanged {
					data,
					transport: Transport::Tls,
				});
			}

			Err(AttemptError::Fatal(error)) => {
				return Err(error);
			}

			Err(AttemptError::Unavailable(message)) => {
				eprintln!("TLS unavailable: {message}");
				reason = format!("TLS: {message}");
			}
		}
	}

	plaintext_fallback_allowed(mode, policy.allow_insecure, &reason)?;

	if !matches!(mode, TransportMode::TcpOnly) {
		eprintln!("WARN: falling back to INSECURE plaintext TCP (--allow-insecure-fallback)");
	}

	eprintln!("Using TCP");

	let data = exchange_tcp(host, port, request, frame, policy.connect_timeout)
		.await
		.with_context(|| format!("Cannot connect to {host}:{port} using TCP"))?;

	Ok(Exchanged {
		data,
		transport: Transport::Tcp,
	})
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
