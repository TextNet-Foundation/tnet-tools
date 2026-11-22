pub mod framing;
mod ssh;
mod tcp;
mod tls;

pub use framing::response_header_end;
pub use ssh::exchange_ssh;
pub use tcp::exchange_tcp;
pub use tls::exchange_tls;

use crate::args::Args;
use crate::types::{AttemptError, FrameKind, SshAttemptError, TransportMode};
use anyhow::Context;

pub async fn exchange_with_fallback(
	host: &str,
	port: u16,
	request: &[u8],
	frame: FrameKind,
	mode: TransportMode,
	args: &Args,
) -> anyhow::Result<Vec<u8>> {
	if matches!(mode, TransportMode::SshThenTlsThenTcp) {
		eprintln!("Trying SSH...");

		match exchange_ssh(host, port, request, frame).await {
			Ok(response) => {
				eprintln!("Transport: SSH");
				return Ok(response);
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
		)
		.await
		{
			Ok(response) => {
				eprintln!("Transport: TLS");
				return Ok(response);
			}

			Err(AttemptError::Fatal(error)) => {
				return Err(error);
			}

			Err(AttemptError::Unavailable(message)) => {
				eprintln!("TLS unavailable: {message}");
			}
		}
	}

	eprintln!("Using TCP");

	exchange_tcp(host, port, request, frame)
		.await
		.with_context(|| format!("Cannot connect to {host}:{port} using TCP"))
}
