use anyhow::{Result, anyhow, bail};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

mod ssh;
mod tcp;
mod tls;

pub use ssh::exchange_ssh;
pub use tcp::exchange_tcp;
pub use tls::exchange_tls;

pub use ssh::SshAttemptError;
pub use tls::TlsAttemptError;

/// UTNP answers are short lists of services; 1 MiB is far more than needed.
pub const MAX_UTNP_RESPONSE: usize = 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Shown whenever a secure channel cannot be set up and plaintext is not allowed.
pub const SECURE_FAILED: &str = "не удалось установить защищённое соединение; \
--allow-insecure-fallback чтобы разрешить plaintext";

#[derive(Debug, Clone, Copy)]
pub struct Policy {
	pub allow_insecure: bool,
	pub connect_timeout: Duration,
}

pub fn policy_from_args(args: &crate::cli::Args) -> Policy {
	Policy {
		allow_insecure: args.allow_insecure_fallback,
		connect_timeout: Duration::from_secs(args.timeout.max(1)),
	}
}

/// Plaintext after failed secure attempts needs the explicit flag.
pub fn plaintext_fallback_allowed(allow_insecure: bool, reason: &str) -> Result<()> {
	if allow_insecure {
		return Ok(());
	}

	bail!("{SECURE_FAILED} ({reason})")
}

pub async fn exchange_v2(args: &crate::cli::Args, request: &str) -> Result<Vec<u8>> {
	let policy = policy_from_args(args);
	#[allow(unused_assignments)]
	let mut reason = String::from("TLS");

	if args.ssh {
		println!("Transport: SSH");

		match exchange_ssh(&args.host, args.port, request, policy).await {
			Ok(response) => return Ok(response),

			Err(SshAttemptError::Untrusted(message)) => {
				bail!(
					"SSH host key verification failed. \
                     Refusing fallback: {message}"
				);
			}

			Err(SshAttemptError::Failed(error)) => {
				return Err(error);
			}

			Err(SshAttemptError::Unavailable(message)) => {
				eprintln!("SSH unavailable: {message}");
				eprintln!("Falling back to TLS...");
			}
		}
	}

	println!("Transport: TLS");

	match exchange_tls(
		&args.host,
		args.port,
		request,
		args.ca_cert.as_deref(),
		args.verify_for_sni.as_deref(),
		policy,
	)
	.await
	{
		Ok(response) => return Ok(response),

		Err(TlsAttemptError::Fatal(error)) => {
			return Err(error);
		}

		Err(TlsAttemptError::Unavailable(message)) => {
			eprintln!("TLS unavailable: {message}");
			reason = format!("TLS: {message}");
		}
	}

	plaintext_fallback_allowed(policy.allow_insecure, &reason)?;

	eprintln!("WARN: falling back to INSECURE plaintext TCP (--allow-insecure-fallback)");
	println!("Transport: TCP (fallback)");

	exchange_tcp(&args.host, args.port, request, policy.connect_timeout).await
}

pub async fn send_request<S>(stream: &mut S, request: &str) -> Result<Vec<u8>>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	stream.write_all(request.as_bytes()).await?;
	stream.flush().await?;

	// Один запрос на соединение.
	stream.shutdown().await?;

	let response = read_until_eof(stream, MAX_UTNP_RESPONSE).await?;

	if response.is_empty() {
		bail!("UTNP server returned an empty response");
	}

	Ok(response)
}

/// Reads to EOF, refusing more than `limit` bytes and more than
/// `IDLE_TIMEOUT` of silence.
pub async fn read_until_eof<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>>
where
	R: AsyncRead + Unpin,
{
	let mut data = Vec::new();
	let mut chunk = [0u8; 16 * 1024];

	loop {
		let count = timeout(IDLE_TIMEOUT, reader.read(&mut chunk))
			.await
			.map_err(|_| anyhow!("Timed out waiting for the UTNP response"))??;

		if count == 0 {
			return Ok(data);
		}

		if data.len() + count > limit {
			bail!("UTNP response exceeds the size limit");
		}

		data.extend_from_slice(&chunk[..count]);
	}
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
