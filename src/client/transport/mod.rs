use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod ssh;
mod tcp;
mod tls;

pub use ssh::exchange_ssh;
pub use tcp::exchange_tcp;
pub use tls::exchange_tls;

pub use ssh::SshAttemptError;
pub use tls::TlsAttemptError;

pub async fn exchange_v2(args: &crate::cli::Args, request: &str) -> Result<Vec<u8>> {
	if args.ssh {
		println!("Transport: SSH");

		match exchange_ssh(&args.host, args.port, request).await {
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
	)
	.await
	{
		Ok(response) => return Ok(response),

		Err(TlsAttemptError::Fatal(error)) => {
			return Err(error);
		}

		Err(TlsAttemptError::Unavailable(message)) => {
			eprintln!("TLS unavailable: {message}");
			eprintln!("Falling back to plain TCP...");
		}
	}

	println!("Transport: TCP (fallback)");

	exchange_tcp(&args.host, args.port, request).await
}

pub async fn send_request<S>(stream: &mut S, request: &str) -> Result<Vec<u8>>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	stream.write_all(request.as_bytes()).await?;
	stream.flush().await?;

	// Один запрос на соединение.
	stream.shutdown().await?;

	let mut response = Vec::new();
	stream.read_to_end(&mut response).await?;

	if response.is_empty() {
		bail!("UTNP server returned an empty response");
	}

	Ok(response)
}
