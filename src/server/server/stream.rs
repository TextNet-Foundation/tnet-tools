use crate::config::AppState;
use crate::conn::{read_idle, write_response};
use crate::protocol::{self, FrameStatus, Framer};
use anyhow::Result;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Допустимый простой чтения запроса.
const REQUEST_IDLE: Duration = Duration::from_secs(15);

pub async fn serve_utnp<S>(mut stream: S, state: AppState, secure_transport: bool) -> Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	// USTS is enforced before parsing or processing plaintext requests.
	if state.require_secure && !secure_transport {
		write_response(&mut stream, b"UTNP/2.0 ERROR REQUIRE SECURE\n").await?;

		// Gracefully close the transport.
		stream.shutdown().await?;

		return Ok(());
	}

	let mut buffer: Vec<u8> = Vec::new();
	let mut framer = Framer::new();
	let mut chunk = [0u8; 4096];

	loop {
		loop {
			match framer.poll(&buffer) {
				FrameStatus::Complete(length) => {
					let frame: Vec<u8> = buffer.drain(..length).collect();
					framer.reset();

					let response = protocol::process_request(&frame, &state);
					write_response(&mut stream, &response).await?;
				}
				FrameStatus::Incomplete => break,
				FrameStatus::Invalid(reason) => {
					tracing::debug!(reason, "rejecting malformed request");

					let response = protocol::error_response("2.0", reason);
					write_response(&mut stream, &response).await?;
					let _ = stream.shutdown().await;

					return Ok(());
				}
			}
		}

		match read_idle(&mut stream, &mut chunk, REQUEST_IDLE).await {
			Ok(0) => {
				// Client finished sending requests (an incomplete frame is dropped).
				// For TLS this sends close_notify.
				stream.shutdown().await?;
				return Ok(());
			}
			Ok(n) => buffer.extend_from_slice(&chunk[..n]),
			Err(error) if error.kind() == ErrorKind::TimedOut && buffer.is_empty() => {
				let _ = stream.shutdown().await;
				return Ok(());
			}
			Err(error) => return Err(error.into()),
		}
	}
}

// Alias matching target naming.
pub async fn serve_stream<S>(stream: S, state: AppState, secure_transport: bool) -> Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	serve_utnp(stream, state, secure_transport).await
}
