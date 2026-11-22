use crate::config::*;
use crate::handler::{make_error_response, process_request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn serve_stream<S>(
	mut stream: S,
	state: AppState,
	secure_transport: bool,
) -> anyhow::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	loop {
		let mut buffer = Vec::new();
		let mut chunk = [0u8; 4096];

		loop {
			let n = stream.read(&mut chunk).await?;

			if n == 0 {
				stream.shutdown().await?;
				return Ok(());
			}

			buffer.extend_from_slice(&chunk[..n]);

			if buffer.len() > 16 * 1024 * 1024 {
				let response = make_error_response(
					BAD_REQUEST,
					"30 Bad request",
					"The request exceeds the server limit",
				);

				stream.write_all(&response).await?;
				stream.flush().await?;
				stream.shutdown().await?;
				return Ok(());
			}

			if let Some(frame_len) = crate::server::complete_request_len(&buffer)
				&& buffer.len() >= frame_len
			{
				let request: Vec<u8> = buffer.drain(..frame_len).collect();

				let response = if state.require_secure && !secure_transport {
					make_error_response(
						REQUIRE_SECURE,
						"55 Require secure",
						"This server requires an encrypted transport",
					)
				} else {
					process_request(&request, &state).await
				};

				stream.write_all(&response).await?;
				stream.flush().await?;

				if !buffer.is_empty() {
					let mut pending = buffer;

					loop {
						if let Some(frame_len) = crate::server::complete_request_len(&pending)
							&& pending.len() >= frame_len
						{
							let request: Vec<u8> = pending.drain(..frame_len).collect();

							let response = if state.require_secure && !secure_transport {
								make_error_response(
									REQUIRE_SECURE,
									"55 Require secure",
									"This server requires an encrypted transport",
								)
							} else {
								process_request(&request, &state).await
							};

							stream.write_all(&response).await?;
							stream.flush().await?;
							continue;
						}

						let n = stream.read(&mut chunk).await?;
						if n == 0 {
							stream.shutdown().await?;
							return Ok(());
						}

						pending.extend_from_slice(&chunk[..n]);

						if pending.len() > 16 * 1024 * 1024 {
							stream.shutdown().await?;
							return Ok(());
						}
					}
				}

				break;
			}
		}
	}
}
