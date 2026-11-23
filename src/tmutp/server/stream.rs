use crate::common::conn::{read_idle, write_response};
use crate::common::frame::{DEFAULT_MAX_BODY, Frame, FrameParser};
use crate::config::*;
use crate::handler::{make_error_response, process_request};
use anyhow::Result;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

async fn respond(request: &[u8], state: &AppState, secure_transport: bool) -> Vec<u8> {
	if state.require_secure && !secure_transport {
		return make_error_response(
			REQUIRE_SECURE,
			"55 Require secure",
			"This server requires an encrypted transport",
		);
	}

	process_request(request, state).await
}

pub async fn serve_stream<S>(mut stream: S, state: AppState, secure_transport: bool) -> Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut buffer: Vec<u8> = Vec::new();
	let mut parser = FrameParser::new(DEFAULT_MAX_BODY);
	let mut chunk = [0u8; 16 * 1024];

	loop {
		// Сначала обрабатываем все готовые запросы, и только потом читаем: буфер
		// не растёт сверх одного кадра плюс один кусок чтения.
		loop {
			match parser.poll(&buffer) {
				Frame::Complete(length) => {
					let request: Vec<u8> = buffer.drain(..length).collect();
					parser.reset();

					let response = respond(&request, &state, secure_transport).await;
					write_response(&mut stream, &response).await?;
				}
				Frame::Incomplete => break,
				Frame::Invalid(error) => {
					let response =
						make_error_response(BAD_REQUEST, "30 Bad request", error.message());

					write_response(&mut stream, &response).await?;
					let _ = stream.shutdown().await;
					return Ok(());
				}
			}
		}

		match read_idle(&mut stream, &mut chunk, parser.idle_timeout()).await {
			Ok(0) => {
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
