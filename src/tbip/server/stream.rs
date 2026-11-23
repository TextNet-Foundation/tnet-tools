use crate::common::conn::{read_idle, write_response};
use crate::common::frame::{Frame, FrameParser};
use crate::config::{AppState, BAD_REQUEST, REQUIRE_SECURE};
use crate::handler::request::process_request;
use crate::handler::response::make_error_response;
use anyhow::Result;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// TBIP-запросы не несут тела: любой ненулевой Content-Length отклоняется.
pub const MAX_REQUEST_BODY: usize = 0;

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
	let mut parser = FrameParser::new(MAX_REQUEST_BODY);
	let mut chunk = [0u8; 8192];

	loop {
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
