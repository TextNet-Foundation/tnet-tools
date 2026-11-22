use crate::config::{AppState, BAD_REQUEST, REQUIRE_SECURE};
use crate::handler::request::process_request;
use crate::handler::response::make_error_response;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn serve_stream<S>(mut stream: S, state: AppState, secure_transport: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        while let Some(frame_len) = complete_request_len(&buffer) {
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
        }

        if buffer.len() > 16 * 1024 * 1024 {
            let response = make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Request exceeds the server limit",
            );

            stream.write_all(&response).await?;
            stream.flush().await?;
            stream.shutdown().await?;
            return Ok(());
        }

        let n = stream.read(&mut chunk).await?;

        if n == 0 {
            stream.shutdown().await?;
            return Ok(());
        }

        buffer.extend_from_slice(&chunk[..n]);
    }
}

pub fn complete_request_len(buffer: &[u8]) -> Option<usize> {
    if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(position + 4);
    }

    buffer
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|position| position + 2)
}
