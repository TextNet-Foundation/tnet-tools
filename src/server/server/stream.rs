use crate::config::AppState;
use crate::protocol;
use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub async fn serve_utnp<S>(stream: S, state: AppState, secure_transport: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);

    // USTS is enforced before parsing or processing plaintext requests.
    if state.require_secure && !secure_transport {
        reader
            .get_mut()
            .write_all(b"UTNP/2.0 ERROR REQUIRE SECURE\n")
            .await?;

        reader.get_mut().flush().await?;

        // Gracefully close the transport.
        reader.get_mut().shutdown().await?;

        return Ok(());
    }

    loop {
        let mut first = String::new();
        let n = reader.read_line(&mut first).await?;

        if n == 0 {
            // Client finished sending requests.
            // For TLS this sends close_notify.
            reader.get_mut().shutdown().await?;
            return Ok(());
        }

        let first_line = first.trim_end_matches(['\r', '\n']);
        let legacy = first_line.starts_with("UTNP/1.0 ");

        let mut frame = first.into_bytes();

        if !legacy {
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;

                if n == 0 {
                    // Incomplete request frame.
                    reader.get_mut().shutdown().await?;
                    return Ok(());
                }

                let done = line == "\n" || line == "\r\n";

                frame.extend_from_slice(line.as_bytes());

                if done {
                    break;
                }
            }
        }

        let response = protocol::process_request(&frame, &state);

        reader.get_mut().write_all(&response).await?;
        reader.get_mut().flush().await?;
    }
}

// Alias matching target naming.
pub async fn serve_stream<S>(stream: S, state: AppState, secure_transport: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve_utnp(stream, state, secure_transport).await
}
