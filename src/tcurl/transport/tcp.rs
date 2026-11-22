use crate::transport::framing::parse_content_length;
use crate::types::{FrameKind, MAX_RESPONSE_BODY, MAX_RESPONSE_HEADER};
use anyhow::{Context, Result, bail};
use tokio::io::{
	AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
	BufReader as TokioBufReader,
};
use tokio::net::TcpStream;

pub async fn exchange_tcp(
	host: &str,
	port: u16,
	request: &[u8],
	frame: FrameKind,
) -> Result<Vec<u8>> {
	let mut stream = TcpStream::connect((host, port))
		.await
		.with_context(|| format!("Cannot connect to {host}:{port}"))?;

	stream.set_nodelay(true)?;

	send_and_receive(&mut stream, request, frame).await
}

pub async fn send_and_receive<S>(
	stream: &mut S,
	request: &[u8],
	frame: FrameKind,
) -> Result<Vec<u8>>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	stream.write_all(request).await?;
	stream.flush().await?;

	match frame {
		FrameKind::Protocol { head } => read_protocol_response(stream, head).await,

		FrameKind::Utnp => {
			// UTNP responses do not contain Content-Length.
			// Half-close tells the UTNP server that this request is complete.
			stream.shutdown().await?;

			let mut response = Vec::new();
			stream.read_to_end(&mut response).await?;

			if response.is_empty() {
				bail!("UTNP server returned an empty response");
			}

			Ok(response)
		}
	}
}

async fn read_protocol_response<S>(stream: &mut S, head: bool) -> Result<Vec<u8>>
where
	S: AsyncRead + Unpin,
{
	let mut reader = TokioBufReader::new(stream);
	let mut header = Vec::new();

	loop {
		let mut line = Vec::new();
		let count = reader.read_until(b'\n', &mut line).await?;

		if count == 0 {
			bail!("Connection closed before response headers were complete");
		}

		header.extend_from_slice(&line);

		if header.len() > MAX_RESPONSE_HEADER {
			bail!("Response headers exceed the size limit");
		}

		if line == b"\n" || line == b"\r\n" {
			break;
		}
	}

	let content_length = parse_content_length(&header)?;

	if content_length > MAX_RESPONSE_BODY {
		bail!("Response body exceeds the size limit");
	}

	let body_length = if head { 0 } else { content_length };

	let mut body = vec![0u8; body_length];
	if body_length > 0 {
		reader.read_exact(&mut body).await?;
	}

	header.extend_from_slice(&body);

	Ok(header)
}
