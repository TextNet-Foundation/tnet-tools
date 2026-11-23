use crate::transport::framing::parse_content_length;
use crate::types::{
	FrameKind, IDLE_TIMEOUT, MAX_RESPONSE_BODY, MAX_RESPONSE_HEADER, MAX_UTNP_RESPONSE,
};
use anyhow::{Context, Result, anyhow, bail};
use std::time::Duration;
use tokio::io::{
	AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
	BufReader as TokioBufReader,
};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CHUNK: usize = 16 * 1024;

pub async fn exchange_tcp(
	host: &str,
	port: u16,
	request: &[u8],
	frame: FrameKind,
	connect_timeout: Duration,
) -> Result<Vec<u8>> {
	let mut stream = timeout(connect_timeout, TcpStream::connect((host, port)))
		.await
		.map_err(|_| anyhow!("Connection to {host}:{port} timed out"))?
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

			let response = read_until_eof(stream, MAX_UTNP_RESPONSE).await?;

			if response.is_empty() {
				bail!("UTNP server returned an empty response");
			}

			Ok(response)
		}
	}
}

/// Reads to EOF, refusing more than `limit` bytes and more than
/// `IDLE_TIMEOUT` of silence.
pub async fn read_until_eof<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>>
where
	R: AsyncRead + Unpin,
{
	let mut data = Vec::new();
	let mut chunk = [0u8; CHUNK];

	loop {
		let count = timeout(IDLE_TIMEOUT, reader.read(&mut chunk))
			.await
			.map_err(|_| anyhow!("Timed out waiting for the response"))??;

		if count == 0 {
			return Ok(data);
		}

		if data.len() + count > limit {
			bail!("Response exceeds the size limit");
		}

		data.extend_from_slice(&chunk[..count]);
	}
}

/// Reads exactly `length` bytes. The buffer grows with the data that really
/// arrives, so a lying Content-Length cannot force a huge allocation.
async fn read_body<R>(reader: &mut R, length: usize) -> Result<Vec<u8>>
where
	R: AsyncRead + Unpin,
{
	let mut body = Vec::new();
	let mut chunk = [0u8; CHUNK];

	while body.len() < length {
		let want = (length - body.len()).min(CHUNK);

		let count = timeout(IDLE_TIMEOUT, reader.read(&mut chunk[..want]))
			.await
			.map_err(|_| anyhow!("Timed out waiting for the response body"))??;

		if count == 0 {
			bail!("Connection closed before the response body was complete");
		}

		body.reserve(count);
		body.extend_from_slice(&chunk[..count]);
	}

	Ok(body)
}

async fn read_header_line<R>(reader: &mut R, header: &mut Vec<u8>) -> Result<bool>
where
	R: AsyncBufReadExt + Unpin,
{
	// The line may not push the header past the limit; one extra byte
	// lets the caller notice the overflow.
	let room = (MAX_RESPONSE_HEADER + 1).saturating_sub(header.len()) as u64;
	let start = header.len();

	let count = timeout(
		IDLE_TIMEOUT,
		(&mut *reader).take(room).read_until(b'\n', header),
	)
	.await
	.map_err(|_| anyhow!("Timed out waiting for response headers"))??;

	if count == 0 {
		bail!("Connection closed before response headers were complete");
	}

	if header.len() > MAX_RESPONSE_HEADER {
		bail!("Response headers exceed the size limit");
	}

	let line = &header[start..];

	Ok(line == b"\n" || line == b"\r\n")
}

async fn read_protocol_response<S>(stream: &mut S, head: bool) -> Result<Vec<u8>>
where
	S: AsyncRead + Unpin,
{
	let mut reader = TokioBufReader::new(stream);
	let mut header = Vec::new();

	while !read_header_line(&mut reader, &mut header).await? {}

	let content_length = parse_content_length(&header)?;

	if content_length > MAX_RESPONSE_BODY {
		bail!("Response body exceeds the size limit");
	}

	if !head && content_length > 0 {
		let body = read_body(&mut reader, content_length).await?;
		header.extend_from_slice(&body);
	}

	Ok(header)
}
