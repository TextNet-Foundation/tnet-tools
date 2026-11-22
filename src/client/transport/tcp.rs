use anyhow::{Context, Result};
use tokio::net::TcpStream;

pub async fn exchange_tcp(host: &str, port: u16, request: &str) -> Result<Vec<u8>> {
	let mut stream = TcpStream::connect((host, port))
		.await
		.with_context(|| format!("Cannot connect to {host}:{port}"))?;

	stream.set_nodelay(true)?;

	super::send_request(&mut stream, request).await
}
