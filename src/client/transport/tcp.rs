use anyhow::{Context, Result, anyhow};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn exchange_tcp(
	host: &str,
	port: u16,
	request: &str,
	connect_timeout: Duration,
) -> Result<Vec<u8>> {
	let mut stream = timeout(connect_timeout, TcpStream::connect((host, port)))
		.await
		.map_err(|_| anyhow!("Connection to {host}:{port} timed out"))?
		.with_context(|| format!("Cannot connect to {host}:{port}"))?;

	stream.set_nodelay(true)?;

	super::send_request(&mut stream, request).await
}
