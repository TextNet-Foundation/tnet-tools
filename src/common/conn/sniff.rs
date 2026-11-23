use anyhow::{Context, Result};
#[cfg(test)]
use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::net::TcpStream;

/// Общий таймаут определения транспорта.
pub const SNIFF_TIMEOUT: Duration = Duration::from_secs(10);

const BACKOFF_START: Duration = Duration::from_millis(5);
const BACKOFF_MAX: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
	Tls,
	Ssh,
	Plain,
}

/// Определяет транспорт по началу потока; `None` — данных пока не хватает.
pub fn classify(prefix: &[u8]) -> Option<Transport> {
	match prefix.first() {
		None => None,
		Some(0x16) => match prefix.get(1) {
			None => None,
			Some(0x03) => Some(Transport::Tls),
			Some(_) => Some(Transport::Plain),
		},
		Some(b'S') => {
			let n = prefix.len().min(4);

			if prefix[..n] != b"SSH-"[..n] {
				Some(Transport::Plain)
			} else if n < 4 {
				None
			} else {
				Some(Transport::Ssh)
			}
		}
		Some(_) => Some(Transport::Plain),
	}
}

pub async fn sniff_transport(stream: &TcpStream) -> Result<Transport> {
	let detect = async {
		let mut backoff = BACKOFF_START;

		loop {
			let mut buf = [0u8; 64];
			let n = stream.peek(&mut buf).await?;

			if n == 0 {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"client closed before sending data",
				));
			}

			if let Some(transport) = classify(&buf[..n]) {
				return Ok(transport);
			}

			tokio::time::sleep(backoff).await;
			backoff = (backoff * 2).min(BACKOFF_MAX);
		}
	};

	tokio::time::timeout(SNIFF_TIMEOUT, detect)
		.await
		.context("timed out while identifying connection transport")?
		.context("cannot identify connection transport")
}

/// `peek` возвращает сразу всё, что уже пришло, поэтому при нехватке данных нельзя
/// сразу вызывать его снова (busy-spin): между попытками идёт растущая пауза.
#[cfg(test)]
pub async fn sniff_with<F, Fut>(limit: Duration, mut peek: F) -> Result<Transport>
where
	F: FnMut(&mut [u8]) -> Fut,
	Fut: Future<Output = io::Result<usize>>,
{
	let detect = async {
		let mut backoff = BACKOFF_START;

		loop {
			let mut buf = [0u8; 64];
			let n = peek(&mut buf).await?;

			if n == 0 {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"client closed before sending data",
				));
			}

			if let Some(transport) = classify(&buf[..n]) {
				return Ok(transport);
			}

			tokio::time::sleep(backoff).await;
			backoff = (backoff * 2).min(BACKOFF_MAX);
		}
	};

	tokio::time::timeout(limit, detect)
		.await
		.context("timed out while identifying connection transport")?
		.context("cannot identify connection transport")
}

#[cfg(test)]
#[path = "tests/sniff_tests.rs"]
mod tests;
