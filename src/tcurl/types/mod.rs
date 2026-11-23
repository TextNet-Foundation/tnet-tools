use std::io;
use std::time::Duration;
use tokio_rustls::rustls;

pub const MAX_RESPONSE_HEADER: usize = 64 * 1024;
pub const MAX_RESPONSE_BODY: usize = 256 * 1024 * 1024;
/// UTNP answers are short lists of services; 1 MiB is far more than needed.
pub const MAX_UTNP_RESPONSE: usize = 1024 * 1024;
/// Maximum silence between two chunks of a response.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Shown whenever a secure channel cannot be set up and plaintext is not allowed.
pub const SECURE_FAILED: &str = "не удалось установить защищённое соединение; \
--allow-insecure-fallback чтобы разрешить plaintext";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
	Tmutp,
	Tbip,
}

impl Protocol {
	pub fn name(self) -> &'static str {
		match self {
			Self::Tmutp => "tmutp",
			Self::Tbip => "tbip",
		}
	}

	pub fn version(self, v1: bool) -> &'static str {
		match (self, v1) {
			(Self::Tmutp, true) => "TMUTP/1.0",
			(Self::Tmutp, false) => "TMUTP/2.0",
			(Self::Tbip, true) => "TBIP/1.0",
			(Self::Tbip, false) => "TBIP/2.0",
		}
	}

	pub fn version_number(v1: bool) -> &'static str {
		if v1 { "1.0" } else { "2.0" }
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
	Get,
	Post,
	Head,
}

impl Method {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Get => "GET",
			Self::Post => "POST",
			Self::Head => "HEAD",
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub enum TransportMode {
	TlsThenTcp,
	SshThenTlsThenTcp,
	TcpOnly,
}

#[derive(Debug, Clone, Copy)]
pub enum TransportTarget {
	Utnp,
	Tmutp,
	Tbip,
}

#[derive(Debug, Clone, Copy)]
pub enum FrameKind {
	Protocol { head: bool },
	Utnp,
}

#[derive(Debug)]
pub struct Target {
	pub protocol: Protocol,
	pub host: String,
	pub path_query: String,
	pub direct_port: Option<u16>,
	pub utnp_port: Option<u16>,
}

#[derive(Debug)]
pub struct Endpoint {
	pub host: String,
	pub port: u16,
}

#[derive(Debug)]
pub enum AttemptError {
	Unavailable(String),
	Fatal(anyhow::Error),
}

#[derive(Debug)]
pub enum SshAttemptError {
	Unavailable(String),
	Untrusted(String),
	Failed(anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
	Ssh,
	Tls,
	Tcp,
}

impl Transport {
	pub fn is_secure(self) -> bool {
		!matches!(self, Self::Tcp)
	}
}

#[derive(Debug)]
pub struct Exchanged {
	pub data: Vec<u8>,
	pub transport: Transport,
}

#[derive(Debug, Clone, Copy)]
pub struct Policy {
	pub allow_insecure: bool,
	pub connect_timeout: Duration,
}

/// Classifies a failure to reach a secure (TLS) peer.
///
/// - `ConnectionRefused`: nothing listens on the port, so the service does not
///   offer TLS here; it is always `Unavailable`.
/// - `UnexpectedEof`, `ConnectionReset`, `ConnectionAborted`, `BrokenPipe`,
///   `TimedOut` and rustls "not a TLS peer" messages are ambiguous: a plaintext
///   service looks the same as an active attacker cutting the handshake. They
///   are `Unavailable` (plaintext fallback possible) only with the explicit
///   `--allow-insecure-fallback`; otherwise `Fatal`.
/// - Everything else (certificate errors, ...) is always `Fatal`.
pub fn classify_io_error(error: &io::Error, allow_insecure: bool, context: &str) -> AttemptError {
	if error.kind() == io::ErrorKind::ConnectionRefused {
		return AttemptError::Unavailable(error.to_string());
	}

	let ambiguous = matches!(
		error.kind(),
		io::ErrorKind::UnexpectedEof
			| io::ErrorKind::ConnectionReset
			| io::ErrorKind::ConnectionAborted
			| io::ErrorKind::BrokenPipe
			| io::ErrorKind::TimedOut
	) || is_not_tls_peer(error);

	if ambiguous && allow_insecure {
		return AttemptError::Unavailable(error.to_string());
	}

	if ambiguous {
		return AttemptError::Fatal(anyhow::anyhow!("{SECURE_FAILED}: {context}: {error}"));
	}

	AttemptError::Fatal(anyhow::anyhow!("{context}: {error}"))
}

fn is_not_tls_peer(error: &io::Error) -> bool {
	matches!(
		error
			.get_ref()
			.and_then(|inner| inner.downcast_ref::<rustls::Error>()),
		Some(
			rustls::Error::InvalidMessage(_)
				| rustls::Error::InappropriateMessage { .. }
				| rustls::Error::InappropriateHandshakeMessage { .. }
		)
	)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
