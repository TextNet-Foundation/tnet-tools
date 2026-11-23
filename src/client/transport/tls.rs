use anyhow::anyhow;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};

pub enum TlsAttemptError {
	Unavailable(String),
	Fatal(anyhow::Error),
}

pub async fn exchange_tls(
	host: &str,
	port: u16,
	request: &str,
	ca_cert: Option<&Path>,
	verify_for_sni: Option<&str>,
	policy: super::Policy,
) -> std::result::Result<Vec<u8>, TlsAttemptError> {
	// Системные корневые сертификаты: парсятся один раз на процесс.
	let native_roots = super::native_roots::native_root_store()
		.map_err(|message| anyhow!(message))
		.map_err(TlsAttemptError::Fatal)?;

	// Дополнительный CA пользователя добавляется поверх копии общего store.
	let roots = match ca_cert {
		None => native_roots,
		Some(path) => {
			let bytes = fs::read(path)
				.await
				.map_err(anyhow::Error::from)
				.map_err(TlsAttemptError::Fatal)?;

			let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
				.collect::<std::result::Result<_, _>>()
				.map_err(anyhow::Error::from)
				.map_err(TlsAttemptError::Fatal)?;

			if certificates.is_empty() {
				return Err(TlsAttemptError::Fatal(anyhow!(
					"CA certificate file contains no certificates"
				)));
			}

			let mut roots = (*native_roots).clone();

			for certificate in certificates {
				roots
					.add(certificate)
					.map_err(anyhow::Error::from)
					.map_err(TlsAttemptError::Fatal)?;
			}

			Arc::new(roots)
		}
	};

	if roots.is_empty() {
		return Err(TlsAttemptError::Fatal(anyhow!(
			"No trusted CA certificates found in the system store or --ca-cert"
		)));
	}

	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();

	let connector = TlsConnector::from(Arc::new(config));

	let stream = match timeout(policy.connect_timeout, TcpStream::connect((host, port))).await {
		Ok(Ok(stream)) => stream,
		Ok(Err(error)) => {
			return Err(classify_io_error(
				&error,
				policy.allow_insecure,
				"TLS connect",
			));
		}
		Err(_) => {
			return Err(classify_io_error(
				&std::io::Error::from(std::io::ErrorKind::TimedOut),
				policy.allow_insecure,
				"TLS connect timed out",
			));
		}
	};

	stream
		.set_nodelay(true)
		.map_err(anyhow::Error::from)
		.map_err(TlsAttemptError::Fatal)?;

	let tls_name = verify_for_sni.unwrap_or(host);

	let server_name = ServerName::try_from(tls_name.to_string())
		.map_err(anyhow::Error::from)
		.map_err(TlsAttemptError::Fatal)?;

	let mut tls_stream = match timeout(
		policy.connect_timeout,
		connector.connect(server_name, stream),
	)
	.await
	{
		Ok(Ok(stream)) => stream,

		Ok(Err(error)) => {
			// Certificate errors never turn into a silent plaintext fallback.
			return Err(classify_io_error(
				&error,
				policy.allow_insecure,
				"TLS handshake failed",
			));
		}

		Err(_) => {
			return Err(classify_io_error(
				&std::io::Error::from(std::io::ErrorKind::TimedOut),
				policy.allow_insecure,
				"TLS handshake timed out",
			));
		}
	};

	super::send_request(&mut tls_stream, request)
		.await
		.map_err(TlsAttemptError::Fatal)
}

/// Classifies a failure to reach a secure (TLS) peer.
///
/// - `ConnectionRefused`: nothing listens on the port, so the service does not
///   offer TLS here; always `Unavailable`.
/// - `UnexpectedEof`, `ConnectionReset`, `ConnectionAborted`, `BrokenPipe`,
///   `TimedOut` and rustls "not a TLS peer" messages are ambiguous: a plaintext
///   service looks the same as an attacker cutting the handshake. They are
///   `Unavailable` (plaintext fallback possible) only with the explicit
///   --allow-insecure-fallback; otherwise `Fatal`.
/// - Everything else (certificate errors, ...) is always `Fatal`.
pub(super) fn classify_io_error(
	error: &std::io::Error,
	allow_insecure: bool,
	context: &str,
) -> TlsAttemptError {
	use std::io::ErrorKind;

	if error.kind() == ErrorKind::ConnectionRefused {
		return TlsAttemptError::Unavailable(error.to_string());
	}

	let not_tls = matches!(
		error
			.get_ref()
			.and_then(|inner| inner.downcast_ref::<tokio_rustls::rustls::Error>()),
		Some(
			tokio_rustls::rustls::Error::InvalidMessage(_)
				| tokio_rustls::rustls::Error::InappropriateMessage { .. }
				| tokio_rustls::rustls::Error::InappropriateHandshakeMessage { .. }
		)
	);

	let ambiguous = not_tls
		|| matches!(
			error.kind(),
			ErrorKind::UnexpectedEof
				| ErrorKind::ConnectionReset
				| ErrorKind::ConnectionAborted
				| ErrorKind::BrokenPipe
				| ErrorKind::TimedOut
		);

	if ambiguous && allow_insecure {
		return TlsAttemptError::Unavailable(error.to_string());
	}

	if ambiguous {
		return TlsAttemptError::Fatal(anyhow!("{}: {context}: {error}", super::SECURE_FAILED));
	}

	TlsAttemptError::Fatal(anyhow!("{context}: {error}"))
}
