use crate::transport::tcp::send_and_receive;
use crate::types::{AttemptError, FrameKind, Policy, classify_io_error};
use anyhow::anyhow;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

pub async fn exchange_tls(
	host: &str,
	port: u16,
	request: &[u8],
	frame: FrameKind,
	ca_cert: Option<&Path>,
	verify_for_sni: Option<&str>,
	policy: Policy,
) -> std::result::Result<Vec<u8>, AttemptError> {
	let mut roots = RootCertStore::empty();

	let native_certs = rustls_native_certs::load_native_certs();

	for error in &native_certs.errors {
		tracing::warn!(error = %error, "cannot load system CA certificate");
	}

	for cert in native_certs.certs {
		roots
			.add(cert)
			.map_err(anyhow::Error::from)
			.map_err(AttemptError::Fatal)?;
	}

	if let Some(path) = ca_cert {
		let bytes = fs::read(path)
			.await
			.map_err(anyhow::Error::from)
			.map_err(AttemptError::Fatal)?;

		let mut reader = Cursor::new(bytes);

		let certificates: Vec<_> = rustls_pemfile::certs(&mut reader)
			.collect::<std::result::Result<_, _>>()
			.map_err(anyhow::Error::from)
			.map_err(AttemptError::Fatal)?;

		if certificates.is_empty() {
			return Err(AttemptError::Fatal(anyhow!(
				"CA certificate file contains no certificates"
			)));
		}

		for certificate in certificates {
			roots
				.add(certificate)
				.map_err(anyhow::Error::from)
				.map_err(AttemptError::Fatal)?;
		}
	}

	if roots.is_empty() {
		return Err(AttemptError::Fatal(anyhow!(
			"No trusted CA certificates found"
		)));
	}

	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();

	let connector = TlsConnector::from(Arc::new(config));

	// Reaching the port is part of the secure attempt: a refused connection
	// means "no listener" (Unavailable); a timeout or reset is classified by
	// `classify_io_error` and is Fatal unless plaintext was explicitly allowed.
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
		.map_err(|error| AttemptError::Fatal(error.into()))?;

	let tls_name = verify_for_sni.unwrap_or(host);

	let server_name = ServerName::try_from(tls_name.to_string())
		.map_err(|error| AttemptError::Fatal(error.into()))?;

	let mut tls_stream = match timeout(
		policy.connect_timeout,
		connector.connect(server_name, stream),
	)
	.await
	{
		Ok(Ok(stream)) => stream,

		Ok(Err(error)) => {
			return Err(classify_io_error(
				&error,
				policy.allow_insecure,
				"TLS handshake or certificate verification failed",
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

	send_and_receive(&mut tls_stream, request, frame)
		.await
		.map_err(AttemptError::Fatal)
}
