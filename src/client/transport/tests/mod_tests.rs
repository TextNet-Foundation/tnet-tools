use super::tls::classify_io_error;
use super::*;
use std::io::{Error, ErrorKind};
use tokio::io::{AsyncWriteExt, duplex};

#[test]
fn refused_is_unavailable() {
	let error = Error::from(ErrorKind::ConnectionRefused);

	assert!(matches!(
		classify_io_error(&error, false, "c"),
		TlsAttemptError::Unavailable(_)
	));
}

#[test]
fn handshake_cut_is_fatal_without_flag_and_unavailable_with_it() {
	for kind in [
		ErrorKind::UnexpectedEof,
		ErrorKind::ConnectionReset,
		ErrorKind::ConnectionAborted,
		ErrorKind::BrokenPipe,
		ErrorKind::TimedOut,
	] {
		let TlsAttemptError::Fatal(message) = classify_io_error(&Error::from(kind), false, "c")
		else {
			panic!("{kind:?} must be fatal");
		};

		assert!(message.to_string().contains("--allow-insecure-fallback"));
		assert!(matches!(
			classify_io_error(&Error::from(kind), true, "c"),
			TlsAttemptError::Unavailable(_)
		));
	}
}

#[test]
fn certificate_errors_are_always_fatal() {
	let make = || {
		Error::new(
			ErrorKind::InvalidData,
			tokio_rustls::rustls::Error::InvalidCertificate(
				tokio_rustls::rustls::CertificateError::UnknownIssuer,
			),
		)
	};

	assert!(matches!(
		classify_io_error(&make(), false, "c"),
		TlsAttemptError::Fatal(_)
	));
	assert!(matches!(
		classify_io_error(&make(), true, "c"),
		TlsAttemptError::Fatal(_)
	));
}

#[test]
fn ssh_classification() {
	let refused = russh::Error::IO(Error::from(ErrorKind::ConnectionRefused));
	let reset = russh::Error::IO(Error::from(ErrorKind::ConnectionReset));

	assert!(matches!(
		ssh::classify_connect_error(&refused, false),
		SshAttemptError::Unavailable(_)
	));
	assert!(matches!(
		ssh::classify_connect_error(&reset, false),
		SshAttemptError::Failed(_)
	));
	assert!(matches!(
		ssh::classify_connect_error(&reset, true),
		SshAttemptError::Unavailable(_)
	));
}

#[test]
fn plaintext_needs_flag() {
	assert!(plaintext_fallback_allowed(true, "x").is_ok());
	assert!(
		plaintext_fallback_allowed(false, "x")
			.unwrap_err()
			.to_string()
			.contains("--allow-insecure-fallback")
	);
}

#[tokio::test]
async fn utnp_read_is_limited() {
	let (mut client, mut server) = duplex(1 << 20);

	tokio::spawn(async move {
		let _ = server.write_all(&vec![b'x'; MAX_UTNP_RESPONSE + 1]).await;
		let _ = server.shutdown().await;
	});

	assert!(
		read_until_eof(&mut client, MAX_UTNP_RESPONSE)
			.await
			.is_err()
	);
}

#[tokio::test]
async fn small_utnp_read_succeeds() {
	let (mut client, mut server) = duplex(1024);

	tokio::spawn(async move {
		let _ = server.write_all(b"UTNP/2.0 OK\n\n").await;
		let _ = server.shutdown().await;
	});

	assert_eq!(
		read_until_eof(&mut client, MAX_UTNP_RESPONSE)
			.await
			.unwrap(),
		b"UTNP/2.0 OK\n\n"
	);
}
