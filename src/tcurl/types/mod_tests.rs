use super::*;
use std::io::{Error, ErrorKind};

fn is_fatal(error: &AttemptError) -> bool {
	matches!(error, AttemptError::Fatal(_))
}

#[test]
fn refused_is_unavailable_with_and_without_flag() {
	let error = Error::from(ErrorKind::ConnectionRefused);

	assert!(matches!(
		classify_io_error(&error, false, "connect"),
		AttemptError::Unavailable(_)
	));
	assert!(matches!(
		classify_io_error(&error, true, "connect"),
		AttemptError::Unavailable(_)
	));
}

#[test]
fn handshake_cut_is_fatal_without_flag() {
	for kind in [
		ErrorKind::UnexpectedEof,
		ErrorKind::ConnectionReset,
		ErrorKind::ConnectionAborted,
		ErrorKind::BrokenPipe,
		ErrorKind::TimedOut,
	] {
		let result = classify_io_error(&Error::from(kind), false, "TLS handshake");

		let AttemptError::Fatal(message) = result else {
			panic!("{kind:?} must be fatal without the flag");
		};

		assert!(message.to_string().contains("--allow-insecure-fallback"));
	}
}

#[test]
fn handshake_cut_is_unavailable_with_flag() {
	for kind in [ErrorKind::UnexpectedEof, ErrorKind::ConnectionReset] {
		assert!(matches!(
			classify_io_error(&Error::from(kind), true, "TLS handshake"),
			AttemptError::Unavailable(_)
		));
	}
}

#[test]
fn not_a_tls_peer_needs_flag() {
	let make = || {
		Error::new(
			ErrorKind::InvalidData,
			rustls::Error::InvalidMessage(rustls::InvalidMessage::MissingData("x")),
		)
	};

	assert!(is_fatal(&classify_io_error(&make(), false, "TLS")));
	assert!(matches!(
		classify_io_error(&make(), true, "TLS"),
		AttemptError::Unavailable(_)
	));
}

#[test]
fn certificate_errors_are_always_fatal() {
	let make = || {
		Error::new(
			ErrorKind::InvalidData,
			rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
		)
	};

	assert!(is_fatal(&classify_io_error(&make(), false, "TLS")));
	assert!(is_fatal(&classify_io_error(&make(), true, "TLS")));
}

#[test]
fn transport_security() {
	assert!(Transport::Ssh.is_secure());
	assert!(Transport::Tls.is_secure());
	assert!(!Transport::Tcp.is_secure());
}
