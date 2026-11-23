use super::*;
use std::io::{Error, ErrorKind};

#[test]
fn refused_is_unavailable() {
	let error = russh::Error::IO(Error::from(ErrorKind::ConnectionRefused));

	assert!(matches!(
		classify_connect_error(&error, false),
		SshAttemptError::Unavailable(_)
	));
}

#[test]
fn reset_and_eof_are_failed_without_flag() {
	for error in [
		russh::Error::IO(Error::from(ErrorKind::ConnectionReset)),
		russh::Error::IO(Error::from(ErrorKind::UnexpectedEof)),
		russh::Error::HUP,
		russh::Error::ConnectionTimeout,
	] {
		let SshAttemptError::Failed(message) = classify_connect_error(&error, false) else {
			panic!("{error} must be Failed");
		};

		assert!(message.to_string().contains("--allow-insecure-fallback"));
	}
}

#[test]
fn reset_is_unavailable_with_flag() {
	let error = russh::Error::IO(Error::from(ErrorKind::ConnectionReset));

	assert!(matches!(
		classify_connect_error(&error, true),
		SshAttemptError::Unavailable(_)
	));
}
