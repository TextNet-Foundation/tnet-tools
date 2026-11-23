use super::framing::{parse_content_length, trim_and_check};
use super::tcp::send_and_receive;
use super::*;
use crate::types::{MAX_RESPONSE_BODY, MAX_RESPONSE_HEADER};
use tokio::io::{AsyncWriteExt, duplex};

#[test]
fn plaintext_requires_flag_unless_explicit() {
	assert!(plaintext_fallback_allowed(TransportMode::TcpOnly, false, "x").is_ok());
	assert!(plaintext_fallback_allowed(TransportMode::TlsThenTcp, true, "x").is_ok());
	assert!(plaintext_fallback_allowed(TransportMode::SshThenTlsThenTcp, true, "x").is_ok());

	let error = plaintext_fallback_allowed(TransportMode::TlsThenTcp, false, "TLS: refused")
		.unwrap_err()
		.to_string();

	assert!(error.contains("--allow-insecure-fallback"));
	assert!(plaintext_fallback_allowed(TransportMode::SshThenTlsThenTcp, false, "x").is_err());
}

#[test]
fn trim_cuts_bytes_beyond_content_length() {
	let mut response = b"TMUTP/2.0 20 OK\nContent-Length: 3\n\nabcEXTRA".to_vec();

	assert!(trim_and_check(&mut response, false).unwrap());
	assert!(response.ends_with(b"abc"));
}

#[test]
fn trim_waits_for_incomplete_body_and_ignores_body_for_head() {
	let mut partial = b"TBIP/2.0 20 OK\nContent-Length: 10\n\nabc".to_vec();
	assert!(!trim_and_check(&mut partial, false).unwrap());

	let mut head = b"TBIP/2.0 20 OK\nContent-Length: 10\n\n".to_vec();
	assert!(trim_and_check(&mut head, true).unwrap());
}

#[test]
fn trim_rejects_oversized_headers_and_body() {
	let mut headers = vec![b'a'; MAX_RESPONSE_HEADER + 1];
	assert!(trim_and_check(&mut headers, false).is_err());

	let mut body = format!(
		"TMUTP/2.0 20 OK\nContent-Length: {}\n\n",
		MAX_RESPONSE_BODY + 1
	)
	.into_bytes();
	assert!(trim_and_check(&mut body, false).is_err());
}

#[test]
fn content_length_is_required() {
	assert!(parse_content_length(b"TMUTP/2.0 20 OK\n\n").is_err());
}

#[tokio::test]
async fn header_without_newline_is_limited() {
	let (mut client, mut server) = duplex(1 << 20);

	tokio::spawn(async move {
		let _ = server.write_all(&vec![b'x'; MAX_RESPONSE_HEADER * 2]).await;
		let _ = server.shutdown().await;
	});

	let error = send_and_receive(&mut client, b"GET", FrameKind::Protocol { head: false })
		.await
		.unwrap_err();

	assert!(error.to_string().contains("size limit"));
}

#[tokio::test]
async fn lying_content_length_does_not_preallocate_and_fails_on_eof() {
	let (mut client, mut server) = duplex(1 << 16);

	tokio::spawn(async move {
		let _ = server
			.write_all(b"TMUTP/2.0 20 OK\nContent-Length: 200000000\n\nshort")
			.await;
		let _ = server.shutdown().await;
	});

	let error = send_and_receive(&mut client, b"GET", FrameKind::Protocol { head: false })
		.await
		.unwrap_err();

	assert!(error.to_string().contains("closed before"));
}

#[tokio::test]
async fn complete_response_is_read() {
	let (mut client, mut server) = duplex(1 << 16);

	tokio::spawn(async move {
		let _ = server
			.write_all(b"TMUTP/2.0 20 OK\nContent-Length: 5\n\nhello")
			.await;
	});

	let data = send_and_receive(&mut client, b"GET", FrameKind::Protocol { head: false })
		.await
		.unwrap();

	assert!(data.ends_with(b"hello"));
}

#[tokio::test]
async fn utnp_read_is_limited() {
	let (mut client, mut server) = duplex(1 << 20);

	tokio::spawn(async move {
		let _ = server
			.write_all(&vec![b'x'; crate::types::MAX_UTNP_RESPONSE + 1])
			.await;
		let _ = server.shutdown().await;
	});

	let error = send_and_receive(&mut client, b"UTNP", FrameKind::Utnp)
		.await
		.unwrap_err();

	assert!(error.to_string().contains("size limit"));
}
