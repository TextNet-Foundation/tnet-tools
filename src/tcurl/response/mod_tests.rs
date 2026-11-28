use super::headers::{is_success, status_code};
use super::*;

const HELLO_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

#[test]
fn status_parsing_and_exit_codes() {
	assert_eq!(status_code("TMUTP/2.0 20 OK\nA: b\n\n"), Some(20));
	assert_eq!(status_code("garbage"), None);

	assert_eq!(exit_code_for(Some(20)), 0);
	assert_eq!(exit_code_for(Some(22)), 0);

	for status in [30, 31, 32, 40, 50, 55] {
		assert_eq!(exit_code_for(Some(status)), 1, "{status}");
	}

	assert_eq!(exit_code_for(None), 1);
	assert!(!is_success(None));
}

#[test]
fn sha256_match_and_mismatch() {
	let header = format!("TMUTP/2.0 20 OK\nFILE-SHA256: {HELLO_SHA}\nContent-Length: 5\n\n");

	assert!(verify_file_sha256(&header, b"hello").unwrap());
	assert!(verify_file_sha256(&header, b"hellO").is_err());
}

#[test]
fn sha256_skipped_without_header_or_for_ranged() {
	assert!(!verify_file_sha256("TMUTP/2.0 20 OK\n\n", b"x").unwrap());

	let ranged =
		format!("TMUTP/2.0 20 OK\nFILE-SHA256: {HELLO_SHA}\nContent-Range: bytes 0-1/5\n\n");
	assert!(!verify_file_sha256(&ranged, b"he").unwrap());
}

#[tokio::test]
async fn error_status_does_not_overwrite_output_file() {
	let dir = std::env::temp_dir().join(format!("tcurl-test-{}", std::process::id()));
	tokio::fs::create_dir_all(&dir).await.unwrap();
	let path = dir.join("out.txt");
	tokio::fs::write(&path, b"precious").await.unwrap();

	let response = b"TMUTP/2.0 31 NOT FOUND\nContent-Length: 3\n\nerr";
	let output = Some(path.clone());
	let none = None;

	let code = handle_response(
		response,
		false,
		OutputOptions {
			output: &output,
			output_header: &none,
			output_on_error: false,
			raw: false,
		},
	)
	.await
	.unwrap();

	assert_eq!(code, 1);
	assert_eq!(tokio::fs::read(&path).await.unwrap(), b"precious");

	handle_response(
		response,
		false,
		OutputOptions {
			output: &output,
			output_header: &none,
			output_on_error: true,
			raw: false,
		},
	)
	.await
	.unwrap();

	assert_eq!(tokio::fs::read(&path).await.unwrap(), b"err");
	let _ = tokio::fs::remove_dir_all(&dir).await;
}

fn gzip(data: &[u8]) -> Vec<u8> {
	use std::io::Write;
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(data).unwrap();
	encoder.finish().unwrap()
}

fn gzip_response(sha: &str, body: &[u8]) -> Vec<u8> {
	let mut response = format!(
		"TMUTP/2.0 20 OK\nContent-Encoding: gzip\nFILE-SHA256: {sha}\nContent-Length: {}\n\n",
		body.len()
	)
	.into_bytes();
	response.extend_from_slice(body);
	response
}

async fn run(response: &[u8], path: &std::path::Path, raw: bool) -> Result<u8> {
	let output = Some(path.to_path_buf());
	let none = None;

	handle_response(
		response,
		false,
		OutputOptions {
			output: &output,
			output_header: &none,
			output_on_error: false,
			raw,
		},
	)
	.await
}

#[tokio::test]
async fn compressed_body_is_decompressed_verified_and_saved() {
	let dir = std::env::temp_dir().join(format!("tcurl-dec-{}", std::process::id()));
	tokio::fs::create_dir_all(&dir).await.unwrap();
	let path = dir.join("out.txt");
	let response = gzip_response(HELLO_SHA, &gzip(b"hello"));

	assert_eq!(run(&response, &path, false).await.unwrap(), 0);
	assert_eq!(tokio::fs::read(&path).await.unwrap(), b"hello");

	// --raw keeps the compressed bytes and does not verify.
	assert_eq!(run(&response, &path, true).await.unwrap(), 0);
	assert_eq!(tokio::fs::read(&path).await.unwrap(), gzip(b"hello"));

	let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn wrong_hash_of_decompressed_body_fails_before_writing() {
	let dir = std::env::temp_dir().join(format!("tcurl-badsha-{}", std::process::id()));
	tokio::fs::create_dir_all(&dir).await.unwrap();
	let path = dir.join("out.txt");
	tokio::fs::write(&path, b"precious").await.unwrap();

	let response = gzip_response(HELLO_SHA, &gzip(b"hellO"));
	assert!(run(&response, &path, false).await.is_err());
	assert_eq!(tokio::fs::read(&path).await.unwrap(), b"precious");

	// --raw skips both decompression and the check.
	assert_eq!(run(&response, &path, true).await.unwrap(), 0);

	let _ = tokio::fs::remove_dir_all(&dir).await;
}
