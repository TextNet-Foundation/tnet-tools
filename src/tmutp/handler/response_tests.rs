use super::*;
use crate::common::FileBody;
use bytes::Bytes;

fn content(len: usize) -> FileBody {
	FileBody::new(Bytes::from(
		(0..len).map(|i| (i % 29) as u8).collect::<Vec<_>>(),
	))
}

fn header_value<'a>(response: &'a [u8], name: &str) -> Option<&'a str> {
	let end = response.windows(2).position(|w| w == b"\n\n")?;
	std::str::from_utf8(&response[..end])
		.ok()?
		.lines()
		.find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
}

#[tokio::test]
async fn range_uses_cached_hash_and_compresses() {
	let body = content(20_000);
	let response =
		compression::make_range_response(&body, None, "bytes=0-9999", Some("gzip"), 100, true)
			.await;

	assert_eq!(
		header_value(&response, "FILE-SHA256"),
		Some(body.sha256_hex())
	);
	assert_eq!(header_value(&response, "Content-Encoding"), Some("gzip"));
	assert_eq!(
		header_value(&response, "Content-Range"),
		Some("bytes 0-9999/20000")
	);
}

#[tokio::test]
async fn out_of_range_is_not_satisfiable() {
	let body = content(10);
	let response =
		compression::make_range_response(&body, None, "bytes=5-50", None, 100, false).await;
	assert!(response.starts_with(b"TMUTP/2.0 53"));
}

#[tokio::test]
async fn file_response_compresses_and_reports_source_length() {
	let dir = std::env::temp_dir().join(format!("tnet-tmutp-resp-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let body = content(30_000);

	let response =
		compression::make_file_response(&body, None, Some("zstd"), 100, &dir, false).await;

	assert_eq!(header_value(&response, "Content-Encoding"), Some("zstd"));
	assert_eq!(
		header_value(&response, "SOURCE-CONTENT-LENGTH"),
		Some("30000")
	);
	let _ = std::fs::remove_dir_all(dir);
}
