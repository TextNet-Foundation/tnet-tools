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
		compression::make_range_response(&body, None, "bytes=10-50", None, 100, false).await;
	assert!(response.starts_with(b"TMUTP/2.0 53"));
}

/// Same table as in the TBIP tests: both protocols must resolve identical inputs identically.
const RANGE_TABLE: [(&str, Option<&str>); 6] = [
	("bytes=0-9", Some("bytes 0-9/10")),
	("bytes=5-50", Some("bytes 5-9/10")),
	("bytes=9-9", Some("bytes 9-9/10")),
	("bytes=0-10", Some("bytes 0-9/10")),
	("bytes=10-10", None),
	("bytes=11-20", None),
];

#[tokio::test]
async fn ranges_match_the_shared_table() {
	let body = content(10);

	for (range, expected) in RANGE_TABLE {
		let response = compression::make_range_response(&body, None, range, None, 100, false).await;
		assert_eq!(
			header_value(&response, "Content-Range"),
			expected,
			"{range}"
		);
		if expected.is_none() {
			assert!(response.starts_with(b"TMUTP/2.0 53"), "{range}");
		}
	}
}

#[test]
fn range_error_header_is_sanitized() {
	let hostile = format!("bytes=\r\nSet-Cookie: x\n\0{}", "a".repeat(500));
	let response = make_range_error_response(INVALID_RANGE, &hostile, "invalid-range", 3);
	let end = response.windows(2).position(|w| w == b"\n\n").unwrap();
	let head = std::str::from_utf8(&response[..end]).unwrap();
	assert!(!head.contains('\r') && !head.contains('\0'));
	assert!(head.lines().all(|line| !line.starts_with("Set-Cookie")));
	let line = head
		.lines()
		.find(|l| l.starts_with("Range-Error: "))
		.unwrap();
	assert!(line.len() < 260);
}

#[tokio::test]
async fn file_response_compresses_and_reports_source_length() {
	let dir = std::env::temp_dir().join(format!("tnet-tmutp-resp-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let body = content(30_000);

	let cache = crate::config::DiskCache {
		dir: dir.clone(),
		policy: crate::common::DiskCachePolicy {
			enable: true,
			source_maximum: u64::MAX,
		},
	};

	let response =
		compression::make_file_response(&body, None, Some("zstd"), 100, &cache, false).await;

	assert_eq!(header_value(&response, "Content-Encoding"), Some("zstd"));
	assert_eq!(
		header_value(&response, "SOURCE-CONTENT-LENGTH"),
		Some("30000")
	);
	let _ = std::fs::remove_dir_all(dir);
}
