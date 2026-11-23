use super::*;
use crate::config::AppState;
use std::path::PathBuf;

fn state(cache: PathBuf, minimum: usize) -> AppState {
	AppState {
		root: String::new(),
		lua_engine: None,
		rhai_engine: None,
		scripting_config: Default::default(),
		require_secure: false,
		support_first_version: false,
		compression_minimum: minimum,
		compression_cache: cache,
		compression_cache_enable: true,
		compression_cache_source_maximum: u64::MAX,
	}
}

fn body(len: usize, seed: u8) -> FileBody {
	FileBody::new(Bytes::from(
		(0..len).map(|i| (i % 41) as u8 ^ seed).collect::<Vec<_>>(),
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
async fn head_and_get_agree_on_headers() {
	let cache = std::env::temp_dir().join(format!("tnet-tbip-head-{}", std::process::id()));
	std::fs::create_dir_all(&cache).unwrap();
	let state = state(cache.clone(), 100);
	let path = Path::new("/x/file.txt");

	for (len, seed) in [(10usize, 1u8), (5000, 2), (200_000, 3)] {
		let content = body(len, seed);

		for alg in [None, Some("gzip"), Some("zstd")] {
			let get = make_file_response(&content, None, alg, &state, path, true).await;
			let head = make_head_response(&content, None, alg, &state, path, true).await;

			assert_eq!(&get[..head.len()], &head[..], "len={len} alg={alg:?}");

			let length: usize = header_value(&get, "Content-Length")
				.unwrap()
				.parse()
				.unwrap();
			assert_eq!(get.len(), head.len() + length);
			assert_eq!(
				header_value(&get, "Content-Encoding"),
				header_value(&head, "Content-Encoding")
			);
		}
	}
	let _ = std::fs::remove_dir_all(cache);
}

#[tokio::test]
async fn compressed_get_announces_encoding_and_hash_of_source() {
	let cache = std::env::temp_dir().join(format!("tnet-tbip-enc-{}", std::process::id()));
	std::fs::create_dir_all(&cache).unwrap();
	let state = state(cache.clone(), 100);
	let content = body(50_000, 9);

	let get = make_file_response(
		&content,
		None,
		Some("gzip"),
		&state,
		Path::new("a.txt"),
		false,
	)
	.await;

	assert_eq!(header_value(&get, "Content-Encoding"), Some("gzip"));
	assert_eq!(
		header_value(&get, "FILE-SHA256"),
		Some(content.sha256_hex())
	);
	assert_eq!(header_value(&get, "SOURCE-CONTENT-LENGTH"), Some("50000"));
	let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn range_response_uses_cached_hash_and_slice() {
	let state = state(PathBuf::from("/nonexistent"), 1 << 30);
	let content = body(1000, 4);

	let response = make_range_response(
		&content,
		None,
		"bytes=10-19",
		None,
		&state,
		Path::new("a.bin"),
		false,
	);

	assert_eq!(
		header_value(&response, "FILE-SHA256"),
		Some(content.sha256_hex())
	);
	assert_eq!(
		header_value(&response, "Content-Range"),
		Some("bytes 10-19/1000")
	);
	assert_eq!(&response[response.len() - 10..], &content[10..20]);
}
