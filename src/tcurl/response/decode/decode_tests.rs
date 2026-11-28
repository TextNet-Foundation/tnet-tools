use super::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

fn gzip(data: &[u8]) -> Vec<u8> {
	let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
	encoder.write_all(data).unwrap();
	encoder.finish().unwrap()
}

fn header(encoding: &str) -> String {
	format!("TMUTP/2.0 20 OK\nContent-Encoding: {encoding}\n\n")
}

#[test]
fn gzip_roundtrip() {
	let packed = gzip(b"hello world");
	let decoded = decode_body(&header("gzip"), &packed).unwrap();
	assert_eq!(&decoded.data[..], b"hello world");
	assert!(decoded.verifiable);
}

#[test]
fn zstd_roundtrip() {
	let packed = zstd::encode_all(&b"hello world"[..], 3).unwrap();
	let decoded = decode_body(&header("ZSTD"), &packed).unwrap();
	assert_eq!(&decoded.data[..], b"hello world");
	assert!(decoded.verifiable);
}

#[test]
fn bomb_is_rejected() {
	let packed = gzip(&vec![0u8; 100_000]);
	let error = decode_body_limited(&header("gzip"), &packed, 1000).unwrap_err();
	assert!(error.to_string().contains("decompression limit exceeded"));

	let packed = zstd::encode_all(&vec![0u8; 100_000][..], 3).unwrap();
	let error = decode_body_limited(&header("zstd"), &packed, 1000).unwrap_err();
	assert!(error.to_string().contains("decompression limit exceeded"));

	// Exactly at the limit is fine.
	let packed = gzip(&[7u8; 1000]);
	assert_eq!(
		decode_body_limited(&header("gzip"), &packed, 1000)
			.unwrap()
			.data
			.len(),
		1000
	);
}

#[test]
fn corrupt_data_is_an_error() {
	assert!(decode_body(&header("gzip"), b"not gzip at all").is_err());
}

#[test]
fn unknown_encoding_and_ranges_stay_raw() {
	let decoded = decode_body(&header("br"), b"abc").unwrap();
	assert_eq!(&decoded.data[..], b"abc");
	assert!(!decoded.verifiable);

	let ranged = "TMUTP/2.0 20 OK\nContent-Range: bytes 0-1/5\n\n";
	let decoded = decode_body(ranged, b"ab").unwrap();
	assert_eq!(&decoded.data[..], b"ab");
	assert!(!decoded.verifiable);

	let plain = decode_body("TMUTP/2.0 20 OK\n\n", b"abc").unwrap();
	assert!(plain.verifiable);
}
