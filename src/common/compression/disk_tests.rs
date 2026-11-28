use super::*;
use std::time::SystemTime;

fn temp_dir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("tnet-disk-{tag}-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

fn set_age(path: &Path, age: Duration) {
	let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
	file.set_modified(SystemTime::now() - age).unwrap();
}

#[tokio::test]
async fn oversized_record_is_rejected_and_removed_when_stale() {
	let dir = temp_dir("huge");
	let content = FileBody::new(Bytes::from_static(b"small source"));
	let path = record_path(&dir, content.sha256_hex(), "gzip");

	// Sparse file far beyond any plausible record for this source.
	let file = std::fs::File::create(&path).unwrap();
	file.set_len(512 * 1024 * 1024).unwrap();
	drop(file);
	set_age(&path, FRESH_GRACE * 2);

	assert!(read(&dir, &content, "gzip").await.is_none());
	assert!(!path.exists());
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn fresh_oversized_record_is_ignored_but_kept() {
	let dir = temp_dir("fresh");
	let content = FileBody::new(Bytes::from_static(b"small source"));
	let path = record_path(&dir, content.sha256_hex(), "gzip");

	let file = std::fs::File::create(&path).unwrap();
	file.set_len(1024 * 1024).unwrap();
	drop(file);

	assert!(read(&dir, &content, "gzip").await.is_none());
	assert!(path.exists());
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn record_within_limit_still_reads() {
	let dir = temp_dir("ok");
	let content = FileBody::new(Bytes::from_static(b"small source"));
	let body = Bytes::from_static(b"packed");

	write(&dir, &content, "gzip", &body).await.unwrap();
	assert_eq!(read(&dir, &content, "gzip").await.unwrap(), body);
	let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn limit_allows_incompressible_overhead() {
	assert!(max_record_len(0) >= HEADER_LEN);
	assert!(max_record_len(1000) > HEADER_LEN + 1000 + 125);
}
