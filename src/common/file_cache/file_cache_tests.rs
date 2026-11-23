use super::*;
use std::sync::atomic::AtomicUsize;

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_dir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!(
		"tnet-fc-{}-{}-{}",
		tag,
		std::process::id(),
		DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
	));
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

#[tokio::test]
async fn reads_and_hashes_once() {
	let dir = temp_dir("basic");
	let path = dir.join("a.txt");
	std::fs::write(&path, b"hello").unwrap();

	let first = read_file_cached(&path).await.unwrap();
	let second = read_file_cached(&path).await.unwrap();

	assert_eq!(&first.bytes[..], b"hello");
	assert_eq!(
		first.bytes.sha256_hex(),
		"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	);
	// A hit shares the same allocation.
	assert_eq!(first.bytes.as_ptr(), second.bytes.as_ptr());
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn same_size_and_mtime_replacement_is_detected() {
	let dir = temp_dir("swap");
	let path = dir.join("f.bin");
	std::fs::write(&path, b"AAAA").unwrap();
	let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();

	assert_eq!(&read_file_cached(&path).await.unwrap().bytes[..], b"AAAA");

	// In-place rewrite with identical size, mtime restored.
	std::fs::write(&path, b"BBBB").unwrap();
	std::fs::File::options()
		.write(true)
		.open(&path)
		.unwrap()
		.set_modified(mtime)
		.unwrap();
	assert_eq!(&read_file_cached(&path).await.unwrap().bytes[..], b"BBBB");

	// Replacement by rename (new inode), identical size, mtime restored.
	let other = dir.join("other.bin");
	std::fs::write(&other, b"CCCC").unwrap();
	std::fs::File::options()
		.write(true)
		.open(&other)
		.unwrap()
		.set_modified(mtime)
		.unwrap();
	std::fs::rename(&other, &path).unwrap();
	assert_eq!(&read_file_cached(&path).await.unwrap().bytes[..], b"CCCC");
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn oversized_file_is_refused() {
	let dir = temp_dir("big");
	let path = dir.join("big.bin");
	std::fs::write(&path, vec![0u8; 2048]).unwrap();

	let previous = MAX_FILE_SIZE.swap(1024, Ordering::Relaxed);
	let result = read_file_cached(&path).await;
	MAX_FILE_SIZE.store(previous, Ordering::Relaxed);

	assert_eq!(
		result.err().map(|e| e.kind()),
		Some(io::ErrorKind::FileTooLarge)
	);
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn directory_is_not_a_file() {
	let dir = temp_dir("dir");
	assert!(read_file_cached(&dir).await.is_err());
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_share_one_load() {
	let dir = temp_dir("flight");
	let path = dir.join("shared.bin");
	std::fs::write(&path, vec![7u8; 600]).unwrap();

	let mut handles = Vec::new();
	for _ in 0..20 {
		let path = path.clone();
		handles.push(tokio::spawn(async move { read_file_cached(&path).await }));
	}

	let mut pointers = Vec::new();
	for handle in handles {
		pointers.push(handle.await.unwrap().unwrap().bytes.as_ptr() as usize);
	}
	pointers.dedup();
	assert_eq!(
		pointers.len(),
		1,
		"all callers must receive the same buffer"
	);
	let _ = std::fs::remove_dir_all(dir);
}
