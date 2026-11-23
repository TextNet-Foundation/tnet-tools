use super::*;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_dir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!(
		"tnet-cmp-{}-{}-{}",
		tag,
		std::process::id(),
		DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
	));
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

fn sample(seed: u8) -> FileBody {
	let data: Vec<u8> = (0..20_000u32).map(|i| (i % 37) as u8 ^ seed).collect();
	FileBody::new(Bytes::from(data))
}

/// An entry heavier than the whole budget is refused and removes the old one.
fn forget_memory(key: MemoryKey) {
	lock_unpoisoned(&MEMORY).put(key, Bytes::new(), usize::MAX);
}

const DISK: DiskCachePolicy = DiskCachePolicy {
	enable: true,
	source_maximum: u64::MAX,
};

fn decompress(alg: &str, data: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	match alg {
		"gzip" => {
			flate2::read::GzDecoder::new(data)
				.read_to_end(&mut out)
				.unwrap();
		}
		_ => {
			zstd::stream::Decoder::new(data)
				.unwrap()
				.read_to_end(&mut out)
				.unwrap();
		}
	}
	out
}

#[test]
fn roundtrip_gzip_and_zstd() {
	let body = sample(1);
	for alg in SUPPORTED_COMPRESSION {
		let packed = compress_body(&body, alg).unwrap();
		assert!(packed.len() < body.len());
		assert_eq!(decompress(alg, &packed), &body[..]);
	}
	assert!(compress_body(&[], "gzip").is_none());
	assert!(compress_body(b"x", "br").is_none());
}

#[test]
fn negotiation_keeps_client_order() {
	assert_eq!(negotiate_compression(Some("gzip, zstd")), Some("gzip"));
	assert_eq!(negotiate_compression(Some("br, ZSTD, gzip")), Some("zstd"));
	assert_eq!(negotiate_compression(Some("br")), None);
	assert_eq!(negotiate_compression(None), None);
}

#[test]
fn negotiation_honours_q_values() {
	assert_eq!(
		negotiate_compression(Some("gzip;q=0.5, zstd;q=0.9")),
		Some("zstd")
	);
	assert_eq!(negotiate_compression(Some("gzip;q=0, zstd")), Some("zstd"));
	assert_eq!(negotiate_compression(Some("gzip;q=0, zstd; q=0")), None);
	assert_eq!(
		negotiate_compression(Some("gzip;q=0.5, zstd;q=0.5")),
		Some("gzip")
	);
	assert_eq!(
		negotiate_compression(Some("zstd;q=0.2, gzip")),
		Some("gzip")
	);
	assert_eq!(negotiate_compression(Some("gzip;q=abc")), Some("gzip"));
	// First mention wins: a later duplicate cannot re-enable a forbidden algorithm.
	assert_eq!(negotiate_compression(Some("gzip;q=0, gzip")), None);
}

#[tokio::test]
async fn cache_roundtrip_and_disk_hit() {
	let dir = temp_dir("rt");
	let body = sample(2);

	let first = get_compressed_cached(&dir, &body, "zstd", DISK)
		.await
		.unwrap();
	assert_eq!(decompress("zstd", &first), &body[..]);

	let record = disk::record_path(&dir, body.sha256_hex(), "zstd");
	assert!(record.exists());

	// A second lookup after dropping the memory entry must come from disk intact.
	forget_memory((*body.digest(), "zstd"));
	let second = get_compressed_cached(&dir, &body, "zstd", DISK)
		.await
		.unwrap();
	assert_eq!(first, second);
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn truncated_or_forged_record_is_ignored() {
	let dir = temp_dir("bad");
	let body = sample(3);
	let key = (*body.digest(), "gzip");
	let good = get_compressed_cached(&dir, &body, "gzip", DISK)
		.await
		.unwrap();
	let record = disk::record_path(&dir, body.sha256_hex(), "gzip");
	let original = std::fs::read(&record).unwrap();

	let drop_memory = || forget_memory(key);

	// Truncated record.
	std::fs::write(&record, &original[..original.len() - 10]).unwrap();
	drop_memory();
	assert_eq!(
		get_compressed_cached(&dir, &body, "gzip", DISK)
			.await
			.unwrap(),
		good
	);

	// Same length, flipped payload byte: body hash must catch it.
	let mut forged = original.clone();
	let last = forged.len() - 1;
	forged[last] ^= 0xff;
	std::fs::write(&record, &forged).unwrap();
	drop_memory();
	assert_eq!(
		get_compressed_cached(&dir, &body, "gzip", DISK)
			.await
			.unwrap(),
		good
	);

	// The damaged record was never served and has been healed by an atomic rewrite.
	assert_eq!(std::fs::read(&record).unwrap(), original);
	let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn decode_rejects_every_kind_of_damage() {
	let source = [9u8; 32];
	let record = disk::encode(&source, b"payload");
	assert_eq!(
		&disk::decode(record.clone(), &source).unwrap()[..],
		b"payload"
	);

	assert!(disk::decode(record[..10].to_vec(), &source).is_err());
	assert!(disk::decode(record.clone(), &[1u8; 32]).is_err());

	let mut bad_magic = record.clone();
	bad_magic[0] = b'X';
	assert!(disk::decode(bad_magic, &source).is_err());

	let mut bad_len = record.clone();
	bad_len[8] ^= 1;
	assert!(disk::decode(bad_len, &source).is_err());

	let mut bad_version = record;
	bad_version[4] = 99;
	assert!(disk::decode(bad_version, &source).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_writes_of_one_key_leave_a_valid_file() {
	let dir = temp_dir("par");
	let body = sample(4);
	let packed = Bytes::from(compress_body(&body, "gzip").unwrap());

	let mut handles = Vec::new();
	for _ in 0..16 {
		let (dir, body, packed) = (dir.clone(), body.clone(), packed.clone());
		handles.push(tokio::spawn(async move {
			disk::write(&dir, &body, "gzip", &packed).await
		}));
	}
	for handle in handles {
		handle.await.unwrap().unwrap();
	}

	let record = std::fs::read(disk::record_path(&dir, body.sha256_hex(), "gzip")).unwrap();
	assert_eq!(disk::decode(record, body.digest()).unwrap(), packed);

	let leftovers = std::fs::read_dir(&dir).unwrap().count();
	assert_eq!(leftovers, 1, "temp files must not be left behind");
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_share_one_compression() {
	let body = sample(5);
	let dir = temp_dir("sf");

	let mut handles = Vec::new();
	for _ in 0..20 {
		let (dir, body) = (dir.clone(), body.clone());
		handles.push(tokio::spawn(async move {
			get_compressed_cached(&dir, &body, "gzip", DISK).await
		}));
	}
	let mut pointers = Vec::new();
	for handle in handles {
		pointers.push(handle.await.unwrap().unwrap().as_ptr() as usize);
	}

	// One computation means every caller got a clone of the same buffer.
	pointers.dedup();
	assert_eq!(pointers.len(), 1);
	let _ = std::fs::remove_dir_all(dir);
}
