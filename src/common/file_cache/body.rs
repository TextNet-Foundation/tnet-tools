use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::ops::Deref;
use std::sync::Arc;

/// File content together with its SHA-256, computed exactly once when the file is loaded.
/// Derefs to `[u8]`; cloning only bumps reference counts.
#[derive(Clone)]
pub struct FileBody {
	bytes: Bytes,
	digest: [u8; 32],
	hex: Arc<str>,
}

impl FileBody {
	pub fn new(bytes: Bytes) -> Self {
		let digest: [u8; 32] = Sha256::digest(&bytes).into();
		let mut hex = String::with_capacity(64);
		for byte in digest {
			// Writing into a String cannot fail.
			let _ = write!(hex, "{byte:02x}");
		}

		Self {
			bytes,
			digest,
			hex: hex.into(),
		}
	}

	pub fn bytes(&self) -> &Bytes {
		&self.bytes
	}

	pub fn digest(&self) -> &[u8; 32] {
		&self.digest
	}

	pub fn sha256_hex(&self) -> &str {
		&self.hex
	}
}

impl Deref for FileBody {
	type Target = [u8];

	fn deref(&self) -> &[u8] {
		&self.bytes
	}
}
