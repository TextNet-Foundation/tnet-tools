use std::fs::Metadata;
use std::time::SystemTime;

/// Identity of a file version taken from an open descriptor.
/// On unix the inode, device and ctime are included, so replacing a file with another
/// of the same size and mtime still produces a different stamp.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FileStamp {
	len: u64,
	modified: Option<SystemTime>,
	#[cfg(unix)]
	unix: (u64, u64, i64, i64),
}

impl FileStamp {
	pub fn of(metadata: &Metadata) -> Self {
		#[cfg(unix)]
		let unix = {
			use std::os::unix::fs::MetadataExt;
			(
				metadata.dev(),
				metadata.ino(),
				metadata.ctime(),
				metadata.ctime_nsec(),
			)
		};

		Self {
			len: metadata.len(),
			modified: metadata.modified().ok(),
			#[cfg(unix)]
			unix,
		}
	}

	pub fn size(&self) -> u64 {
		self.len
	}
}
