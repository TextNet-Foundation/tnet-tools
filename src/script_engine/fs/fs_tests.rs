use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
	fn new() -> Self {
		let dir = std::env::temp_dir().join(format!(
			"tnet-fs-{}-{}",
			std::process::id(),
			COUNTER.fetch_add(1, Ordering::SeqCst)
		));
		fs::create_dir_all(dir.join("root")).expect("create temp root");
		TempRoot(dir)
	}

	fn root(&self) -> PathBuf {
		self.0.join("root")
	}

	fn sandbox(&self) -> Sandbox {
		Sandbox::new(
			self.root(),
			vec![".script.lua".into(), ".script.rhai".into()],
		)
	}
}

impl Drop for TempRoot {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

#[test]
fn write_and_read_roundtrip_inside_root() {
	let tmp = TempRoot::new();
	let sb = tmp.sandbox();
	sb.write("data/a.txt", b"hello").expect("write");
	assert_eq!(sb.read("/data/a.txt").expect("read"), b"hello");
	assert!(sb.exists("data/a.txt"));
}

#[test]
fn parent_traversal_is_denied() {
	let tmp = TempRoot::new();
	let sb = tmp.sandbox();
	assert!(sb.write("../x", b"1").is_err());
	assert!(sb.write("a/../../x", b"1").is_err());
	assert!(!tmp.0.join("x").exists());
	assert!(sb.read("../root/../x").is_err());
}

#[test]
fn leading_slash_stays_inside_root() {
	let tmp = TempRoot::new();
	let sb = tmp.sandbox();
	sb.write("/etc-like/passwd", b"1").expect("write");
	assert!(tmp.root().join("etc-like/passwd").is_file());
	assert!(sb.read("/etc/passwd").is_err());
}

#[test]
fn dangling_symlink_pointing_outside_is_not_followed() {
	let tmp = TempRoot::new();
	let outside = tmp.0.join("outside.txt");
	std::os::unix::fs::symlink(&outside, tmp.root().join("link")).expect("symlink");
	let sb = tmp.sandbox();
	assert!(sb.write("link", b"pwn").is_err());
	assert!(!outside.exists());
	// Висячий симлинк в середине пути тоже не приводит к созданию каталогов.
	std::os::unix::fs::symlink(tmp.0.join("nodir"), tmp.root().join("dl")).expect("symlink");
	assert!(sb.write("dl/f.txt", b"pwn").is_err());
	assert!(!tmp.0.join("nodir").exists());
}

#[test]
fn symlink_dir_outside_is_rejected() {
	let tmp = TempRoot::new();
	let outside = tmp.0.join("out");
	fs::create_dir_all(&outside).expect("mkdir");
	std::os::unix::fs::symlink(&outside, tmp.root().join("escape")).expect("symlink");
	let sb = tmp.sandbox();
	assert!(sb.write("escape/f.txt", b"pwn").is_err());
	assert!(!outside.join("f.txt").exists());
}

#[test]
fn script_files_cannot_be_written_or_removed() {
	let tmp = TempRoot::new();
	fs::write(tmp.root().join("a.script.lua"), "x").expect("seed");
	let sb = tmp.sandbox();
	assert!(sb.write("evil.script.lua", b"x").is_err());
	assert!(sb.write("EVIL.SCRIPT.RHAI", b"x").is_err());
	assert!(sb.remove("a.script.lua").is_err());
	assert!(tmp.root().join("a.script.lua").exists());
	assert!(!tmp.root().join("evil.script.lua").exists());
}

#[test]
fn oversized_write_is_rejected() {
	let tmp = TempRoot::new();
	let sb = tmp.sandbox();
	let big = vec![0u8; MAX_WRITE_BYTES + 1];
	assert!(sb.write("big.bin", &big).is_err());
	assert!(!tmp.root().join("big.bin").exists());
}

#[test]
fn exists_outside_root_is_false() {
	let tmp = TempRoot::new();
	fs::write(tmp.0.join("secret"), "x").expect("seed");
	let sb = tmp.sandbox();
	assert!(!sb.exists("../secret"));
	assert!(!sb.exists("nope"));
}

#[test]
fn remove_deletes_regular_file_and_symlink_itself() {
	let tmp = TempRoot::new();
	let target = tmp.0.join("keep.txt");
	fs::write(&target, "x").expect("seed");
	std::os::unix::fs::symlink(&target, tmp.root().join("l")).expect("symlink");
	fs::write(tmp.root().join("f.txt"), "x").expect("seed");
	let sb = tmp.sandbox();
	sb.remove("f.txt").expect("remove file");
	sb.remove("l").expect("remove link");
	assert!(target.exists());
	assert!(!tmp.root().join("f.txt").exists());
}
