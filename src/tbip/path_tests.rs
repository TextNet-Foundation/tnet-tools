use std::fs;
fn temp_root(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tnet-tbip-test-{}", name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("index.tmkup"), b"idx").unwrap();
    fs::write(dir.join("hello.bin"), b"hi").unwrap();
    dir
}

#[test]
fn resolve_path_blocks_traversal() {
    let root = temp_root("trav");
    let r = crate::common::resolve_path(root.to_str().unwrap(), "../../etc/passwd");
    assert!(r.is_err() || r.unwrap().is_none());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_path_serves_existing_file() {
    let root = temp_root("file");
    let r = crate::common::resolve_path(root.to_str().unwrap(), "hello.bin").unwrap();
    assert!(r.is_some());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_path_missing_returns_none() {
    let root = temp_root("missing");
    let r = crate::common::resolve_path(root.to_str().unwrap(), "nope.bin").unwrap();
    assert!(r.is_none());
    let _ = fs::remove_dir_all(&root);
}
