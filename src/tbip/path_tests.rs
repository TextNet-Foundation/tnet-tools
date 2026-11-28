use super::mime_type;
use std::path::Path;

#[test]
fn mime_type_known_extensions() {
	assert_eq!(mime_type(Path::new("a.png")), "image/png");
	assert_eq!(mime_type(Path::new("a.JPG")), "image/jpeg");
	assert_eq!(mime_type(Path::new("a.woff2")), "font/woff2");
}

#[test]
fn mime_type_unknown_falls_back_to_octet_stream() {
	assert_eq!(
		mime_type(Path::new("a.unknown")),
		"application/octet-stream"
	);
	assert_eq!(mime_type(Path::new("noext")), "application/octet-stream");
}
