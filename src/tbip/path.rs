pub fn mime_type(path: &std::path::Path) -> &'static str {
	match path
		.extension()
		.and_then(|ext| ext.to_str())
		.map(|ext| ext.to_ascii_lowercase())
		.as_deref()
	{
		Some("png") => "image/png",
		Some("jpg") | Some("jpeg") => "image/jpeg",
		Some("gif") => "image/gif",
		Some("webp") => "image/webp",
		Some("avif") => "image/avif",
		Some("apng") => "image/apng",
		Some("bmp") => "image/bmp",
		Some("ico") => "image/vnd.microsoft.icon",

		Some("mp3") => "audio/mpeg",
		Some("wav") => "audio/wav",
		Some("ogg") | Some("oga") => "audio/ogg",
		Some("aac") => "audio/aac",
		Some("m4a") => "audio/mp4",
		Some("mid") | Some("midi") => "audio/midi",
		Some("opus") => "audio/opus",
		Some("flac") => "audio/flac",

		Some("mp4") => "video/mp4",
		Some("webm") => "video/webm",
		Some("avi") => "video/x-msvideo",
		Some("mov") => "video/quicktime",
		Some("mkv") => "video/x-matroska",
		Some("m4v") => "video/x-m4v",
		Some("mpeg") | Some("mpg") => "video/mpeg",

		Some("pdf") => "application/pdf",

		Some("zip") => "application/zip",
		Some("gz") => "application/gzip",
		Some("bz") => "application/x-bzip",
		Some("bz2") => "application/x-bzip2",
		Some("xz") => "application/x-xz",
		Some("7z") => "application/x-7z-compressed",
		Some("rar") => "application/vnd.rar",
		Some("tar") => "application/x-tar",
		Some("zst") => "application/zstd",

		Some("wasm") => "application/wasm",
		Some("bin") => "application/octet-stream",
		Some("exe") => "application/vnd.microsoft.portable-executable",
		Some("apk") => "application/vnd.android.package-archive",
		Some("deb") => "application/vnd.debian.binary-package",
		Some("rpm") => "application/x-rpm",

		Some("woff") => "font/woff",
		Some("woff2") => "font/woff2",
		Some("ttf") => "font/ttf",
		Some("otf") => "font/otf",

		_ => "application/octet-stream",
	}
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
