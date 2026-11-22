use std::fs;
use std::io;
use std::path::{Component, PathBuf};

pub fn validate_relative_path(path: &str) -> io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};

    let normalized = path.replace('\\', "/");
    let clean = normalized.trim_start_matches('/');

    let mut relative = PathBuf::new();

    for component in PathBuf::from(clean).components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "Absolute filesystem path is forbidden",
                ));
            }

            Component::CurDir => {}

            Component::ParentDir => {
                if !relative.pop() {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "Path escapes document root",
                    ));
                }
            }

            Component::Normal(part) => {
                relative.push(part);
            }
        }
    }

    Ok(relative)
}

pub fn resolve_path(root: &str, path: &str) -> io::Result<Option<PathBuf>> {
    use std::io::{Error, ErrorKind};

    let canonical_root = fs::canonicalize(root)?;

    let relative = validate_relative_path(path)?;

    if relative.as_os_str().is_empty() {
        return Ok(None);
    }

    let mut current = canonical_root.clone();
    let components: Vec<_> = relative.components().collect();

    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            continue;
        };

        current.push(part);

        match fs::symlink_metadata(&current) {
            Ok(_) => {
                let canonical = fs::canonicalize(&current)?;

                if !canonical.starts_with(&canonical_root) {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "Path escapes document root through a symlink",
                    ));
                }

                current = canonical;

                if index + 1 < components.len() && !current.is_dir() {
                    return Ok(None);
                }
            }

            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(None);
            }

            Err(error) => return Err(error),
        }
    }

    if current.is_file() {
        Ok(Some(current))
    } else {
        Ok(None)
    }
}

pub fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            raw.windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        })
}

pub fn percent_decode(value: &str) -> String {
    use percent_encoding::percent_decode_str;

    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

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
mod tests {
    use super::*;
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
        let r = resolve_path(root.to_str().unwrap(), "../../etc/passwd");
        assert!(r.is_err() || r.unwrap().is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_path_serves_existing_file() {
        let root = temp_root("file");
        let r = resolve_path(root.to_str().unwrap(), "hello.bin").unwrap();
        assert!(r.is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_path_missing_returns_none() {
        let root = temp_root("missing");
        let r = resolve_path(root.to_str().unwrap(), "nope.bin").unwrap();
        assert!(r.is_none());
        let _ = fs::remove_dir_all(&root);
    }
}
