use super::*;

#[cfg(unix)]
#[tokio::test]
async fn key_permissions_are_checked() {
	use std::os::unix::fs::PermissionsExt;

	let path = std::env::temp_dir().join(format!("utnp-key-{}", std::process::id()));
	std::fs::write(&path, b"key").unwrap();
	let name = path.to_str().unwrap();

	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(check_key_permissions(name, true).await.is_err());
	assert!(check_key_permissions(name, false).await.is_ok());

	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	assert!(check_key_permissions(name, true).await.is_ok());

	let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn missing_key_is_an_error_on_unix() {
	if cfg!(unix) {
		assert!(
			check_key_permissions("/nonexistent/utnp-key", false)
				.await
				.is_err()
		);
	}
}

#[test]
fn strict_key_permissions_default_to_true() {
	assert!(SecurityConfig::default().strict_key_permissions);
	let parsed: SecurityConfig = toml::from_str("require_secure = true").unwrap();
	assert!(parsed.strict_key_permissions);
	let relaxed: SecurityConfig = toml::from_str("strict_key_permissions = false").unwrap();
	assert!(!relaxed.strict_key_permissions);
}
