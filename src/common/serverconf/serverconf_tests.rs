use super::*;

#[test]
fn relative_cache_dir_is_resolved_against_config_dir_not_root() {
	let base = std::env::temp_dir().join(format!("tnet-sc-{}", std::process::id()));
	let root = base.join("www");
	std::fs::create_dir_all(&root).unwrap();
	let config = base.join("server.toml");

	let dir = resolve_cache_dir("./compression_cache", &config, &root).unwrap();
	assert_eq!(
		dir,
		std::fs::canonicalize(&base)
			.unwrap()
			.join("compression_cache")
	);
	assert!(!dir.starts_with(std::fs::canonicalize(&root).unwrap()));
	let _ = std::fs::remove_dir_all(base);
}

#[test]
fn cache_dir_inside_root_is_refused() {
	let base = std::env::temp_dir().join(format!("tnet-sc-in-{}", std::process::id()));
	let root = base.join("www");
	std::fs::create_dir_all(&root).unwrap();
	let config = base.join("server.toml");

	let inside = root.join("cache");
	assert!(resolve_cache_dir(inside.to_str().unwrap(), &config, &root).is_err());
	assert!(resolve_cache_dir("www/cache", &config, &root).is_err());
	assert!(resolve_cache_dir("www/../www/cache", &config, &root).is_err());
	assert!(resolve_cache_dir("www", &config, &root).is_err());
	assert!(resolve_cache_dir("../elsewhere", &config, &root).is_ok());
	let _ = std::fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn cache_dir_is_created_private() {
	use std::os::unix::fs::PermissionsExt;

	let base = std::env::temp_dir().join(format!("tnet-sc-mode-{}", std::process::id()));
	let dir = base.join("cache");
	prepare_cache_dir(&dir).unwrap();
	assert_eq!(
		std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
		0o700
	);
	let _ = std::fs::remove_dir_all(base);
}

#[test]
fn validators() {
	assert!(validate_port(0).is_err());
	assert!(validate_port(100).is_ok());
	assert!(validate_bind_address("127.0.0.1").is_ok());
	assert!(validate_bind_address("::").is_ok());
	assert!(validate_bind_address("not-an-ip").is_err());
	assert!(validate_script_extensions(&[("lua_extension", Some(".script.lua"))]).is_ok());
	assert!(validate_script_extensions(&[("lua_extension", Some("lua"))]).is_err());
	assert!(validate_script_extensions(&[("lua_extension", Some("."))]).is_err());
	assert!(validate_script_extensions(&[("lua_extension", None)]).is_ok());
}

#[test]
fn security_rejects_unknown_keys() {
	let ok: Result<SecurityConfig, _> = toml::from_str("require_secure = true");
	assert!(ok.is_ok());
	let typo: Result<SecurityConfig, _> = toml::from_str("requre_secure = true");
	assert!(typo.is_err());
}

#[test]
fn limits_are_validated() {
	assert!(validate_limits(256, 32, 3600).is_ok());
	assert!(validate_limits(0, 32, 3600).is_err());
	assert!(validate_limits(256, 0, 3600).is_err());
	assert!(validate_limits(256, 32, 0).is_err());
	assert!(validate_limits(10_000_000, 32, 3600).is_err());
	assert!(validate_limits(256, 32, u64::MAX).is_err());
}

#[test]
fn strict_key_permissions_default_to_true() {
	assert!(SecurityConfig::default().strict_key_permissions);
	let parsed: SecurityConfig = toml::from_str("require_secure = true").unwrap();
	assert!(parsed.strict_key_permissions);
}

#[cfg(unix)]
#[test]
fn exposed_key_is_refused_when_strict() {
	use std::os::unix::fs::PermissionsExt;

	let path = std::env::temp_dir().join(format!("tnet-sc-key-{}", std::process::id()));
	std::fs::write(&path, b"key").unwrap();

	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(check_key_permissions(&path, "test key", true).is_err());
	assert!(check_key_permissions(&path, "test key", false).is_ok());

	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	assert!(check_key_permissions(&path, "test key", true).is_ok());
	let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn load_ssh_config_refuses_world_readable_host_key_by_default() {
	use std::os::unix::fs::PermissionsExt;

	let path = std::env::temp_dir().join(format!("tnet-sc-ssh-{}", std::process::id()));
	std::fs::write(&path, b"not a key").unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

	let security = SecurityConfig {
		ssh_host_key_path: path.to_string_lossy().into_owned(),
		..SecurityConfig::default()
	};
	let error = load_ssh_config(&security).unwrap_err().to_string();
	assert!(error.contains("insecure permissions"), "{error}");
	let _ = std::fs::remove_file(path);
}
