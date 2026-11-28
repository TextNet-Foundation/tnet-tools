use super::*;

const README_EXAMPLE: &str = r#"
port = 100
root = "./www"

[scripting]
enabled = true
lua_extension = ".script.lua"
rhai_extension = ".script.rhai"
order = ["lua", "rhai"]
hot_reload = true
hide_scripts_behind = true
"#;

#[test]
fn readme_example_parses_with_defaults() {
	let config: Config = toml::from_str(README_EXAMPLE).unwrap();
	assert_eq!(config.port, 100);
	assert_eq!(config.bind_address, "127.0.0.1");
	assert!(config.compression_cache_enable);
	assert_eq!(config.max_file_size, DEFAULT_MAX_FILE_SIZE);
}

#[test]
fn scripting_section_is_optional() {
	let config: Config = toml::from_str("port = 100\nroot = \"./www\"\n").unwrap();
	assert!(!config.scripting.enabled);
}

#[test]
fn typo_in_key_is_an_error() {
	let result: Result<Config, _> = toml::from_str("port = 100\nroot = \"./www\"\nportt = 1\n");
	assert!(result.is_err());

	let result: Result<Config, _> =
		toml::from_str("port = 100\nroot = \"./www\"\n[security]\nrequire_secur = true\n");
	assert!(result.is_err());
}

#[test]
fn normalized_rejects_bad_values_and_cache_inside_root() {
	let base = std::env::temp_dir().join(format!("tnet-tmutp-cfg-{}", std::process::id()));
	let root = base.join("www");
	std::fs::create_dir_all(&root).unwrap();
	let config_path = base.join("tmutp-config.toml");
	let config_path = config_path.to_str().unwrap();
	let root_str = root.to_str().unwrap();

	let parse = |extra: &str| -> Config {
		toml::from_str(&format!("port = 100\nroot = \"{root_str}\"\n{extra}")).unwrap()
	};

	let good = parse("").normalized(config_path).unwrap();
	assert!(std::path::Path::new(&good.compression_cache).is_absolute());
	assert!(!std::path::Path::new(&good.compression_cache).starts_with(&root));

	let inside = format!("compression_cache = \"{}/cache\"\n", root_str);
	assert!(parse(&inside).normalized(config_path).is_err());

	let mut zero = parse("");
	zero.port = 0;
	assert!(zero.normalized(config_path).is_err());

	let bad_ext = parse("[scripting]\nenabled = true\nlua_extension = \"lua\"\n");
	assert!(bad_ext.normalized(config_path).is_err());

	let bad_bind = parse("bind_address = \"nope\"\n");
	assert!(bad_bind.normalized(config_path).is_err());
	let _ = std::fs::remove_dir_all(base);
}

#[test]
fn limits_have_defaults_and_are_validated() {
	let config: Config = toml::from_str("port = 100\nroot = \"./www\"\n").unwrap();
	assert_eq!(config.max_connections, 256);
	assert_eq!(config.max_connections_per_ip, 32);
	assert_eq!(config.max_connection_secs, 3600);

	let base = std::env::temp_dir().join(format!("tnet-tmutp-lim-{}", std::process::id()));
	let root = base.join("www");
	std::fs::create_dir_all(&root).unwrap();
	let config_path = base.join("config.toml");
	let config_path = config_path.to_str().unwrap();

	for extra in [
		"max_connections = 0\n",
		"max_connections_per_ip = 0\n",
		"max_connection_secs = 0\n",
		"max_connections = 99999999\n",
	] {
		let text = format!("port = 100\nroot = \"{}\"\n{extra}", root.display());
		let config: Config = toml::from_str(&text).unwrap();
		assert!(config.normalized(config_path).is_err(), "{extra}");
	}
	let _ = std::fs::remove_dir_all(base);
}

#[test]
fn max_body_default_is_one_mib_and_validated() {
	assert_eq!(DEFAULT_MAX_BODY, 1024 * 1024);
	let config: Config = toml::from_str("port = 100\nroot = \"./www\"\n").unwrap();
	assert_eq!(config.max_body, DEFAULT_MAX_BODY);

	let base = std::env::temp_dir().join(format!("tnet-tmutp-body-{}", std::process::id()));
	let root = base.join("www");
	std::fs::create_dir_all(&root).unwrap();
	let config_path = base.join("config.toml");
	let config_path = config_path.to_str().unwrap();

	for value in ["0", "999999999999"] {
		let text = format!(
			"port = 100\nroot = \"{}\"\nmax_body = {value}\n",
			root.display()
		);
		assert!(Config::prepare(&text, config_path).is_err(), "{value}");
	}
	let ok = format!(
		"port = 100\nroot = \"{}\"\nmax_body = 4096\n",
		root.display()
	);
	assert_eq!(Config::prepare(&ok, config_path).unwrap().max_body, 4096);
	let _ = std::fs::remove_dir_all(base);
}

#[test]
fn prepare_runs_normalization() {
	let base = std::env::temp_dir().join(format!("tnet-tmutp-prep-{}", std::process::id()));
	let root = base.join("www");
	std::fs::create_dir_all(&root).unwrap();
	let config_path = base.join("tmutp-config.toml");
	let config_path = config_path.to_str().unwrap();

	let inside = format!(
		"port = 100\nroot = \"{r}\"\ncompression_cache = \"{r}/cache\"\n",
		r = root.display()
	);
	assert!(Config::prepare(&inside, config_path).is_err());
	assert!(Config::prepare("port = 0\nroot = \"x\"\n", config_path).is_err());

	let ok = format!("port = 100\nroot = \"{}\"\n", root.display());
	let config = Config::prepare(&ok, config_path).unwrap();
	assert!(std::path::Path::new(&config.compression_cache).is_absolute());
	let _ = std::fs::remove_dir_all(base);
}
