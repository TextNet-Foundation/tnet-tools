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
