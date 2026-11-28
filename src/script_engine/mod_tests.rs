use super::*;

#[test]
fn script_relative_appends_suffix_instead_of_replacing_extension() {
	assert_eq!(
		script_relative("/api.v2", ".script.lua"),
		"api.v2.script.lua"
	);
	assert_eq!(
		script_relative("/foo.html", ".script.lua"),
		"foo.html.script.lua"
	);
	assert_eq!(script_relative("/", ".script.lua"), "index.script.lua");
	assert_eq!(
		script_relative("/docs/", ".script.rhai"),
		"docs/index.script.rhai"
	);
}

#[test]
fn extension_validation_rejects_bad_values() {
	assert!(validate_extension("").is_err());
	assert!(validate_extension(".").is_err());
	assert!(validate_extension("script.lua").is_err());
	assert!(validate_extension(".a/b").is_err());
	assert!(validate_extension(".script.lua").is_ok());
}

#[test]
fn empty_extension_does_not_panic_in_engines() {
	assert!(lua::LuaEngine::try_new("/tmp", Some(String::new()), true).is_err());
	assert!(rhai::RhaiEngine::try_new("/tmp", Some(String::new()), true).is_err());
	// Инфаллибельный конструктор откатывается к значению по умолчанию.
	let engine = lua::LuaEngine::new("/tmp", Some(String::new()), true);
	assert!(!engine.has_script("/definitely-missing"));
}

#[test]
fn status_check_enforces_range() {
	assert_eq!(check_status(20), Ok(20));
	assert_eq!(check_status(55), Ok(55));
	assert!(check_status(19).is_err());
	assert!(check_status(56).is_err());
	assert!(check_status(65_556).is_err());
	assert!(check_status(-1).is_err());
}

#[test]
fn limits_use_defaults_and_overrides() {
	let defaults = ScriptingConfig::default().limits();
	assert_eq!(defaults.max_concurrent, DEFAULT_MAX_CONCURRENT);

	let config = ScriptingConfig {
		max_concurrent: Some(0),
		timeout_ms: Some(10),
		..ScriptingConfig::default()
	};
	let limits = config.limits();
	assert_eq!(limits.max_concurrent, 1);
	assert_eq!(limits.deadline, Duration::from_millis(10));
}
