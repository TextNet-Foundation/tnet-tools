use super::*;

/// The first TOML block of the README section starting with `heading`.
fn readme_example(heading: &str) -> &'static str {
	let readme = include_str!("../../README.md");
	let (_, section) = readme.split_once(heading).unwrap();
	let (_, block) = section.split_once("```toml\n").unwrap();
	block.split_once("```").unwrap().0
}

#[test]
fn readme_utnp_example_is_a_valid_config() {
	let config: Config = toml::from_str(readme_example("### UTNP\n")).unwrap();
	validate_protocols(&config.protocols).unwrap();
	assert_eq!(config.protocols.len(), 2);
}
