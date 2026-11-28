use super::*;
use crate::target::parse_target;

#[test]
fn user_agent_carries_the_package_version() {
	let target = parse_target("tmutp://localhost/").unwrap();
	let request = build_request(&target, Method::Get, &[], &[], false, false).unwrap();
	let text = String::from_utf8(request).unwrap();
	let expected = format!("User-Agent: tcurl/{}\n", env!("CARGO_PKG_VERSION"));
	assert!(text.contains(&expected), "{text}");
}
