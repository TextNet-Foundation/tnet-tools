use super::*;

#[test]
fn insecure_utnp_keeps_original_host() {
	assert_eq!(
		choose_host("a.example", "evil.example", false, false),
		"a.example"
	);
}

#[test]
fn insecure_utnp_with_trust_flag_accepts_host() {
	assert_eq!(
		choose_host("a.example", "b.example", false, true),
		"b.example"
	);
}

#[test]
fn secure_utnp_accepts_announced_host() {
	assert_eq!(
		choose_host("a.example", "b.example", true, false),
		"b.example"
	);
}

#[test]
fn same_host_is_kept_case_insensitively() {
	assert_eq!(
		choose_host("A.example", "a.EXAMPLE", false, false),
		"A.example"
	);
}

#[test]
fn host_validation() {
	assert!(is_valid_host("example.org"));
	assert!(is_valid_host("2001:db8::1"));
	assert!(!is_valid_host(""));
	assert!(!is_valid_host("a\u{1b}[31m"));
	assert!(!is_valid_host("a/b"));
}

#[test]
fn security_header_is_parsed() {
	let response = "UTNP/2.0 START PROTOCOL tmutp 2.0 h 1\nSecurity: TLS, ssh\n\n";

	assert_eq!(parse_utnp_security(response), vec!["tls", "ssh"]);
}
