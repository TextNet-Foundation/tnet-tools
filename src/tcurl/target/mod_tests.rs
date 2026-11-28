use super::*;

#[test]
fn ipv6_literal_has_no_brackets() {
	let target = parse_target("tmutp://[::1]/index").unwrap();

	assert_eq!(target.host, "::1");
	assert_eq!(target.direct_port, None);
	assert_eq!(target.path_query, "/index");
}

#[test]
fn ipv6_literal_with_direct_port() {
	let target = parse_target("tbip://[2001:db8::7]:8443/a?b=1").unwrap();

	assert_eq!(target.host, "2001:db8::7");
	assert_eq!(target.direct_port, Some(8443));
	assert_eq!(target.path_query, "/a?b=1");
}

#[test]
fn ipv6_literal_with_utnp_port() {
	let target = parse_target("tmutp://[::1]:u3400/x").unwrap();

	assert_eq!(target.host, "::1");
	assert_eq!(target.utnp_port, Some(3400));
	assert_eq!(target.direct_port, None);
}

#[test]
fn ipv6_host_is_a_valid_tls_ip_name() {
	use tokio_rustls::rustls::pki_types::ServerName;

	let target = parse_target("tmutp://[::1]/").unwrap();
	let name = ServerName::try_from(target.host).unwrap();

	assert!(matches!(name, ServerName::IpAddress(_)));
}

#[test]
fn plain_host_and_ports() {
	let target = parse_target("tmutp://example.org:99/").unwrap();
	assert_eq!(target.host, "example.org");
	assert_eq!(target.direct_port, Some(99));

	assert!(parse_target("tmutp://example.org:u0/").is_err());
	assert!(parse_target("tmutp://example.org:uabc/").is_err());
	assert!(parse_target("http://example.org/").is_err());
}
