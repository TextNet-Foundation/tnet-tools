use super::*;

#[test]
fn parses_simple_get() {
	let raw = b"TMUTP/2.0 GET /index.tmkup\nHost: localhost\n\n";
	match parse_request(raw, 1024) {
		ParseResult::Ok(req) => {
			assert_eq!(req.version, "TMUTP/2.0");
			assert_eq!(req.method, "GET");
			assert_eq!(req.path, "/index.tmkup");
			assert_eq!(req.content_length, 0);
			assert!(req.body.is_empty());
			assert_eq!(
				req.headers.get("host").map(String::as_str),
				Some("localhost")
			);
		}
		other => panic!("expected Ok, got {other:?}"),
	}
}

#[test]
fn parses_post_with_body_and_query() {
	let raw = b"TMUTP/2.0 POST /submit?a=1&b=2\nContent-Length: 7\n\nfoo=bar";
	match parse_request(raw, 1024) {
		ParseResult::Ok(req) => {
			assert_eq!(req.method, "POST");
			assert_eq!(req.path, "/submit");
			assert_eq!(req.query.get("a").map(String::as_str), Some("1"));
			assert_eq!(req.query.get("b").map(String::as_str), Some("2"));
			assert_eq!(req.content_length, 7);
			assert_eq!(req.body, b"foo=bar");
		}
		other => panic!("expected Ok, got {other:?}"),
	}
}

#[test]
fn rejects_incomplete_headers() {
	let raw = b"TMUTP/2.0 GET /\nHost: x\n";
	assert!(matches!(
		parse_request(raw, 1024),
		ParseResult::BadRequest(_)
	));
}

#[test]
fn rejects_traversal() {
	let raw = b"TMUTP/2.0 GET /../etc/passwd\n\n";
	assert!(matches!(parse_request(raw, 1024), ParseResult::Forbidden));
}

#[test]
fn rejects_body_over_limit() {
	let raw = b"TMUTP/2.0 POST /\nContent-Length: 100\n\n";
	assert!(matches!(parse_request(raw, 10), ParseResult::BadRequest(_)));
}

#[test]
fn rejects_conflicting_content_length() {
	let raw = b"TMUTP/2.0 POST /\nContent-Length: 5\nContent-Length: 10\n\n";
	assert!(matches!(
		parse_request(raw, 1024),
		ParseResult::BadRequest(_)
	));
}

#[test]
fn parse_fields_caps_count() {
	let input: String = (0..300)
		.map(|i| format!("k{i}=v"))
		.collect::<Vec<_>>()
		.join("&");
	assert!(parse_fields(&input).is_none());
	assert!(parse_fields("a=1&b=2").is_some());
}
