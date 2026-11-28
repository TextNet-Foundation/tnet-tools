use super::*;

#[test]
fn parse_range_forms() {
	assert!(matches!(
		parse_range("bytes=0-9"),
		RangeParseResult::Valid(0, 9)
	));
	assert!(matches!(
		parse_range("bytes=9-0"),
		RangeParseResult::Invalid(_)
	));
	assert!(matches!(
		parse_range("items=0-9"),
		RangeParseResult::Unsupported(_)
	));
	assert!(matches!(
		parse_range("bytes=0-1,4-5"),
		RangeParseResult::Unsupported(_)
	));
	assert!(matches!(
		parse_range("bytes=x-1"),
		RangeParseResult::Invalid(_)
	));
}

#[test]
fn range_error_mentions_reason_and_length() {
	let response = make_range_error_response(
		RANGE_NOT_SATISFIABLE,
		"outside-source",
		"bytes=5-9",
		Some(3),
	);
	let text = String::from_utf8(response).unwrap();
	assert!(text.contains("SOURCE-CONTENT-LENGTH: 3"));
	assert!(text.contains("Range-Error: bytes=5-9; outside-source"));
}

#[test]
fn range_error_header_is_sanitized() {
	let hostile = format!("bytes=\r\nSet-Cookie: x\n\0{}", "a".repeat(500));
	let response = make_range_error_response(INVALID_RANGE, "invalid-range", &hostile, Some(3));
	let end = response.windows(2).position(|w| w == b"\n\n").unwrap();
	let head = std::str::from_utf8(&response[..end]).unwrap();
	assert!(!head.contains('\r') && !head.contains('\0'));
	assert!(head.lines().all(|line| !line.starts_with("Set-Cookie")));
	let line = head
		.lines()
		.find(|l| l.starts_with("Range-Error: "))
		.unwrap();
	assert!(line.len() < 260);
}
