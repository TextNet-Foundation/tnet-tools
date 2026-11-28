use super::*;

#[test]
fn escape_sequences_are_neutralised() {
	let clean = sanitize_terminal("a\u{1b}]0;title\u{7}b\u{1b}[2Jc");

	assert!(!clean.contains('\u{1b}'));
	assert!(!clean.contains('\u{7}'));
	assert!(clean.contains("\\x1b"));
}

#[test]
fn c1_del_and_bidi_are_escaped() {
	let clean = sanitize_terminal("x\u{9b}y\u{7f}z\u{202e}w");

	assert_eq!(clean, "x\\x9by\\x7fz\\u{202e}w");
}

#[test]
fn newline_tab_cr_and_text_are_kept() {
	let text = "привет\tмир\r\nline2\n";

	assert_eq!(sanitize_terminal(text), text);
}

#[test]
fn files_and_pipes_are_not_filtered() {
	let body = b"\x1b[31mred\x00\xff";
	let (out, changed) = render_body(body, false);

	assert_eq!(&*out, body);
	assert!(!changed);
}

#[test]
fn terminal_body_is_filtered_and_reported() {
	let (out, changed) = render_body(b"hi\x1b[2J", true);

	assert!(changed);
	assert!(!out.contains(&0x1b));

	let (_, changed) = render_body(b"plain\n", true);
	assert!(!changed);
}
