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
	assert_eq!(
		sanitize_terminal("x\u{9b}y\u{7f}z\u{202e}w"),
		"x\\x9by\\x7fz\\u{202e}w"
	);
}

#[test]
fn newline_tab_cr_and_text_are_kept() {
	let text = "привет\tмир\r\nline2\n";

	assert_eq!(sanitize_terminal(text), text);
}
