use std::borrow::Cow;

/// Replaces terminal control characters with visible escapes so that a
/// server cannot move the cursor, change the title or fake output.
///
/// Newline, tab and carriage return are kept. Everything else in C0, DEL,
/// C1 (U+0080..U+009F) and the invisible line/bidi controls is escaped.
pub fn sanitize_terminal(input: &str) -> String {
	let mut output = String::with_capacity(input.len());

	for ch in input.chars() {
		if matches!(ch, '\n' | '\t' | '\r') || !is_dangerous(ch) {
			output.push(ch);
		} else if (ch as u32) < 0x100 {
			output.push_str(&format!("\\x{:02x}", ch as u32));
		} else {
			output.push_str(&format!("\\u{{{:x}}}", ch as u32));
		}
	}

	output
}

fn is_dangerous(ch: char) -> bool {
	ch.is_control()
		|| matches!(
			ch,
			'\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
		)
}

/// Prepares a response body for output. Files and pipes get the bytes
/// untouched; a terminal gets the sanitized text. The flag tells whether
/// anything was changed or the body is not valid UTF-8.
pub fn render_body(body: &[u8], is_terminal: bool) -> (Cow<'_, [u8]>, bool) {
	if !is_terminal {
		return (Cow::Borrowed(body), false);
	}

	let text = String::from_utf8_lossy(body);
	let clean = sanitize_terminal(&text);
	let changed = clean != text;

	(Cow::Owned(clean.into_bytes()), changed)
}

#[cfg(test)]
#[path = "sanitize_tests.rs"]
mod tests;
