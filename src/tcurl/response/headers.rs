/// Returns the numeric status of "TMUTP/2.0 20 OK".
pub fn status_code(header: &str) -> Option<u16> {
	header
		.lines()
		.next()?
		.split_whitespace()
		.nth(1)?
		.parse()
		.ok()
}

/// 2x statuses are success (20 OK, 22 OK EMPTY).
pub fn is_success(status: Option<u16>) -> bool {
	matches!(status, Some(20..=29))
}

pub fn header_value<'a>(header: &'a str, wanted: &str) -> Option<&'a str> {
	header
		.lines()
		.skip(1)
		.take_while(|line| !line.trim().is_empty())
		.find_map(|line| {
			let (name, value) = line.split_once(':')?;

			name.trim()
				.eq_ignore_ascii_case(wanted)
				.then(|| value.trim())
		})
}
