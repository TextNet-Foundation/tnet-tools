use super::*;

fn poll(data: &[u8]) -> FrameStatus {
	Framer::new().poll(data)
}

#[test]
fn v2_ends_on_blank_line() {
	assert_eq!(poll(b"UTNP/2.0 LIST\n\n"), FrameStatus::Complete(15));
	assert_eq!(poll(b"UTNP/2.0 LIST\r\n\r\n"), FrameStatus::Complete(17));
	assert_eq!(poll(b"UTNP/2.0 LIST\n"), FrameStatus::Incomplete);
}

#[test]
fn legacy_is_single_line() {
	assert_eq!(poll(b"UTNP/1.0 LIST\n"), FrameStatus::Complete(14));
	assert_eq!(poll(b"UTNP/1.0 LIST\r\nrest"), FrameStatus::Complete(15));
	// trailing space is not trimmed away: same rule everywhere
	assert_eq!(poll(b"UTNP/1.0 \n"), FrameStatus::Complete(10));
}

#[test]
fn two_frames_in_buffer() {
	let mut framer = Framer::new();
	let data = b"UTNP/2.0 LIST\n\nUTNP/2.0 EXPLORE\n\n";

	assert_eq!(framer.poll(data), FrameStatus::Complete(15));
	framer.reset();
	assert_eq!(framer.poll(&data[15..]), FrameStatus::Complete(18));
}

#[test]
fn invalid_utf8_is_an_error() {
	assert_eq!(
		poll(b"UTNP/2.0 LIST\nX: \xff\xfe\n\n"),
		FrameStatus::Invalid("Request is not valid UTF-8")
	);
	assert_eq!(
		poll(b"\xff\xfe\n"),
		FrameStatus::Invalid("Request is not valid UTF-8")
	);
}

#[test]
fn line_length_limit() {
	let mut ok = b"UTNP/2.0 LIST\nX: ".to_vec();
	ok.resize(14 + MAX_LINE_BYTES - 1, b'a');
	ok.extend_from_slice(b"\n\n");
	assert_eq!(poll(&ok), FrameStatus::Complete(ok.len()));

	let mut long = b"UTNP/2.0 LIST\nX: ".to_vec();
	long.resize(14 + MAX_LINE_BYTES + 1, b'a');
	assert_eq!(poll(&long), FrameStatus::Invalid("Line too long"));

	long.push(b'\n');
	assert_eq!(poll(&long), FrameStatus::Invalid("Line too long"));
}

#[test]
fn header_count_limit() {
	let mut data = b"UTNP/2.0 LIST\n".to_vec();
	for _ in 0..MAX_HEADERS {
		data.extend_from_slice(b"A: b\n");
	}
	let mut with_end = data.clone();
	with_end.push(b'\n');
	assert_eq!(poll(&with_end), FrameStatus::Complete(with_end.len()));

	data.extend_from_slice(b"A: b\n");
	assert_eq!(poll(&data), FrameStatus::Invalid("Too many headers"));
}

#[test]
fn total_size_limit() {
	let mut data = b"UTNP/2.0 LIST\n".to_vec();

	while data.len() <= MAX_FRAME_BYTES {
		data.extend_from_slice(&[b'a'; 1000]);
		data.push(b'\n');
	}

	assert!(matches!(poll(&data), FrameStatus::Invalid(_)));
}

#[test]
fn incremental_matches_whole_buffer() {
	let data = b"UTNP/2.0 NEGOTIATE x\nSupported-Versions: 1\r\n\r\n";
	let mut framer = Framer::new();

	for len in 1..data.len() {
		assert_eq!(
			framer.poll(&data[..len]),
			FrameStatus::Incomplete,
			"len {len}"
		);
	}

	assert_eq!(framer.poll(data), FrameStatus::Complete(data.len()));
}
