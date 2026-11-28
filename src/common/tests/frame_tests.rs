use super::*;

const DEFAULT_MAX_BODY: usize = 16 * 1024 * 1024;

fn poll_all(data: &[u8], max_body: usize) -> Frame {
	FrameParser::new(max_body).poll(data)
}

#[test]
fn header_end_lf_and_crlf() {
	assert_eq!(find_header_end(b"GET / TMUTP/2.0\n\n"), Some(17));
	assert_eq!(find_header_end(b"GET / TMUTP/2.0\r\n\r\n"), Some(19));
	assert_eq!(find_header_end(b"GET / TMUTP/2.0\n"), None);
	assert_eq!(find_header_end(b""), None);
}

#[test]
fn header_end_picks_earliest_terminator() {
	assert_eq!(find_header_end(b"A\n\nB\r\n\r\n"), Some(3));
	assert_eq!(find_header_end(b"A\r\n\r\nB\n\n"), Some(5));
}

#[test]
fn mixed_endings() {
	assert_eq!(find_header_end(b"A\nH: v\r\n\r\n"), Some(10));
	assert_eq!(find_header_end(b"A\r\nH: v\n\r\n"), Some(10));
	assert_eq!(find_header_end(b"A\r\n\n"), Some(4));
}

#[test]
fn whitespace_line_is_not_a_terminator_for_find() {
	assert_eq!(find_header_end(b"A\n  \nB\n\n"), Some(8));
}

#[test]
fn whitespace_line_is_rejected_by_framing() {
	let data = b"POST / TMUTP/2.0\nContent-Length: 3\n   \nabc";
	// строки из пробелов нет в терминаторах, но кадр содержит пустую строку позже
	assert_eq!(
		poll_all(data, 100),
		Frame::Incomplete,
		"no terminator yet means wait"
	);

	let data = b"POST / TMUTP/2.0\nContent-Length: 3\n   \n\nabc";
	assert_eq!(
		poll_all(data, 100),
		Frame::Invalid(FrameError::MalformedHeaders)
	);
}

#[test]
fn two_requests_in_one_buffer() {
	let first = b"GET /a TMUTP/2.0\n\n";
	let mut data = first.to_vec();
	data.extend_from_slice(b"GET /b TMUTP/2.0\n\n");

	let mut parser = FrameParser::new(100);
	assert_eq!(parser.poll(&data), Frame::Complete(first.len()));

	data.drain(..first.len());
	parser.reset();
	assert_eq!(parser.poll(&data), Frame::Complete(data.len()));
}

#[test]
fn crlfcrlf_inside_body_is_body() {
	let head = b"POST /f TMUTP/2.0\nContent-Length: 10\n\n";
	let mut data = head.to_vec();
	data.extend_from_slice(b"a\r\n\r\nbcdef");

	assert_eq!(data.len(), head.len() + 10);
	assert_eq!(poll_all(&data, 100), Frame::Complete(data.len()));
	assert_eq!(find_header_end(&data), Some(head.len()));
}

#[test]
fn body_incomplete_until_full() {
	let data = b"POST /f TMUTP/2.0\nContent-Length: 5\n\nabc";
	let mut parser = FrameParser::new(100);
	assert_eq!(parser.idle_timeout(), HEADER_IDLE);

	assert_eq!(parser.poll(data), Frame::Incomplete);
	assert_eq!(parser.idle_timeout(), BODY_IDLE);

	let mut full = data.to_vec();
	full.extend_from_slice(b"de");
	assert_eq!(parser.poll(&full), Frame::Complete(full.len()));
}

#[test]
fn huge_content_length_rejected_before_body() {
	let data = b"POST /f TMUTP/2.0\nContent-Length: 99999999999999999999\n\n";
	assert_eq!(
		poll_all(data, DEFAULT_MAX_BODY),
		Frame::Invalid(FrameError::InvalidContentLength)
	);

	let data = b"POST /f TMUTP/2.0\nContent-Length: 17000000\n\n";
	assert_eq!(
		poll_all(data, DEFAULT_MAX_BODY),
		Frame::Invalid(FrameError::BodyTooLarge)
	);

	let data = format!("POST /f TMUTP/2.0\nContent-Length: {}\n\n", usize::MAX);
	assert_eq!(
		poll_all(data.as_bytes(), usize::MAX),
		Frame::Invalid(FrameError::BodyTooLarge)
	);
}

#[test]
fn content_length_boundaries() {
	let data = b"POST /f TMUTP/2.0\nContent-Length: 4\n\n";
	assert_eq!(poll_all(data, 4), Frame::Incomplete);
	assert_eq!(poll_all(data, 3), Frame::Invalid(FrameError::BodyTooLarge));

	let zero = b"GET / TMUTP/2.0\nContent-Length: 0\n\n";
	assert_eq!(poll_all(zero, 0), Frame::Complete(zero.len()));
}

#[test]
fn conflicting_content_length_rejected() {
	let data = b"POST / TMUTP/2.0\nContent-Length: 1\ncontent-length: 2\n\n";
	assert_eq!(
		poll_all(data, 10),
		Frame::Invalid(FrameError::InvalidContentLength)
	);

	let same = b"POST / TMUTP/2.0\nContent-Length: 1\ncontent-length: 1\n\nx";
	assert_eq!(poll_all(same, 10), Frame::Complete(same.len()));
}

#[test]
fn header_size_limit_boundaries() {
	let mut data = b"GET / TMUTP/2.0\n".to_vec();
	data.resize(MAX_HEADER_BYTES, b'a');
	assert_eq!(poll_all(&data, 0), Frame::Incomplete);

	data.push(b'a');
	assert_eq!(
		poll_all(&data, 0),
		Frame::Invalid(FrameError::HeadersTooLarge)
	);

	let mut exact = b"GET / TMUTP/2.0\n".to_vec();
	exact.resize(MAX_HEADER_BYTES - 2, b'a');
	exact.extend_from_slice(b"\n\n");
	assert_eq!(poll_all(&exact, 0), Frame::Complete(MAX_HEADER_BYTES));

	let mut over = b"GET / TMUTP/2.0\n".to_vec();
	over.resize(MAX_HEADER_BYTES - 1, b'a');
	over.extend_from_slice(b"\n\n");
	assert_eq!(
		poll_all(&over, 0),
		Frame::Invalid(FrameError::HeadersTooLarge)
	);
}

#[test]
fn byte_by_byte_matches_whole_buffer() {
	let data = b"POST /f TMUTP/2.0\r\nContent-Length: 4\r\n\r\n\r\n\r\n";
	let mut parser = FrameParser::new(100);

	for len in 1..data.len() {
		assert_eq!(parser.poll(&data[..len]), Frame::Incomplete, "len {len}");
	}

	assert_eq!(parser.poll(data), Frame::Complete(data.len()));
}

#[test]
fn split_terminator_across_chunks() {
	let mut parser = FrameParser::new(0);
	assert_eq!(parser.poll(b"GET / TBIP/2.0\r\n\r"), Frame::Incomplete);
	assert_eq!(parser.poll(b"GET / TBIP/2.0\r\n\r\n"), Frame::Complete(18));
}

#[test]
fn transfer_encoding_is_rejected_before_the_body() {
	for name in [
		"Transfer-Encoding",
		"transfer-encoding",
		"TRANSFER-ENCODING",
		" Transfer-Encoding ",
	] {
		let data = format!("POST / TMUTP/2.0\nContent-Length: 5\n{name}: chunked\n\n");
		assert_eq!(
			poll_all(data.as_bytes(), 100),
			Frame::Invalid(FrameError::TransferEncodingUnsupported),
			"{name}"
		);
	}

	let alone = b"POST / TMUTP/2.0\r\nTransfer-Encoding: chunked\r\n\r\n";
	assert_eq!(
		poll_all(alone, 100),
		Frame::Invalid(FrameError::TransferEncodingUnsupported)
	);
	assert!(!FrameError::TransferEncodingUnsupported.message().is_empty());
}
