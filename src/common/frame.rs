//! Единый разбор границ запроса TMUTP/TBIP.
//!
//! Конец заголовков — первая пустая строка (`\n\n`, `\r\n\r\n` или их смесь).
//! Фрейминг соединения и разбор запроса (`find_header_end`) используют одну и ту же
//! функцию, поэтому границы запросов не расходятся (нет склейки/расщепления запросов).

use std::borrow::Cow;
use std::time::Duration;

/// Максимальный размер блока заголовков.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Максимальный размер тела по умолчанию (используется TMUTP; TBIP передаёт 0).
#[allow(dead_code)]
pub const DEFAULT_MAX_BODY: usize = 16 * 1024 * 1024;

/// Простой соединения в ожидании заголовков запроса.
pub const HEADER_IDLE: Duration = Duration::from_secs(15);

/// Простой при чтении тела запроса.
pub const BODY_IDLE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
	HeadersTooLarge,
	MalformedHeaders,
	InvalidContentLength,
	BodyTooLarge,
}

impl FrameError {
	pub fn message(self) -> &'static str {
		match self {
			Self::HeadersTooLarge => "Request headers exceed the server limit",
			Self::MalformedHeaders => "Request headers are malformed",
			Self::InvalidContentLength => "Invalid Content-Length header",
			Self::BodyTooLarge => "Request body exceeds the server limit",
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
	/// Нужно больше данных.
	Incomplete,
	/// Запрос целиком занимает первые N байт буфера.
	Complete(usize),
	/// Запрос недопустим: ответить 30 и закрыть соединение.
	Invalid(FrameError),
}

/// Позиция конца самого раннего терминатора заголовков.
pub fn find_header_end(raw: &[u8]) -> Option<usize> {
	scan_end(raw, 0)
}

/// Ищет терминатор среди `\n`, лежащих на позициях `>= from`.
/// Просмотренные ранее строки повторно не сканируются.
fn scan_end(buf: &[u8], from: usize) -> Option<usize> {
	let mut index = from;

	loop {
		let tail = buf.get(index..)?;
		let newline = index + tail.iter().position(|byte| *byte == b'\n')?;

		if ends_blank_line(buf, newline) {
			return Some(newline + 1);
		}

		index = newline + 1;
	}
}

/// `\n` на позиции `newline` завершает пустую строку (первая строка не считается).
fn ends_blank_line(buf: &[u8], newline: usize) -> bool {
	let mut start = newline;

	if start > 0 && buf[start - 1] == b'\r' {
		start -= 1;
	}

	start > 0 && buf[start - 1] == b'\n'
}

fn header_lines(block: &[u8]) -> impl Iterator<Item = Cow<'_, str>> {
	block
		.split(|byte| *byte == b'\n')
		.skip(1)
		.map(String::from_utf8_lossy)
}

/// Проверяет заголовки и возвращает Content-Length (0, если не задан).
fn parse_headers(block: &[u8], max_body: usize) -> Result<usize, FrameError> {
	let mut content_length: Option<usize> = None;

	for line in header_lines(block) {
		let line = line.trim_end_matches('\r');
		let trimmed = line.trim();

		// Обработчик считает строку из пробелов концом заголовков, а фрейминг нет:
		// такое расхождение позволяет спрятать второй запрос в теле.
		if trimmed.is_empty() && !line.is_empty() {
			return Err(FrameError::MalformedHeaders);
		}

		let Some((key, value)) = trimmed.split_once(':') else {
			continue;
		};

		if !key.trim().eq_ignore_ascii_case("content-length") {
			continue;
		}

		let value = value
			.trim()
			.parse::<usize>()
			.map_err(|_| FrameError::InvalidContentLength)?;

		if content_length.is_some_and(|previous| previous != value) {
			return Err(FrameError::InvalidContentLength);
		}

		content_length = Some(value);
	}

	let length = content_length.unwrap_or(0);

	if length > max_body {
		return Err(FrameError::BodyTooLarge);
	}

	Ok(length)
}

/// Инкрементальный разборщик кадров одного соединения/канала.
#[derive(Debug)]
pub struct FrameParser {
	max_body: usize,
	scanned: usize,
	header: Option<(usize, usize)>,
}

impl FrameParser {
	pub fn new(max_body: usize) -> Self {
		Self {
			max_body,
			scanned: 0,
			header: None,
		}
	}

	/// Допустимый простой чтения в текущей фазе (заголовки или тело).
	pub fn idle_timeout(&self) -> Duration {
		if self.header.is_some() {
			BODY_IDLE
		} else {
			HEADER_IDLE
		}
	}

	/// Сбросить состояние после удаления кадра из буфера.
	pub fn reset(&mut self) {
		self.scanned = 0;
		self.header = None;
	}

	/// Проверяет буфер; вызывать после каждого дописывания данных.
	pub fn poll(&mut self, buf: &[u8]) -> Frame {
		if self.header.is_none() {
			let Some(end) = scan_end(buf, self.scanned) else {
				self.scanned = buf.len();

				return if buf.len() > MAX_HEADER_BYTES {
					Frame::Invalid(FrameError::HeadersTooLarge)
				} else {
					Frame::Incomplete
				};
			};

			if end > MAX_HEADER_BYTES {
				return Frame::Invalid(FrameError::HeadersTooLarge);
			}

			match parse_headers(&buf[..end], self.max_body) {
				Ok(length) => self.header = Some((end, length)),
				Err(error) => return Frame::Invalid(error),
			}
		}

		match self.header {
			Some((end, length)) => match end.checked_add(length) {
				Some(total) if buf.len() >= total => Frame::Complete(total),
				Some(_) => Frame::Incomplete,
				None => Frame::Invalid(FrameError::BodyTooLarge),
			},
			None => Frame::Incomplete,
		}
	}
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
