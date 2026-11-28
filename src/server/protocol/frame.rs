//! Единое правило фрейминга UTNP для plain/TLS и SSH.
//!
//! Запрос — первая строка плюс заголовки до пустой строки; запрос `UTNP/1.0 ...`
//! состоит из одной строки. Пустая строка определяется так же, как в
//! `process_request` (после `\n` отбрасываются все `\r`). Каждая строка должна быть
//! корректным UTF-8, а размеры ограничены.

/// Максимальная длина строки вместе с терминатором.
pub const MAX_LINE_BYTES: usize = 16 * 1024;
/// Максимальное число строк заголовков.
pub const MAX_HEADERS: usize = 64;
/// Максимальный размер запроса целиком.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStatus {
	Incomplete,
	Complete(usize),
	Invalid(&'static str),
}

#[derive(Debug, Default)]
pub struct Framer {
	line_start: usize,
	searched: usize,
	headers: usize,
	first_done: bool,
}

impl Framer {
	pub fn new() -> Self {
		Self::default()
	}

	/// Сброс после удаления кадра из буфера.
	pub fn reset(&mut self) {
		*self = Self::default();
	}

	pub fn poll(&mut self, buffer: &[u8]) -> FrameStatus {
		loop {
			let Some(tail) = buffer.get(self.searched..) else {
				return FrameStatus::Incomplete;
			};

			let Some(offset) = tail.iter().position(|byte| *byte == b'\n') else {
				self.searched = buffer.len();

				return if buffer.len() - self.line_start > MAX_LINE_BYTES {
					FrameStatus::Invalid("Line too long")
				} else if buffer.len() > MAX_FRAME_BYTES {
					FrameStatus::Invalid("Request too large")
				} else {
					FrameStatus::Incomplete
				};
			};

			let end = self.searched + offset + 1;

			if end - self.line_start > MAX_LINE_BYTES {
				return FrameStatus::Invalid("Line too long");
			}

			if end > MAX_FRAME_BYTES {
				return FrameStatus::Invalid("Request too large");
			}

			let Ok(line) = std::str::from_utf8(&buffer[self.line_start..end]) else {
				return FrameStatus::Invalid("Request is not valid UTF-8");
			};

			let content = line
				.strip_suffix('\n')
				.unwrap_or(line)
				.trim_end_matches('\r');

			if !self.first_done {
				if content.starts_with("UTNP/1.0 ") {
					return FrameStatus::Complete(end);
				}

				self.first_done = true;
			} else if content.is_empty() {
				return FrameStatus::Complete(end);
			} else {
				self.headers += 1;

				if self.headers > MAX_HEADERS {
					return FrameStatus::Invalid("Too many headers");
				}
			}

			self.line_start = end;
			self.searched = end;
		}
	}
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
