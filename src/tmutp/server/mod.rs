mod accept;
mod dispatch;
mod stream;

pub use accept::run;
pub use dispatch::*;

pub fn complete_request_len(buffer: &[u8]) -> Option<usize> {
    let first_end = buffer.iter().position(|byte| *byte == b'\n')? + 1;

    let mut position = first_end;
    let mut content_length = 0usize;

    loop {
        let relative = buffer
            .get(position..)?
            .iter()
            .position(|byte| *byte == b'\n')?;

        let end = position + relative + 1;
        let line = &buffer[position..end];

        if line == b"\n" || line == b"\r\n" {
            return end.checked_add(content_length);
        }

        if let Ok(line) = std::str::from_utf8(line)
            && let Some((key, value)) = line.trim().split_once(':')
            && key.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<usize>().ok()?;
        }

        position = end;
    }
}
