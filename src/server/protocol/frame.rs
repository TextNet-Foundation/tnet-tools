pub fn complete_frame_len(buffer: &[u8]) -> Option<usize> {
    let first_end = buffer.iter().position(|byte| *byte == b'\n')? + 1;

    let first = std::str::from_utf8(&buffer[..first_end]).ok()?.trim();

    if first.starts_with("UTNP/1.0 ") {
        return Some(first_end);
    }

    let mut position = first_end;

    loop {
        let relative = buffer[position..].iter().position(|byte| *byte == b'\n')?;

        let end = position + relative + 1;
        let line = &buffer[position..end];

        if line == b"\n" || line == b"\r\n" {
            return Some(end);
        }

        position = end;
    }
}
