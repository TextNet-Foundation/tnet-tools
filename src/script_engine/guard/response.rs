use crate::script_engine::Response;

/// Заголовки, которые формирует только сервер.
const RESERVED_HEADERS: &[&str] = &[
	"content-length",
	"content-encoding",
	"content-range",
	"file-sha256",
	"supported-compression",
];

fn is_token_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

fn has_control(value: &str) -> bool {
	value.chars().any(|c| c.is_control() && c != '\t')
}

/// Проверяет ответ скрипта перед сериализацией. `status_known` — таблица кодов протокола.
pub fn validate_response(
	response: &Response,
	status_known: impl Fn(u16) -> bool,
) -> Result<(), &'static str> {
	if !status_known(response.status) {
		return Err("unknown status code");
	}

	for (key, value) in &response.headers {
		if key.is_empty() || !key.chars().all(is_token_char) {
			return Err("invalid header name");
		}

		if has_control(value) {
			return Err("invalid header value");
		}

		if RESERVED_HEADERS
			.iter()
			.any(|reserved| key.eq_ignore_ascii_case(reserved))
		{
			return Err("reserved header");
		}
	}

	Ok(())
}
