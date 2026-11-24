//! Ограничения на функции сопоставления с образцом: их C-код не прерывается
//! хуком инструкций, поэтому длинные шаблоны, субъекты и шаблоны с большим числом
//! квантификаторов отклоняются заранее.
//!
//! Это смягчение, а не полная защита: время работы сопоставления остаётся
//! полиномиальным по длине субъекта (степень зависит от числа квантификаторов), и
//! злонамеренный автор скрипта по-прежнему может занять поток. Скрипты — доверенный
//! код владельца сервера; песочница ограничивает ошибки и случайные взрывы, а не
//! противника с правом писать скрипты.

use mlua::{Function, Lua, MultiValue, Table, Value};

/// Максимальная длина шаблона, байт.
const MAX_PATTERN_BYTES: usize = 256;
/// Максимальная длина строки-субъекта, байт.
const MAX_SUBJECT_BYTES: usize = 1024 * 1024;

/// Максимум квантификаторов (`*`, `+`, `-`, `?` вне наборов `[...]`) в одном шаблоне.
const MAX_PATTERN_QUANTIFIERS: usize = 16;

const WRAPPED: &[&str] = &["find", "match", "gmatch", "gsub"];

/// Считает квантификаторы шаблона Lua: пропускает `%x`-экранирование и содержимое
/// наборов `[...]`, где эти символы обычные.
pub fn count_quantifiers(pattern: &[u8]) -> usize {
	let mut count = 0;
	let mut in_set = false;
	let mut i = 0;

	while i < pattern.len() {
		match pattern[i] {
			b'%' => i += 1,
			b'[' if !in_set => {
				in_set = true;
				// `[^]...]` и `[]...]`: первый `]` после `[` или `[^` — обычный символ.
				if pattern.get(i + 1) == Some(&b'^') {
					i += 1;
				}
				if pattern.get(i + 1) == Some(&b']') {
					i += 1;
				}
			}
			b']' if in_set => in_set = false,
			b'*' | b'+' | b'-' | b'?' if !in_set => count += 1,
			_ => {}
		}
		i += 1;
	}

	count
}

fn registry_key(name: &str) -> String {
	format!("tnet_std_string_{name}")
}

fn check_quantifiers(value: Option<&Value>) -> mlua::Result<()> {
	match value {
		Some(Value::String(s)) if count_quantifiers(s.as_bytes()) > MAX_PATTERN_QUANTIFIERS => {
			Err(mlua::Error::RuntimeError(format!(
				"pattern has too many quantifiers (limit {MAX_PATTERN_QUANTIFIERS})"
			)))
		}
		_ => Ok(()),
	}
}

fn check_len(value: Option<&Value>, max: usize, what: &str) -> mlua::Result<()> {
	match value {
		Some(Value::String(s)) if s.as_bytes().len() > max => Err(mlua::Error::RuntimeError(
			format!("{what} too long (limit {max} bytes)"),
		)),
		_ => Ok(()),
	}
}

/// Подменяет string.find/match/gmatch/gsub обёртками с проверкой размеров.
/// Оригиналы лежат в реестре: замыкание с фичей `send` не может захватывать Function.
pub fn restrict_patterns(lua: &Lua) -> Result<(), String> {
	let inner = |e: mlua::Error| e.to_string();
	let string: Table = lua.globals().get("string").map_err(inner)?;

	for name in WRAPPED {
		let key = registry_key(name);
		let original: Function = string.get(*name).map_err(inner)?;
		lua.set_named_registry_value(&key, original)
			.map_err(inner)?;

		// `string.find(s, p, init, true)` ищет подстроку без образцов — квантификаторы не важны.
		let may_be_plain = *name == "find";

		let wrapper = lua
			.create_function(move |lua, args: MultiValue| {
				check_len(args.get(0), MAX_SUBJECT_BYTES, "subject")?;
				check_len(args.get(1), MAX_PATTERN_BYTES, "pattern")?;
				let plain = may_be_plain && matches!(args.get(3), Some(Value::Boolean(true)));
				if !plain {
					check_quantifiers(args.get(1))?;
				}
				let original: Function = lua.named_registry_value(&key)?;
				original.call::<_, MultiValue>(args)
			})
			.map_err(inner)?;
		string.set(*name, wrapper).map_err(inner)?;
	}
	Ok(())
}
