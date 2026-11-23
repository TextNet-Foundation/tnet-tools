use crate::script_engine::fs::Sandbox;
use crate::script_engine::{ScriptLimits, check_status};
use mlua::{Function, HookTriggers, Lua, LuaOptions, MultiValue, StdLib, Table, Value};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Как часто (в VM-инструкциях) проверяется дедлайн.
const HOOK_INSTRUCTIONS: u32 = 1_000;
const STD_ERROR_KEY: &str = "tnet_std_error";

/// Глобалы базовой библиотеки, дающие доступ к файловой системе, загрузке кода и GC.
const REMOVED_GLOBALS: &[&str] = &[
	"dofile",
	"loadfile",
	"load",
	"loadstring",
	"require",
	"collectgarbage",
];

fn rt(e: impl ToString) -> mlua::Error {
	mlua::Error::RuntimeError(e.to_string())
}

/// Создаёт Lua без io/os/package/debug, с лимитом памяти и дедлайном.
pub fn new_sandboxed(limits: &ScriptLimits) -> Result<Lua, String> {
	let libs = StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8 | StdLib::COROUTINE;
	let lua = Lua::new_with(libs, LuaOptions::default()).map_err(|e| e.to_string())?;

	lua.set_memory_limit(limits.memory_bytes)
		.map_err(|e| e.to_string())?;

	let started = Instant::now();
	let deadline = started + limits.deadline;
	lua.set_hook(
		HookTriggers::new().every_nth_instruction(HOOK_INSTRUCTIONS),
		move |_lua, _debug| {
			if Instant::now() >= deadline {
				Err(rt("script time limit exceeded"))
			} else {
				Ok(())
			}
		},
	);

	let globals = lua.globals();
	for name in REMOVED_GLOBALS {
		globals.set(*name, Value::Nil).map_err(|e| e.to_string())?;
	}

	// Безопасные замены os.time / os.clock.
	let os = lua.create_table().map_err(|e| e.to_string())?;
	let time = lua
		.create_function(|_, ()| {
			Ok(SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map(|d| d.as_secs() as i64)
				.unwrap_or(0))
		})
		.map_err(|e| e.to_string())?;
	let clock = lua
		.create_function(move |_, ()| Ok(started.elapsed().as_secs_f64()))
		.map_err(|e| e.to_string())?;
	os.set("time", time).map_err(|e| e.to_string())?;
	os.set("clock", clock).map_err(|e| e.to_string())?;
	globals.set("os", os).map_err(|e| e.to_string())?;
	drop(globals);

	Ok(lua)
}

fn response_table<'lua>(
	lua: &'lua Lua,
	status: u16,
	body: Option<mlua::String<'lua>>,
) -> mlua::Result<Table<'lua>> {
	let table = lua.create_table()?;
	table.set("status", status)?;
	if let Some(body) = body {
		table.set("body", body)?;
	}
	Ok(table)
}

/// Регистрирует ok/empty/redirect/error.
///
/// `error(status, body)` по README возвращает ответ, но только когда первый
/// аргумент число, а второй строка; во всех остальных случаях вызывается
/// стандартный `error`, поэтому `error("msg")` и `pcall(error, ...)` работают как обычно.
pub fn register_responses(lua: &Lua) -> Result<(), String> {
	let globals = lua.globals();
	let inner = |e: mlua::Error| e.to_string();

	globals
		.set(
			"ok",
			lua.create_function(|lua, body: mlua::String| response_table(lua, 20, Some(body)))
				.map_err(inner)?,
		)
		.map_err(inner)?;

	globals
		.set(
			"empty",
			lua.create_function(|lua, ()| response_table(lua, 22, None))
				.map_err(inner)?,
		)
		.map_err(inner)?;

	globals
		.set(
			"redirect",
			lua.create_function(|lua, location: String| {
				let table = response_table(lua, 21, None)?;
				let headers = lua.create_table()?;
				headers.set("Location", location)?;
				table.set("headers", headers)?;
				Ok(table)
			})
			.map_err(inner)?,
		)
		.map_err(inner)?;

	// Оригинальный error хранится в реестре: замыкание с фичей mlua `send` не может
	// захватывать Function (он не Send).
	let std_error: Function = globals.get("error").map_err(inner)?;
	lua.set_named_registry_value(STD_ERROR_KEY, std_error)
		.map_err(inner)?;
	globals
		.set(
			"error",
			lua.create_function(|lua, args: MultiValue| {
				let status_body = match (args.get(0), args.get(1)) {
					(Some(Value::Integer(s)), Some(Value::String(b))) => Some((*s, b.clone())),
					(Some(Value::Number(n)), Some(Value::String(b))) if n.fract() == 0.0 => {
						Some((*n as i64, b.clone()))
					}
					_ => None,
				};

				match status_body {
					Some((status, body)) => {
						response_table(lua, check_status(status).map_err(rt)?, Some(body))
							.map(Value::Table)
					}
					None => {
						let std_error: Function = lua.named_registry_value(STD_ERROR_KEY)?;
						std_error.call::<_, Value>(args)
					}
				}
			})
			.map_err(inner)?,
		)
		.map_err(inner)?;

	Ok(())
}

/// Регистрирует read_file / write_file / exists / remove_file поверх песочницы.
pub fn register_files(lua: &Lua, sandbox: &Sandbox) -> Result<(), String> {
	let globals = lua.globals();
	let inner = |e: mlua::Error| e.to_string();

	let sb = sandbox.clone();
	globals
		.set(
			"read_file",
			lua.create_function(move |lua, path: String| {
				let data = sb.read(&path).map_err(rt)?;
				lua.create_string(data)
			})
			.map_err(inner)?,
		)
		.map_err(inner)?;

	let sb = sandbox.clone();
	globals
		.set(
			"write_file",
			lua.create_function(move |_, (path, data): (String, mlua::String)| {
				sb.write(&path, data.as_bytes()).map_err(rt)
			})
			.map_err(inner)?,
		)
		.map_err(inner)?;

	let sb = sandbox.clone();
	globals
		.set(
			"exists",
			lua.create_function(move |_, path: String| Ok(sb.exists(&path)))
				.map_err(inner)?,
		)
		.map_err(inner)?;

	let sb = sandbox.clone();
	globals
		.set(
			"remove_file",
			lua.create_function(move |_, path: String| sb.remove(&path).map_err(rt))
				.map_err(inner)?,
		)
		.map_err(inner)?;

	Ok(())
}

/// Строит таблицу `request`.
pub fn request_table<'lua>(
	lua: &'lua Lua,
	req: &crate::script_engine::Request,
) -> mlua::Result<Table<'lua>> {
	fn map_table<'lua>(
		lua: &'lua Lua,
		map: &std::collections::HashMap<String, String>,
	) -> mlua::Result<Table<'lua>> {
		let table = lua.create_table()?;
		for (k, v) in map {
			table.set(k.as_str(), v.as_str())?;
		}
		Ok(table)
	}

	let table = lua.create_table()?;
	table.set("protocol", req.protocol.as_str())?;
	table.set("method", req.method.as_str())?;
	table.set("path", req.path.as_str())?;
	table.set("query", map_table(lua, &req.query)?)?;
	table.set("body", String::from_utf8_lossy(&req.body).into_owned())?;
	table.set("form", map_table(lua, &req.form)?)?;
	table.set("headers", map_table(lua, &req.headers)?)?;
	Ok(table)
}
