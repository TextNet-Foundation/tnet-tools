use crate::script_engine::fs::Sandbox;
use crate::script_engine::{Request, ScriptLimits, check_status};
use ::rhai::module_resolvers::DummyModuleResolver;
use ::rhai::{Dynamic, Engine, EvalAltResult, Map};
use std::time::Instant;

type RhaiResult<T> = Result<T, Box<EvalAltResult>>;

const MAX_OPERATIONS: u64 = 5_000_000;
const MAX_STRING_SIZE: usize = 8 * 1024 * 1024;
const MAX_COLLECTION_SIZE: usize = 100_000;
const MAX_CALL_LEVELS: usize = 64;
const MAX_EXPR_DEPTH: usize = 64;
const MAX_FUNCTION_EXPR_DEPTH: usize = 32;

fn fail(message: impl ToString) -> Box<EvalAltResult> {
	message.to_string().into()
}

/// Движок с лимитами ресурсов, без eval и без загрузки модулей с диска.
pub fn new_limited(limits: &ScriptLimits) -> Engine {
	let mut engine = Engine::new();

	engine.set_max_operations(MAX_OPERATIONS);
	engine.set_max_string_size(MAX_STRING_SIZE);
	engine.set_max_array_size(MAX_COLLECTION_SIZE);
	engine.set_max_map_size(MAX_COLLECTION_SIZE);
	engine.set_max_call_levels(MAX_CALL_LEVELS);
	engine.set_max_expr_depths(MAX_EXPR_DEPTH, MAX_FUNCTION_EXPR_DEPTH);
	engine.disable_symbol("eval");
	engine.set_module_resolver(DummyModuleResolver::new());
	engine.on_print(|text| tracing::debug!(target: "script", "{}", text));
	engine.on_debug(|text, _, _| tracing::debug!(target: "script", "{}", text));

	let deadline = Instant::now() + limits.deadline;
	engine.on_progress(move |_| {
		if Instant::now() >= deadline {
			Some(Dynamic::from("time limit exceeded"))
		} else {
			None
		}
	});

	engine
}

fn response(status: u16, body: Option<String>) -> Map {
	let mut m = Map::new();
	m.insert("status".into(), Dynamic::from(i64::from(status)));
	if let Some(body) = body {
		m.insert("body".into(), Dynamic::from(body));
	}
	m
}

/// Регистрирует ok/empty/redirect/err и файловые функции.
pub fn register_helpers(engine: &mut Engine, sandbox: &Sandbox) {
	engine.register_fn("ok", |body: String| response(20, Some(body)));
	engine.register_fn("empty", || response(22, None));
	engine.register_fn("redirect", |location: String| {
		let mut m = response(21, None);
		let mut h = Map::new();
		h.insert("Location".into(), Dynamic::from(location));
		m.insert("headers".into(), Dynamic::from(h));
		m
	});
	// `err`, чтобы не конфликтовать со встроенным `throw`/ошибками Rhai.
	engine.register_fn("err", |status: i64, body: String| -> RhaiResult<Map> {
		Ok(response(check_status(status).map_err(fail)?, Some(body)))
	});

	let sb = sandbox.clone();
	engine.register_fn("read_file", move |path: String| -> RhaiResult<String> {
		let data = sb.read(&path).map_err(fail)?;
		String::from_utf8(data).map_err(fail)
	});

	let sb = sandbox.clone();
	engine.register_fn(
		"write_file",
		move |path: String, data: String| -> RhaiResult<()> {
			sb.write(&path, data.as_bytes()).map_err(fail)
		},
	);

	let sb = sandbox.clone();
	engine.register_fn("exists", move |path: String| -> RhaiResult<bool> {
		Ok(sb.exists(&path))
	});

	let sb = sandbox.clone();
	engine.register_fn("remove_file", move |path: String| -> RhaiResult<()> {
		sb.remove(&path).map_err(fail)
	});
}

/// Строит map `request`.
pub fn request_map(req: &Request) -> Map {
	fn to_map(src: &std::collections::HashMap<String, String>) -> Map {
		src.iter()
			.map(|(k, v)| (k.as_str().into(), Dynamic::from(v.clone())))
			.collect()
	}

	let mut m = Map::new();
	m.insert("protocol".into(), Dynamic::from(req.protocol.clone()));
	m.insert("method".into(), Dynamic::from(req.method.clone()));
	m.insert("path".into(), Dynamic::from(req.path.clone()));
	m.insert("query".into(), Dynamic::from(to_map(&req.query)));
	m.insert(
		"body".into(),
		Dynamic::from(String::from_utf8_lossy(&req.body).into_owned()),
	);
	m.insert("form".into(), Dynamic::from(to_map(&req.form)));
	m.insert("headers".into(), Dynamic::from(to_map(&req.headers)));
	m
}
