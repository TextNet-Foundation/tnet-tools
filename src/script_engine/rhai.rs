use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use rhai::{Engine, Scope, Map, Dynamic};
use super::{Request, Response, ScriptEngine};

pub struct RhaiEngine {
    root: PathBuf,
    extension: String,
    hot_reload: bool,
}

impl RhaiEngine {
    pub fn new(root: impl Into<PathBuf>, extension: Option<String>, hot_reload: bool) -> Self {
        Self {
            root: root.into(),
            extension: extension.unwrap_or_else(|| ".script.rhai".to_string()),
            hot_reload,
        }
    }

    fn script_path(&self, path: &str) -> PathBuf {
        let relative = path.trim_start_matches('/');
        let mut full = self.root.clone();
        if relative.is_empty() {
            full.push("index");
        } else {
            if path.ends_with('/') {
                full.push(relative);
                full.push("index");
            } else {
                full.push(relative);
            }
        }
        full.set_extension(&self.extension[1..]);
        full
    }

    fn script_exists(&self, path: &str) -> bool {
        self.script_path(path).exists()
    }
}

impl ScriptEngine for RhaiEngine {
    fn has_script(&self, path: &str) -> bool {
        self.script_exists(path)
    }

    fn execute(&self, path: &str, req: &Request) -> Result<Option<Response>, String> {
        let script_path = self.script_path(path);
        if !script_path.exists() {
            return Err("Script not found".to_string());
        }

        let script = fs::read_to_string(&script_path)
            .map_err(|e| format!("Failed to read script: {}", e))?;

        let mut engine = Engine::new();
        let mut scope = Scope::new();

        // Создаём request как Map
        let mut req_map = Map::new();
        req_map.insert("protocol".into(), Dynamic::from(req.protocol.clone()));
        req_map.insert("method".into(), Dynamic::from(req.method.clone()));
        req_map.insert("path".into(), Dynamic::from(req.path.clone()));

        let mut query_map = Map::new();
        for (k, v) in &req.query {
            query_map.insert(k.clone().into(), Dynamic::from(v.clone()));
        }
        req_map.insert("query".into(), Dynamic::from(query_map));

        let body_str = String::from_utf8_lossy(&req.body).to_string();
        req_map.insert("body".into(), Dynamic::from(body_str));

        let mut form_map = Map::new();
        for (k, v) in &req.form {
            form_map.insert(k.clone().into(), Dynamic::from(v.clone()));
        }
        req_map.insert("form".into(), Dynamic::from(form_map));

        let mut headers_map = Map::new();
        for (k, v) in &req.headers {
            headers_map.insert(k.clone().into(), Dynamic::from(v.clone()));
        }
        req_map.insert("headers".into(), Dynamic::from(headers_map));

        // Регистрируем функции-помощники
        engine.register_fn("ok", |body: String| -> Map {
            let mut m = Map::new();
            m.insert("status".into(), Dynamic::from(20));
            m.insert("body".into(), Dynamic::from(body));
            m
        });
        engine.register_fn("empty", || -> Map {
            let mut m = Map::new();
            m.insert("status".into(), Dynamic::from(22));
            m
        });
        engine.register_fn("redirect", |location: String| -> Map {
            let mut m = Map::new();
            m.insert("status".into(), Dynamic::from(21));
            let mut h = Map::new();
            h.insert("Location".into(), Dynamic::from(location));
            m.insert("headers".into(), Dynamic::from(h));
            m
        });
        // Используем имя err вместо error (чтобы не конфликтовать со встроенной функцией Rhai)
        engine.register_fn("err", |status: i64, body: String| -> Map {
            let mut m = Map::new();
            m.insert("status".into(), Dynamic::from(status as u16));
            m.insert("body".into(), Dynamic::from(body));
            m
        });

        // Файловые функции
        let root = self.root.clone();
        engine.register_fn("read_file", move |path: String| -> Result<String, String> {
            let full = root.join(path.trim_start_matches('/'));
            if !full.starts_with(&root) {
                return Err("Access denied".to_string());
            }
            fs::read_to_string(&full).map_err(|e| e.to_string())
        });

        let root2 = self.root.clone();
        engine.register_fn("write_file", move |(path, data): (String, String)| -> Result<(), String> {
            let full = root2.join(path.trim_start_matches('/'));
            if !full.starts_with(&root2) {
                return Err("Access denied".to_string());
            }
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&full, data).map_err(|e| e.to_string())
        });

        let root3 = self.root.clone();
        engine.register_fn("exists", move |path: String| -> Result<bool, String> {
            let full = root3.join(path.trim_start_matches('/'));
            if !full.starts_with(&root3) {
                return Err("Access denied".to_string());
            }
            Ok(full.exists())
        });

        let root4 = self.root.clone();
        engine.register_fn("remove_file", move |path: String| -> Result<(), String> {
            let full = root4.join(path.trim_start_matches('/'));
            if !full.starts_with(&root4) {
                return Err("Access denied".to_string());
            }
            fs::remove_file(&full).map_err(|e| e.to_string())
        });

        let ast = engine.compile(&script).map_err(|e| e.to_string())?;
        engine.run_ast(&ast).map_err(|e| e.to_string())?;

        // Вызываем handle(request) с передачей req_map как аргумента
        let result: Dynamic = engine.call_fn(&mut scope, &ast, "handle", (req_map,))
            .map_err(|e| e.to_string())?;

        if result.is_unit() {
            return Ok(None);
        }

        let map = result.try_cast::<Map>().ok_or("Expected Map")?;
        let status: u16 = map.get("status")
            .and_then(|v| v.as_int().ok())
            .ok_or("Missing status")? as u16;

        let mut headers = HashMap::new();
        if let Some(headers_map) = map.get("headers")
            .and_then(|v| v.clone().try_cast::<Map>())
        {
            for (k, v) in headers_map.iter() {
                if let Ok(s) = v.clone().into_string() {
                    headers.insert(k.to_string(), s);
                }
            }
        }

        let body = map.get("body")
            .and_then(|v| v.clone().into_string().ok())
            .map(|s| s.into_bytes());

        Ok(Some(Response { status, headers, body }))
    }
}