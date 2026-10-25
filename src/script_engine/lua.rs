use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use mlua::{Lua, Function, Value};
use super::{Request, Response, ScriptEngine};

pub struct LuaEngine {
    root: PathBuf,
    extension: String,
    hot_reload: bool,
}

impl LuaEngine {
    pub fn new(root: impl Into<PathBuf>, extension: Option<String>, hot_reload: bool) -> Self {
        Self {
            root: root.into(),
            extension: extension.unwrap_or_else(|| ".script.lua".to_string()),
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
        full.set_extension(&self.extension[1..]); // убираем точку
        full
    }

    fn script_exists(&self, path: &str) -> bool {
        self.script_path(path).exists()
    }
}

impl ScriptEngine for LuaEngine {
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

        let lua = Lua::new();

        lua.load(&script).exec().map_err(|e| e.to_string())?;

        // Создаём request таблицу
        let req_table = lua.create_table().map_err(|e| e.to_string())?;
        req_table.set("protocol", req.protocol.clone()).map_err(|e| e.to_string())?;
        req_table.set("method", req.method.clone()).map_err(|e| e.to_string())?;
        req_table.set("path", req.path.clone()).map_err(|e| e.to_string())?;

        let query_table = lua.create_table().map_err(|e| e.to_string())?;
        for (k, v) in &req.query {
            query_table.set(k.as_str(), v.as_str()).map_err(|e| e.to_string())?;
        }
        req_table.set("query", query_table).map_err(|e| e.to_string())?;

        let body_str = String::from_utf8_lossy(&req.body).to_string();
        req_table.set("body", body_str).map_err(|e| e.to_string())?;

        let form_table = lua.create_table().map_err(|e| e.to_string())?;
        for (k, v) in &req.form {
            form_table.set(k.as_str(), v.as_str()).map_err(|e| e.to_string())?;
        }
        req_table.set("form", form_table).map_err(|e| e.to_string())?;

        let headers_table = lua.create_table().map_err(|e| e.to_string())?;
        for (k, v) in &req.headers {
            headers_table.set(k.as_str(), v.as_str()).map_err(|e| e.to_string())?;
        }
        req_table.set("headers", headers_table).map_err(|e| e.to_string())?;

        // Регистрируем вспомогательные функции
        let ok_func = lua.create_function(|lua, body: String| {
            let table = lua.create_table().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            table.set("status", 20).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            table.set("body", body).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            Ok(table)
        }).map_err(|e| e.to_string())?;
        lua.globals().set("ok", ok_func).map_err(|e| e.to_string())?;

        let empty_func = lua.create_function(|lua, ()| {
            let table = lua.create_table().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            table.set("status", 22).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            Ok(table)
        }).map_err(|e| e.to_string())?;
        lua.globals().set("empty", empty_func).map_err(|e| e.to_string())?;

        let redirect_func = lua.create_function(|lua, location: String| {
            let headers = lua.create_table().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            headers.set("Location", location).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            let table = lua.create_table().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            table.set("status", 21).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            table.set("headers", headers).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            Ok(table)
        }).map_err(|e| e.to_string())?;
        lua.globals().set("redirect", redirect_func).map_err(|e| e.to_string())?;

        let error_func = lua.create_function(|lua, (status, body): (u16, String)| {
            let table = lua.create_table().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            table.set("status", status).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            table.set("body", body).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            Ok(table)
        }).map_err(|e| e.to_string())?;
        lua.globals().set("error", error_func).map_err(|e| e.to_string())?;

        // Файловые функции
        let root = self.root.clone();
        let read_file_func = lua.create_function(move |_lua, path: String| {
            let full = root.join(path.trim_start_matches('/'));
            if !full.starts_with(&root) {
                return Err(mlua::Error::RuntimeError("Access denied".to_string()));
            }
            fs::read_to_string(&full).map_err(|e| mlua::Error::RuntimeError(e.to_string()))
        }).map_err(|e| e.to_string())?;
        lua.globals().set("read_file", read_file_func).map_err(|e| e.to_string())?;

        let root2 = self.root.clone();
        let write_file_func = lua.create_function(move |_lua, (path, data): (String, String)| {
            let full = root2.join(path.trim_start_matches('/'));
            if !full.starts_with(&root2) {
                return Err(mlua::Error::RuntimeError("Access denied".to_string()));
            }
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            }
            fs::write(&full, data).map_err(|e| mlua::Error::RuntimeError(e.to_string()))
        }).map_err(|e| e.to_string())?;
        lua.globals().set("write_file", write_file_func).map_err(|e| e.to_string())?;

        let root3 = self.root.clone();
        let exists_func = lua.create_function(move |_lua, path: String| {
            let full = root3.join(path.trim_start_matches('/'));
            if !full.starts_with(&root3) {
                return Err(mlua::Error::RuntimeError("Access denied".to_string()));
            }
            Ok(full.exists())
        }).map_err(|e| e.to_string())?;
        lua.globals().set("exists", exists_func).map_err(|e| e.to_string())?;

        let root4 = self.root.clone();
        let remove_file_func = lua.create_function(move |_lua, path: String| {
            let full = root4.join(path.trim_start_matches('/'));
            if !full.starts_with(&root4) {
                return Err(mlua::Error::RuntimeError("Access denied".to_string()));
            }
            fs::remove_file(&full).map_err(|e| mlua::Error::RuntimeError(e.to_string()))
        }).map_err(|e| e.to_string())?;
        lua.globals().set("remove_file", remove_file_func).map_err(|e| e.to_string())?;

        let handle: Function = lua.globals().get("handle").map_err(|e| e.to_string())?;
        let result: Value = handle.call(req_table).map_err(|e| e.to_string())?;

        if result.is_nil() {
            return Ok(None);
        }

        let tbl = result.as_table().ok_or("Expected table")?;
        let status: u16 = tbl.get("status").map_err(|e| e.to_string())?;
        let mut headers = HashMap::new();
        if let Some(headers_tbl) = tbl.get::<_, Option<mlua::Table>>("headers").map_err(|e| e.to_string())? {
            for pair in headers_tbl.pairs::<String, String>() {
                let (k, v) = pair.map_err(|e| e.to_string())?;
                headers.insert(k, v);
            }
        }
        let body: Option<String> = tbl.get("body").ok();
        let body_bytes = body.map(|s| s.into_bytes());

        Ok(Some(Response { status, headers, body: body_bytes }))
    }
}