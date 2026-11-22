use super::{Request, Response, ScriptEngine, resolve_existing_path, resolve_write_path};
use mlua::{Function, Lua, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub struct LuaEngine {
    root: PathBuf,
    extension: String,
    _hot_reload: bool,
}

impl LuaEngine {
    pub fn new(root: impl Into<PathBuf>, extension: Option<String>, hot_reload: bool) -> Self {
        Self {
            root: root.into(),
            extension: extension.unwrap_or_else(|| ".script.lua".to_string()),
            _hot_reload: hot_reload,
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
        let script_path = self.script_path(path);

        resolve_existing_path(
            &self.root,
            script_path
                .strip_prefix(&self.root)
                .unwrap_or(&script_path)
                .to_string_lossy()
                .as_ref(),
        )
        .map(|p| p.is_file())
        .unwrap_or(false)
    }
}

impl ScriptEngine for LuaEngine {
    fn has_script(&self, path: &str) -> bool {
        self.script_exists(path)
    }

    fn execute(&self, path: &str, req: &Request) -> Result<Option<Response>, String> {
        let script_path = self.script_path(path);

        let script_path = resolve_existing_path(
            &self.root,
            script_path
                .strip_prefix(&self.root)
                .unwrap_or(&script_path)
                .to_string_lossy()
                .as_ref(),
        )
        .map_err(|e| e.to_string())?;

        if !script_path.is_file() {
            return Err("Script not found".to_string());
        }

        let script = fs::read_to_string(&script_path)
            .map_err(|e| format!("Failed to read script: {}", e))?;

        let lua = Lua::new();

        lua.load(&script).exec().map_err(|e| e.to_string())?;

        // Создаём request таблицу
        let req_table = lua.create_table().map_err(|e| e.to_string())?;
        req_table
            .set("protocol", req.protocol.clone())
            .map_err(|e| e.to_string())?;
        req_table
            .set("method", req.method.clone())
            .map_err(|e| e.to_string())?;
        req_table
            .set("path", req.path.clone())
            .map_err(|e| e.to_string())?;

        let query_table = lua.create_table().map_err(|e| e.to_string())?;
        for (k, v) in &req.query {
            query_table
                .set(k.as_str(), v.as_str())
                .map_err(|e| e.to_string())?;
        }
        req_table
            .set("query", query_table)
            .map_err(|e| e.to_string())?;

        let body_str = String::from_utf8_lossy(&req.body).to_string();
        req_table.set("body", body_str).map_err(|e| e.to_string())?;

        let form_table = lua.create_table().map_err(|e| e.to_string())?;
        for (k, v) in &req.form {
            form_table
                .set(k.as_str(), v.as_str())
                .map_err(|e| e.to_string())?;
        }
        req_table
            .set("form", form_table)
            .map_err(|e| e.to_string())?;

        let headers_table = lua.create_table().map_err(|e| e.to_string())?;
        for (k, v) in &req.headers {
            headers_table
                .set(k.as_str(), v.as_str())
                .map_err(|e| e.to_string())?;
        }
        req_table
            .set("headers", headers_table)
            .map_err(|e| e.to_string())?;

        // Регистрируем вспомогательные функции
        let ok_func = lua
            .create_function(|lua, body: String| {
                let table = lua
                    .create_table()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                table
                    .set("status", 20)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                table
                    .set("body", body)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                Ok(table)
            })
            .map_err(|e| e.to_string())?;
        lua.globals()
            .set("ok", ok_func)
            .map_err(|e| e.to_string())?;

        let empty_func = lua
            .create_function(|lua, ()| {
                let table = lua
                    .create_table()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                table
                    .set("status", 22)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                Ok(table)
            })
            .map_err(|e| e.to_string())?;
        lua.globals()
            .set("empty", empty_func)
            .map_err(|e| e.to_string())?;

        let redirect_func = lua
            .create_function(|lua, location: String| {
                let headers = lua
                    .create_table()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                headers
                    .set("Location", location)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                let table = lua
                    .create_table()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                table
                    .set("status", 21)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                table
                    .set("headers", headers)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                Ok(table)
            })
            .map_err(|e| e.to_string())?;
        lua.globals()
            .set("redirect", redirect_func)
            .map_err(|e| e.to_string())?;

        let error_func = lua
            .create_function(|lua, (status, body): (u16, String)| {
                let table = lua
                    .create_table()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                table
                    .set("status", status)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                table
                    .set("body", body)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                Ok(table)
            })
            .map_err(|e| e.to_string())?;
        lua.globals()
            .set("error", error_func)
            .map_err(|e| e.to_string())?;

        // Файловые функции с обязательной проверкой границ root.
        let root = self.root.clone();

        let read_file_func = lua
            .create_function(move |_lua, path: String| {
                let full = resolve_existing_path(&root, &path)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                fs::read_to_string(&full).map_err(|e| mlua::Error::RuntimeError(e.to_string()))
            })
            .map_err(|e| e.to_string())?;

        lua.globals()
            .set("read_file", read_file_func)
            .map_err(|e| e.to_string())?;

        let root2 = self.root.clone();

        let write_file_func = lua
            .create_function(move |_lua, (path, data): (String, String)| {
                let full = resolve_write_path(&root2, &path)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                fs::write(&full, data).map_err(|e| mlua::Error::RuntimeError(e.to_string()))
            })
            .map_err(|e| e.to_string())?;

        lua.globals()
            .set("write_file", write_file_func)
            .map_err(|e| e.to_string())?;

        let root3 = self.root.clone();

        let exists_func = lua
            .create_function(
                move |_lua, path: String| match resolve_existing_path(&root3, &path) {
                    Ok(full) => Ok(full.exists()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
                },
            )
            .map_err(|e| e.to_string())?;

        lua.globals()
            .set("exists", exists_func)
            .map_err(|e| e.to_string())?;

        let root4 = self.root.clone();

        let remove_file_func = lua
            .create_function(move |_lua, path: String| {
                let full = resolve_existing_path(&root4, &path)
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                fs::remove_file(&full).map_err(|e| mlua::Error::RuntimeError(e.to_string()))
            })
            .map_err(|e| e.to_string())?;

        lua.globals()
            .set("remove_file", remove_file_func)
            .map_err(|e| e.to_string())?;

        let handle: Function = lua.globals().get("handle").map_err(|e| e.to_string())?;
        let result: Value = handle.call(req_table).map_err(|e| e.to_string())?;

        if result.is_nil() {
            return Ok(None);
        }

        let tbl = result.as_table().ok_or("Expected table")?;
        let status: u16 = tbl.get("status").map_err(|e| e.to_string())?;
        let mut headers = HashMap::new();
        if let Some(headers_tbl) = tbl
            .get::<_, Option<mlua::Table>>("headers")
            .map_err(|e| e.to_string())?
        {
            for pair in headers_tbl.pairs::<String, String>() {
                let (k, v) = pair.map_err(|e| e.to_string())?;
                headers.insert(k, v);
            }
        }
        let body: Option<String> = tbl.get("body").ok();
        let body_bytes = body.map(|s| s.into_bytes());

        Ok(Some(Response {
            status,
            headers,
            body: body_bytes,
        }))
    }
}
