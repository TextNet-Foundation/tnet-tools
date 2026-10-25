use std::collections::HashMap;
use std::path::{Path};
use serde::Deserialize;

pub mod lua;
pub mod rhai;

/// Запрос к скрипту
#[derive(Debug, Clone)]
pub struct Request {
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
    pub form: HashMap<String, String>,
    pub headers: HashMap<String, String>,
}

/// Ответ от скрипта
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// Трейт для движка скриптов
pub trait ScriptEngine: Send + Sync {
    fn has_script(&self, path: &str) -> bool;
    fn execute(&self, path: &str, req: &Request) -> Result<Option<Response>, String>;
}

/// Конфигурация скриптов
#[derive(Debug, Deserialize, Clone)]
pub struct ScriptingConfig {
    pub enabled: bool,
    pub lua_extension: Option<String>,
    pub rhai_extension: Option<String>,
    pub order: Option<Vec<String>>,
    pub hot_reload: Option<bool>,
    pub hide_scripts_behind: Option<bool>,
}

impl Default for ScriptingConfig {
    fn default() -> Self {
        ScriptingConfig {
            enabled: false,
            lua_extension: Some(".script.lua".to_string()),
            rhai_extension: Some(".script.rhai".to_string()),
            order: Some(vec!["lua".to_string(), "rhai".to_string()]),
            hot_reload: Some(true),
            hide_scripts_behind: Some(true),
        }
    }
}

// (утилита для нормализации пути, не используется сейчас, но оставлена)
pub fn normalize_script_path(root: &Path, full_path: &Path, ext: &str) -> Option<String> {
    let rel = full_path.strip_prefix(root).ok()?;
    let rel_str = rel.to_str()?;
    let without_ext = rel_str.trim_end_matches(ext);
    let key = if without_ext.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", without_ext)
    };
    Some(key)
}