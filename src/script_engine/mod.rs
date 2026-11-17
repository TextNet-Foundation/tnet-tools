use std::collections::HashMap;
use serde::Deserialize;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

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

/// Проверяет существующий путь и запрещает выход за пределы root.
/// Каноникализация учитывает `..`, симлинки и другие компоненты пути.
pub fn resolve_existing_path(root: &Path, requested: &str) -> io::Result<PathBuf> {
    let canonical_root = fs::canonicalize(root)?;

    let relative = requested.trim_start_matches(['/', '\\']);
    let relative_path = Path::new(relative);

    if relative_path.is_absolute()
        || relative_path.components().any(|c| matches!(c, Component::Prefix(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Access denied",
        ));
    }

    let candidate = canonical_root.join(relative_path);
    let canonical = fs::canonicalize(candidate)?;

    if !canonical.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Access denied",
        ));
    }

    Ok(canonical)
}

/// Подготавливает путь для записи.
/// Создаёт отсутствующие директории, проверяя каждый компонент.
pub fn resolve_write_path(root: &Path, requested: &str) -> io::Result<PathBuf> {
    let canonical_root = fs::canonicalize(root)?;

    let relative = requested.trim_start_matches(['/', '\\']);
    let relative_path = Path::new(relative);

    if relative_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Access denied",
        ));
    }

    let mut components = Vec::new();

    for component in relative_path.components() {
        match component {
            Component::Normal(part) => components.push(part.to_os_string()),
            Component::CurDir => {}
            // Не разрешаем обход даже тогда, когда он в итоге
            // возвращает путь внутрь root.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Access denied",
                ));
            }
        }
    }

    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Invalid file path",
        ));
    }

    let mut current = canonical_root.clone();

    for component in &components[..components.len() - 1] {
        current.push(component);

        if current.exists() {
            let canonical = fs::canonicalize(&current)?;

            if !canonical.starts_with(&canonical_root) || !canonical.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Access denied",
                ));
            }

            current = canonical;
        } else {
            fs::create_dir(&current)?;

            let canonical = fs::canonicalize(&current)?;

            if !canonical.starts_with(&canonical_root) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Access denied",
                ));
            }

            current = canonical;
        }
    }

    current.push(components.last().unwrap());

    // Если конечный файл уже существует (в том числе является
    // симлинком), проверяем его реальное расположение.
    if current.exists() {
        let canonical = fs::canonicalize(&current)?;

        if !canonical.starts_with(&canonical_root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Access denied",
            ));
        }

        return Ok(canonical);
    }

    Ok(current)
}