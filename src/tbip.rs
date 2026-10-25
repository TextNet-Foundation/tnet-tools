use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::collections::HashMap;
use url::form_urlencoded;

mod script_engine;
use script_engine::{ScriptEngine, Request, Response, ScriptingConfig};
use script_engine::lua::LuaEngine;
use script_engine::rhai::RhaiEngine;

// ---------- Конфигурация ----------
#[derive(Debug, Deserialize)]
struct Config {
    port: u16,
    root: String,
    scripting: ScriptingConfig,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "TBIP server (TNet Binary Information Protocol)")]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "./tbip-config.toml")]
    config: String,
}

// Статус-коды (аналогичны TMUTP, но без 23, 41)
const OK: &str = "20 OK";
#[allow(dead_code)]
const MOVED: &str = "21 MOVED";
const OK_EMPTY: &str = "22 OK EMPTY";
const BAD_REQUEST: &str = "30 BAD REQUEST";
const NOT_FOUND: &str = "31 NOT FOUND";
#[allow(dead_code)]
const FORBIDDEN: &str = "32 FORBIDDEN";
#[allow(dead_code)]
const SERVER_ERROR: &str = "40 SERVER ERROR";
#[allow(dead_code)]
const SERVICE_UNAVAILABLE: &str = "42 SERVICE UNAVAILABLE";
const METHOD_NOT_ALLOWED: &str = "50 METHOD NOT ALLOWED";
const VERSION_NOT_SUPPORTED: &str = "51 VERSION NOT SUPPORTED";

fn status_code_to_text(code: u16) -> &'static str {
    match code {
        20 => "OK",
        21 => "MOVED",
        22 => "OK EMPTY",
        30 => "BAD REQUEST",
        31 => "NOT FOUND",
        32 => "FORBIDDEN",
        40 => "SERVER ERROR",
        42 => "SERVICE UNAVAILABLE",
        50 => "METHOD NOT ALLOWED",
        51 => "VERSION NOT SUPPORTED",
        _ => "UNKNOWN",
    }
}

fn mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("bmp") => "image/bmp",
        Some("ico") => "image/x-icon",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("ogg") => "audio/ogg",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("avi") => "video/x-msvideo",
        Some("mov") => "video/quicktime",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz") => "application/gzip",
        Some("txt") => "text/plain",
        _ => "application/octet-stream",
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let config_content = fs::read_to_string(&args.config)
        .expect("Failed to read TBIP config");
    let config: Config = toml::from_str(&config_content)
        .expect("Failed to parse TBIP config");

    let lua_engine: Option<Arc<LuaEngine>> = if config.scripting.enabled {
        let ext = config.scripting.lua_extension.clone().unwrap_or_else(|| ".script.lua".to_string());
        let hot_reload = config.scripting.hot_reload.unwrap_or(true);
        Some(Arc::new(LuaEngine::new(&config.root, Some(ext), hot_reload)))
    } else {
        None
    };

    let rhai_engine: Option<Arc<RhaiEngine>> = if config.scripting.enabled {
        let ext = config.scripting.rhai_extension.clone().unwrap_or_else(|| ".script.rhai".to_string());
        let hot_reload = config.scripting.hot_reload.unwrap_or(true);
        Some(Arc::new(RhaiEngine::new(&config.root, Some(ext), hot_reload)))
    } else {
        None
    };

    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.port))?;
    println!("TBIP server listening on port {}", config.port);
    println!("Serving files from {}", config.root);
    if config.scripting.enabled {
        println!("Scripting enabled (Lua: {}, Rhai: {})",
                 lua_engine.is_some(), rhai_engine.is_some());
        println!("hide_scripts_behind: {}", config.scripting.hide_scripts_behind.unwrap_or(true));
    } else {
        println!("Scripting disabled");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let root = config.root.clone();
                let lua = lua_engine.clone();
                let rhai = rhai_engine.clone();
                let scripting_config = config.scripting.clone();
                thread::spawn(move || {
                    handle_client(stream, &root, &lua, &rhai, &scripting_config);
                });
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, root: &str,
                 lua_engine: &Option<Arc<LuaEngine>>,
                 rhai_engine: &Option<Arc<RhaiEngine>>,
                 scripting_config: &ScriptingConfig) {
    let mut reader = BufReader::new(&mut stream);

    let mut request_line = String::new();
    if let Err(e) = reader.read_line(&mut request_line) {
        eprintln!("Read error: {}", e);
        return;
    }
    let request_line = request_line.trim();

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        send_error(&mut stream, BAD_REQUEST, "Bad Request");
        return;
    }

    let version = parts[0];
    let method = parts[1];
    let raw_path = parts[2];

    if version != "TBIP/1.0" {
        send_error(&mut stream, VERSION_NOT_SUPPORTED, "Version Not Supported");
        return;
    }

    if method != "GET" && method != "HEAD" {
        send_error(&mut stream, METHOD_NOT_ALLOWED, "Method Not Allowed");
        return;
    }

    let (path, query_str) = if let Some(pos) = raw_path.find('?') {
        let (p, q) = raw_path.split_at(pos);
        (p, Some(&q[1..]))
    } else {
        (raw_path, None)
    };

    let decoded_path = percent_decode(path);

    let query_params = if let Some(qs) = query_str {
        form_urlencoded::parse(qs.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>()
    } else {
        HashMap::new()
    };

    let mut request_headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            request_headers.insert(key.clone(), value.clone());
        }
    }

    // TBIP не использует тело, оставляем пустым
    let body_bytes = Vec::new();
    let form_params = HashMap::new();

    // ---------- Нормализация пути для скриптов ----------
    let mut script_path = decoded_path.clone();
    let hide = scripting_config.hide_scripts_behind.unwrap_or(true);
    if hide {
        let lua_ext = scripting_config.lua_extension.clone().unwrap_or_else(|| ".script.lua".to_string());
        let rhai_ext = scripting_config.rhai_extension.clone().unwrap_or_else(|| ".script.rhai".to_string());

        if script_path.ends_with(&lua_ext) {
            script_path = script_path.trim_end_matches(&lua_ext).to_string();
        } else if script_path.ends_with(&rhai_ext) {
            script_path = script_path.trim_end_matches(&rhai_ext).to_string();
        }
        if script_path.is_empty() {
            script_path = "/".to_string();
        }
    }

    let req = Request {
        protocol: "tbip".to_string(),
        method: method.to_string(),
        path: decoded_path.clone(),
        query: query_params,
        body: body_bytes,
        form: form_params,
        headers: request_headers,
    };

    // ---------- Попытка выполнить скрипт ----------
    if scripting_config.enabled {
        let order = scripting_config.order.clone().unwrap_or_else(|| vec!["lua".to_string(), "rhai".to_string()]);
        for engine_name in &order {
            if engine_name == "lua" {
                if let Some(engine) = lua_engine {
                    if engine.has_script(&script_path) {
                        match engine.execute(&script_path, &req) {
                            Ok(Some(resp)) => { send_script_response(&mut stream, resp, method); return; }
                            Ok(None) => { send_empty_response(&mut stream); return; }
                            Err(e) => {
                                eprintln!("Lua script error: {}", e);
                                send_error(&mut stream, SERVER_ERROR, &format!("Lua script error: {}", e));
                                return;
                            }
                        }
                    }
                }
            } else if engine_name == "rhai" {
                if let Some(engine) = rhai_engine {
                    if engine.has_script(&script_path) {
                        match engine.execute(&script_path, &req) {
                            Ok(Some(resp)) => { send_script_response(&mut stream, resp, method); return; }
                            Ok(None) => { send_empty_response(&mut stream); return; }
                            Err(e) => {
                                eprintln!("Rhai script error: {}", e);
                                send_error(&mut stream, SERVER_ERROR, &format!("Rhai script error: {}", e));
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    // ---------- Статика ----------
    let file_path = resolve_path(root, &decoded_path);
    match file_path {
        Some(full_path) => {
            match fs::read(&full_path) {
                Ok(data) => {
                    let mime = mime_type(&full_path);
                    if method == "HEAD" {
                        send_head(&mut stream, OK, mime, data.len() as u64);
                    } else {
                        send_binary(&mut stream, OK, mime, &data);
                    }
                }
                Err(_) => {
                    send_error(&mut stream, NOT_FOUND, "Not Found");
                }
            }
        }
        None => {
            send_error(&mut stream, NOT_FOUND, "Not Found");
        }
    }
}

// ---------- Отправка ответа из скрипта для TBIP ----------
fn send_script_response(stream: &mut TcpStream, resp: Response, method: &str) {
    let status_text = status_code_to_text(resp.status);
    let status_line = format!("TBIP/1.0 {} {}\n", resp.status, status_text);
    let mut headers_str = String::new();
    for (k, v) in &resp.headers {
        headers_str.push_str(&format!("{}: {}\n", k, v));
    }
    let body = resp.body.as_deref().unwrap_or(&[]);
    let content_len = format!("Content-Length: {}\n", body.len());
    let response = format!("{}{}{}\n", status_line, headers_str, content_len);
    let _ = stream.write_all(response.as_bytes());
    if method == "GET" && !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
}

// ---------- Отправка бинарного ответа ----------
fn send_binary(stream: &mut TcpStream, code: &str, mime: &str, data: &[u8]) {
    let status_line = format!("TBIP/1.0 {}\n", code);
    let content_type = format!("Content-Type: {}\n", mime);
    let content_len = format!("Content-Length: {}\n", data.len());
    let response = format!("{}{}{}\n", status_line, content_type, content_len);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(data);
    let _ = stream.flush();
}

fn send_head(stream: &mut TcpStream, code: &str, mime: &str, len: u64) {
    let status_line = format!("TBIP/1.0 {}\n", code);
    let content_type = format!("Content-Type: {}\n", mime);
    let content_len = format!("Content-Length: {}\n", len);
    let response = format!("{}{}{}\n", status_line, content_type, content_len);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn send_empty_response(stream: &mut TcpStream) {
    let response = format!("TBIP/1.0 {}\nContent-Length: 0\n", OK_EMPTY);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn send_error(stream: &mut TcpStream, code: &str, _name: &str) {
    let status_line = format!("TBIP/1.0 {}\n", code);
    let content_len = "Content-Length: 0\n";
    let response = format!("{}{}\n", status_line, content_len);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

// ---------- Разрешение пути ----------
fn resolve_path(root: &str, path: &str) -> Option<PathBuf> {
    let clean = path.trim_start_matches('/');
    if clean.is_empty() {
        return None;
    }
    let full = PathBuf::from(root).join(clean);
    if full.exists() && full.is_file() {
        Some(full)
    } else {
        None
    }
}

fn percent_decode(s: &str) -> String {
    use percent_encoding::percent_decode_str;
    percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}