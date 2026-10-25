use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::collections::HashMap;
use url::form_urlencoded;

// Импортируем модуль скриптового движка
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
#[command(author, version, about = "TMUTP server (TMkUp Transfer Protocol)")]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "./tmutp-config.toml")]
    config: String,
}

// ---------- Статус-коды ----------
const OK: &str = "20 OK";
const OK_EMPTY: &str = "22 OK EMPTY";
const BAD_REQUEST: &str = "30 BAD REQUEST";
const NOT_FOUND: &str = "31 NOT FOUND";
const FORBIDDEN: &str = "32 FORBIDDEN";
const SERVER_ERROR: &str = "40 SERVER ERROR";
const METHOD_NOT_ALLOWED: &str = "50 METHOD NOT ALLOWED";
const VERSION_NOT_SUPPORTED: &str = "51 VERSION NOT SUPPORTED";

fn status_code_to_text(code: u16) -> &'static str {
    match code {
        20 => "OK",
        21 => "MOVED",
        22 => "OK EMPTY",
        23 => "MULTIPLE CHOICES",
        30 => "BAD REQUEST",
        31 => "NOT FOUND",
        32 => "FORBIDDEN",
        40 => "SERVER ERROR",
        41 => "NOT IMPLEMENTED",
        42 => "SERVICE UNAVAILABLE",
        50 => "METHOD NOT ALLOWED",
        51 => "VERSION NOT SUPPORTED",
        _ => "UNKNOWN",
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let config_content = fs::read_to_string(&args.config)
        .expect("Failed to read TMUTP config");
    let config: Config = toml::from_str(&config_content)
        .expect("Failed to parse TMUTP config");

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
    println!("TMUTP server listening on port {}", config.port);
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

// ---------- Обработка клиента ----------
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
        send_tmkup_error(&mut stream, BAD_REQUEST, "Bad request",
                         "Request must contain method and path");
        return;
    }

    let version = parts[0];
    let method = parts[1];
    let raw_path = parts[2];

    if version != "TMUTP/1.0" {
        send_tmkup_error(&mut stream, VERSION_NOT_SUPPORTED,
                         "51 Version not supported",
                         "Server supports only TMUTP/1.0");
        return;
    }

    if method != "GET" && method != "POST" {
        send_tmkup_error(&mut stream, METHOD_NOT_ALLOWED,
                         "50 Method not allowed",
                         "TMUTP supports only GET and POST");
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
    let mut content_length = 0;
    let mut content_length_found = false;
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
            if key == "content-length" {
                content_length = value.parse::<usize>().unwrap_or(0);
                content_length_found = true;
            }
        }
    }

    if method == "POST" && !content_length_found {
        send_tmkup_error(&mut stream, BAD_REQUEST,
                         "30 Bad request",
                         "POST request must include Content-Length header");
        return;
    }

    let mut body_bytes = Vec::new();
    if content_length > 0 {
        body_bytes.resize(content_length, 0);
        if let Err(e) = reader.read_exact(&mut body_bytes) {
            eprintln!("Failed to read body: {}", e);
            send_tmkup_error(&mut stream, BAD_REQUEST, "Body read error",
                             "Failed to read request body");
            return;
        }
    }

    let form_params = if method == "POST" && !body_bytes.is_empty() {
        let body_str = String::from_utf8_lossy(&body_bytes);
        form_urlencoded::parse(body_str.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>()
    } else {
        HashMap::new()
    };

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
        protocol: "tmutp".to_string(),
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
                            Ok(Some(resp)) => { send_script_response(&mut stream, resp); return; }
                            Ok(None) => { send_empty_response(&mut stream); return; }
                            Err(e) => {
                                eprintln!("Lua script error: {}", e);
                                send_tmkup_error(&mut stream, SERVER_ERROR,
                                                 "40 Server error",
                                                 &format!("Lua script error: {}", e));
                                return;
                            }
                        }
                    }
                }
            } else if engine_name == "rhai" {
                if let Some(engine) = rhai_engine {
                    if engine.has_script(&script_path) {
                        match engine.execute(&script_path, &req) {
                            Ok(Some(resp)) => { send_script_response(&mut stream, resp); return; }
                            Ok(None) => { send_empty_response(&mut stream); return; }
                            Err(e) => {
                                eprintln!("Rhai script error: {}", e);
                                send_tmkup_error(&mut stream, SERVER_ERROR,
                                                 "40 Server error",
                                                 &format!("Rhai script error: {}", e));
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
            if let Ok(content) = fs::read(&full_path) {
                if content.is_empty() {
                    send_empty_response(&mut stream);
                } else {
                    let body = String::from_utf8_lossy(&content);
                    send_response(&mut stream, OK, "OK", &body);
                }
            } else {
                send_tmkup_error(&mut stream, NOT_FOUND,
                                 "31 Not found",
                                 &format!("File '{}' not found", decoded_path));
            }
        }
        None => {
            send_tmkup_error(&mut stream, NOT_FOUND,
                             "31 Not found",
                             &format!("Path '{}' not found", decoded_path));
        }
    }
}

// ---------- Отправка ответа из скрипта ----------
fn send_script_response(stream: &mut TcpStream, resp: Response) {
    let status_text = status_code_to_text(resp.status);
    let status_line = format!("TMUTP/1.0 {} {}\n", resp.status, status_text);
    let mut headers_str = String::new();
    for (k, v) in &resp.headers {
        headers_str.push_str(&format!("{}: {}\n", k, v));
    }
    let body = resp.body.as_deref().unwrap_or(&[]);
    let content_len = format!("Content-Length: {}\n", body.len());
    let response = format!("{}{}{}\n", status_line, headers_str, content_len);
    let _ = stream.write_all(response.as_bytes());
    if !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
}

// ---------- Обычный ответ ----------
fn send_response(stream: &mut TcpStream, code: &str, _name: &str, body: &str) {
    let status_line = format!("TMUTP/1.0 {}\n", code);
    let content_len = format!("Content-Length: {}\n", body.len());
    let response = format!("{}{}\n{}", status_line, content_len, body);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn send_empty_response(stream: &mut TcpStream) {
    let response = format!("TMUTP/1.0 {}\nContent-Length: 0\n", OK_EMPTY);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

// ---------- Ошибка в TMkUp ----------
fn send_tmkup_error(stream: &mut TcpStream, code: &str, title: &str, message: &str) {
    let body = format!(
        "---tmk-meta\ntitle: \"{}\"\n---tmk-meta\n\n# {}\n\n{}\n\n[Back to main](/index.tmkup)",
        title, title, message
    );
    send_response(stream, code, title, &body);
}

// ---------- Разрешение статического пути ----------
fn resolve_path(root: &str, path: &str) -> Option<PathBuf> {
    let mut full = PathBuf::from(root);
    let clean = path.trim_start_matches('/');
    if clean.is_empty() {
        full.push("index.tmkup");
    } else {
        if path.ends_with('/') {
            full.push(clean);
            full.push("index.tmkup");
        } else {
            full.push(clean);
        }
    }
    if full.exists() && full.is_file() {
        Some(full)
    } else {
        None
    }
}

// ---------- Процентное декодирование ----------
fn percent_decode(s: &str) -> String {
    use percent_encoding::percent_decode_str;
    percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}