
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::Parser;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader as StdBufReader;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig as TlsServerConfig,
};
use tokio_rustls::TlsAcceptor;
use url::form_urlencoded;

mod script_engine;
use script_engine::{ScriptEngine, Request, Response, ScriptingConfig};
use script_engine::lua::LuaEngine;
use script_engine::rhai::RhaiEngine;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Config {
    port: u16,
    root: String,
    scripting: ScriptingConfig,

    #[serde(default)]
    security: SecurityConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct SecurityConfig {
    #[serde(default)]
    require_secure: bool,

    #[serde(default)]
    enable_ssh: bool,

    #[serde(default)]
    enable_tls: bool,

    #[serde(default)]
    tls_public_path: String,

    #[serde(default)]
    tls_private_path: String,

    #[serde(default = "default_ssh_host_key_path")]
    ssh_host_key_path: String,
}

fn default_ssh_host_key_path() -> String {
    "./ssh_host_ed25519_key".to_string()
}

#[derive(Parser, Debug)]
#[command(author, version, about = "TMUTP server (TMkUp Transfer Protocol)")]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "./tmutp-config.toml")]
    config: String,
}

#[derive(Clone)]
struct AppState {
    root: String,
    lua_engine: Option<Arc<LuaEngine>>,
    rhai_engine: Option<Arc<RhaiEngine>>,
    scripting_config: ScriptingConfig,
    require_secure: bool,
}

// -----------------------------------------------------------------------------
// TMUTP status codes
// -----------------------------------------------------------------------------

const OK: &str = "20 OK";
const OK_EMPTY: &str = "22 OK EMPTY";
const BAD_REQUEST: &str = "30 BAD REQUEST";
const NOT_FOUND: &str = "31 NOT FOUND";
const FORBIDDEN: &str = "32 FORBIDDEN";
const SERVER_ERROR: &str = "40 SERVER ERROR";
const METHOD_NOT_ALLOWED: &str = "50 METHOD NOT ALLOWED";
const VERSION_NOT_SUPPORTED: &str = "51 VERSION NOT SUPPORTED";
const REQUIRE_SECURE: &str = "55 REQUIRE SECURE";

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
        55 => "REQUIRE SECURE",
        _ => "UNKNOWN",
    }
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config_content = fs::read_to_string(&args.config)
        .with_context(|| format!("Failed to read config: {}", args.config))?;

    let config: Config =
        toml::from_str(&config_content).context("Failed to parse TMUTP config")?;

    let lua_engine = if config.scripting.enabled {
        let ext = config.scripting.lua_extension
            .clone()
            .unwrap_or_else(|| ".script.lua".to_string());

        let hot_reload = config.scripting.hot_reload.unwrap_or(true);

        Some(Arc::new(LuaEngine::new(
            &config.root,
            Some(ext),
            hot_reload,
        )))
    } else {
        None
    };

    let rhai_engine = if config.scripting.enabled {
        let ext = config.scripting.rhai_extension
            .clone()
            .unwrap_or_else(|| ".script.rhai".to_string());

        let hot_reload = config.scripting.hot_reload.unwrap_or(true);

        Some(Arc::new(RhaiEngine::new(
            &config.root,
            Some(ext),
            hot_reload,
        )))
    } else {
        None
    };

    let tls_acceptor = if config.security.enable_tls {
        Some(load_tls_acceptor(&config.security)?)
    } else {
        None
    };

    let ssh_config = if config.security.enable_ssh {
        Some(load_ssh_config(&config.security)?)
    } else {
        None
    };

    let state = AppState {
        root: config.root.clone(),
        lua_engine,
        rhai_engine,
        scripting_config: config.scripting.clone(),
        require_secure: config.security.require_secure,
    };

    let listener = TcpListener::bind(("0.0.0.0", config.port)).await?;

    println!("TMUTP server listening on port {}", config.port);
    println!("Serving files from {}", config.root);
    println!("TSTS (require_secure): {}", state.require_secure);
    println!("TLS enabled: {}", tls_acceptor.is_some());
    println!("SSH enabled: {}", ssh_config.is_some());

    if config.scripting.enabled {
        println!(
            "Scripting enabled (Lua: {}, Rhai: {})",
            state.lua_engine.is_some(),
            state.rhai_engine.is_some()
        );

        println!(
            "hide_scripts_behind: {}",
            state.scripting_config.hide_scripts_behind.unwrap_or(true)
        );
    } else {
        println!("Scripting disabled");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tls = tls_acceptor.clone();
        let ssh = ssh_config.clone();

        tokio::spawn(async move {
            if let Err(error) = dispatch_connection(stream, state, tls, ssh).await {
                eprintln!("Connection from {} failed: {:#}", peer, error);
            }
        });
    }
}

// -----------------------------------------------------------------------------
// TLS / SSH configuration
// -----------------------------------------------------------------------------

fn load_tls_acceptor(security: &SecurityConfig) -> Result<TlsAcceptor> {
    if security.tls_public_path.is_empty() || security.tls_private_path.is_empty() {
        return Err(anyhow!(
            "enable_tls=true requires tls_public_path and tls_private_path"
        ));
    }

    let cert_file = fs::File::open(&security.tls_public_path)
        .with_context(|| format!("Cannot open TLS certificate: {}", security.tls_public_path))?;

    let mut cert_reader = StdBufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<_, _>>()?;

    if certs.is_empty() {
        return Err(anyhow!("TLS certificate file contains no certificates"));
    }

    let key_file = fs::File::open(&security.tls_private_path)
        .with_context(|| format!("Cannot open TLS private key: {}", security.tls_private_path))?;

    let mut key_reader = StdBufReader::new(key_file);

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow!("TLS private key file contains no supported key"))?;

    let tls_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS certificate and private key are invalid or do not match")?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

fn load_ssh_config(
    security: &SecurityConfig,
) -> Result<Arc<russh::server::Config>> {
    let path = &security.ssh_host_key_path;

    let key = russh::keys::load_secret_key(path, None)
        .with_context(|| format!("Cannot load SSH host key: {}", path))?;

    let mut methods = russh::MethodSet::empty();
    methods.push(MethodKind::None);

    let config = russh::server::Config {
        methods,
        keys: vec![key],
        ..Default::default()
    };

    Ok(Arc::new(config))
}

// -----------------------------------------------------------------------------
// Transport detection and dispatch
// -----------------------------------------------------------------------------

async fn sniff_transport(stream: &TcpStream) -> Result<&'static str> {
    let mut peek = [0u8; 8];

    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async {
            loop {
                let n = stream.peek(&mut peek).await?;

                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Client closed before sending data",
                    ));
                }

                if n >= 4 || (n >= 2 && peek[0] == 0x16) {
                    return Ok(n);
                }

                tokio::task::yield_now().await;
            }
        },
    )
    .await
    .context("Timed out while detecting transport")??;

    if n >= 4 && &peek[..4] == b"SSH-" {
        return Ok("ssh");
    }

    if n >= 2 && peek[0] == 0x16 && peek[1] == 0x03 {
        return Ok("tls");
    }

    Ok("plain")
}

async fn dispatch_connection(
    stream: TcpStream,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    ssh_config: Option<Arc<russh::server::Config>>,
) -> Result<()> {
    stream.set_nodelay(true)?;

    match sniff_transport(&stream).await? {
        "tls" => {
            let acceptor = tls_acceptor
                .ok_or_else(|| anyhow!("TLS connection received, but TLS is disabled"))?;

            let tls_stream = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                acceptor.accept(stream),
            )
            .await
            .context("TLS handshake timed out")??;

            serve_stream(tls_stream, state, true).await?;
        }

        "ssh" => {
            let config = ssh_config
                .ok_or_else(|| anyhow!("SSH connection received, but SSH is disabled"))?;

            let handler = TmutpSshHandler {
                state,
                buffers: HashMap::new(),
            };

            let session =
                russh::server::run_stream(config, stream, handler).await?;

            session.await?;
        }

        _ => {
            serve_stream(stream, state, false).await?;
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// TCP / TLS stream processing
// -----------------------------------------------------------------------------

async fn serve_stream<S>(
    mut stream: S,
    state: AppState,
    secure_transport: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];

        // Read enough bytes to determine the complete TMUTP request.
        loop {
            let n = stream.read(&mut chunk).await?;

            if n == 0 {
                return Ok(());
            }

            buffer.extend_from_slice(&chunk[..n]);

            if buffer.len() > 16 * 1024 * 1024 {
                let response = make_error_response(
                    BAD_REQUEST,
                    "Request too large",
                    "The request exceeds the server limit",
                );

                stream.write_all(&response).await?;
                stream.flush().await?;
                return Ok(());
            }

            if let Some(frame_len) = complete_request_len(&buffer) {
                if buffer.len() >= frame_len {
                    let request: Vec<u8> = buffer.drain(..frame_len).collect();

                    let response = if state.require_secure && !secure_transport {
                        make_error_response(
                            REQUIRE_SECURE,
                            "55 Require secure",
                            "This server requires an encrypted transport",
                        )
                    } else {
                        process_request(&request, &state)
                    };

                    stream.write_all(&response).await?;
                    stream.flush().await?;

                    // Preserve any bytes read beyond the first request.
                    // They are processed as the next request on this connection.
                    if !buffer.is_empty() {
                        let mut pending = buffer;
                        loop {
                            if let Some(frame_len) = complete_request_len(&pending) {
                                if pending.len() >= frame_len {
                                    let request: Vec<u8> =
                                        pending.drain(..frame_len).collect();

                                    let response = if state.require_secure && !secure_transport {
                                        make_error_response(
                                            REQUIRE_SECURE,
                                            "55 Require secure",
                                            "This server requires an encrypted transport",
                                        )
                                    } else {
                                        process_request(&request, &state)
                                    };

                                    stream.write_all(&response).await?;
                                    stream.flush().await?;
                                    continue;
                                }
                            }

                            let n = stream.read(&mut chunk).await?;
                            if n == 0 {
                                return Ok(());
                            }

                            pending.extend_from_slice(&chunk[..n]);

                            if pending.len() > 16 * 1024 * 1024 {
                                return Ok(());
                            }
                        }
                    }

                    break;
                }
            }
        }
    }
}

// -----------------------------------------------------------------------------
// SSH transport
// SSH channel data is TMUTP input/output. No operating-system shell is started.
// -----------------------------------------------------------------------------

struct TmutpSshHandler {
    state: AppState,
    buffers: HashMap<ChannelId, Vec<u8>>,
}

impl Handler for TmutpSshHandler {
    type Error = russh::Error;

    async fn auth_none(
        &mut self,
        _user: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.buffers.insert(channel.id(), Vec::new());
        reply.accept().await;
        Ok(())
    }

    // ssh -T without a remote command requests a session shell.
    // Accept the channel request, but do NOT start a system shell.
    // Channel data remains a raw TMUTP byte stream.
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    // No PTY is needed. ssh -T does not request one.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let buffer = self.buffers.entry(channel).or_default();

        buffer.extend_from_slice(data);

        if buffer.len() > 16 * 1024 * 1024 {
            self.buffers.remove(&channel);
            session.close(channel)?;
            return Ok(());
        }

        while let Some(frame_len) = complete_request_len(buffer) {
            if buffer.len() < frame_len {
                break;
            }

            let request: Vec<u8> = buffer.drain(..frame_len).collect();

            let response = if self.state.require_secure {
                // SSH is an encrypted transport.
                process_request(&request, &self.state)
            } else {
                process_request(&request, &self.state)
            };

            session.data(channel, Bytes::from(response))?;
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.buffers.remove(&channel);
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// TMUTP request framing
// A request ends after its header terminator and Content-Length bytes.
// -----------------------------------------------------------------------------

fn complete_request_len(buffer: &[u8]) -> Option<usize> {
    let first_end = buffer.iter().position(|byte| *byte == b'\n')? + 1;

    let mut position = first_end;
    let mut content_length = 0usize;

    loop {
        let relative = buffer.get(position..)?
            .iter()
            .position(|byte| *byte == b'\n')?;

        let end = position + relative + 1;
        let line = &buffer[position..end];

        if line == b"\n" || line == b"\r\n" {
            return Some(end.checked_add(content_length)?);
        }

        if let Ok(line) = std::str::from_utf8(line) {
            if let Some((key, value)) = line.trim().split_once(':') {
                if key.trim().eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse::<usize>().ok()?;
                }
            }
        }

        position = end;
    }
}

// -----------------------------------------------------------------------------
// TMUTP request processing
// This function is shared by TCP, TLS and SSH.
// -----------------------------------------------------------------------------

fn process_request(raw: &[u8], state: &AppState) -> Vec<u8> {
    let header_end = match find_header_end(raw) {
        Some(end) => end,
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Request headers are incomplete",
            );
        }
    };

    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();

    let request_line = match lines.next() {
        Some(line) => line.trim(),
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Request line is missing",
            );
        }
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();

    if parts.len() < 3 {
        return make_error_response(
            BAD_REQUEST,
            "30 Bad request",
            "Request must contain version, method and path",
        );
    }

    let version = parts[0];
    let method = parts[1];
    let raw_path = parts[2];

    if version != "TMUTP/1.0" {
        return make_error_response(
            VERSION_NOT_SUPPORTED,
            "51 Version not supported",
            "Server supports only TMUTP/1.0",
        );
    }

    if method != "GET" && method != "POST" {
        return make_error_response(
            METHOD_NOT_ALLOWED,
            "50 Method not allowed",
            "TMUTP supports only GET and POST",
        );
    }

    let (path, query_str) = if let Some(pos) = raw_path.find('?') {
        let (path, query) = raw_path.split_at(pos);
        (path, Some(&query[1..]))
    } else {
        (raw_path, None)
    };

    let decoded_path = percent_decode(path);

    let query_params = if let Some(query) = query_str {
        form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>()
    } else {
        HashMap::new()
    };

    let mut request_headers = HashMap::new();
    let mut content_length = 0usize;
    let mut content_length_found = false;

    for line in lines {
        let line = line.trim();

        if line.is_empty() {
            break;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();

            if key == "content-length" {
                content_length = match value.parse::<usize>() {
                    Ok(value) => value,
                    Err(_) => {
                        return make_error_response(
                            BAD_REQUEST,
                            "30 Bad request",
                            "Invalid Content-Length header",
                        );
                    }
                };

                content_length_found = true;
            }

            request_headers.insert(key, value);
        }
    }

    if method == "POST" && !content_length_found {
        return make_error_response(
            BAD_REQUEST,
            "30 Bad request",
            "POST request must include Content-Length header",
        );
    }

    let body_start = header_end;
    let body_end = match body_start.checked_add(content_length) {
        Some(end) => end,
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Invalid request body length",
            );
        }
    };

    if raw.len() < body_end {
        return make_error_response(
            BAD_REQUEST,
            "30 Bad request",
            "Request body is incomplete",
        );
    }

    let body_bytes = raw[body_start..body_end].to_vec();

    let form_params = if method == "POST" && !body_bytes.is_empty() {
        let body = String::from_utf8_lossy(&body_bytes);

        form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect::<HashMap<String, String>>()
    } else {
        HashMap::new()
    };

    // Script path normalization
    let mut script_path = decoded_path.clone();

    if state.scripting_config.hide_scripts_behind.unwrap_or(true) {
        let lua_ext = state.scripting_config.lua_extension
            .clone()
            .unwrap_or_else(|| ".script.lua".to_string());

        let rhai_ext = state.scripting_config.rhai_extension
            .clone()
            .unwrap_or_else(|| ".script.rhai".to_string());

        if script_path.ends_with(&lua_ext) {
            script_path = script_path
                .trim_end_matches(&lua_ext)
                .to_string();
        } else if script_path.ends_with(&rhai_ext) {
            script_path = script_path
                .trim_end_matches(&rhai_ext)
                .to_string();
        }

        if script_path.is_empty() {
            script_path = "/".to_string();
        }
    }

    let request = Request {
        protocol: "tmutp".to_string(),
        method: method.to_string(),
        path: decoded_path.clone(),
        query: query_params,
        body: body_bytes,
        form: form_params,
        headers: request_headers,
    };

    // Script engines
    if state.scripting_config.enabled {
        let order = state.scripting_config.order
            .clone()
            .unwrap_or_else(|| vec!["lua".to_string(), "rhai".to_string()]);

        for engine_name in &order {
            if engine_name == "lua" {
                if let Some(engine) = &state.lua_engine {
                    if engine.has_script(&script_path) {
                        return match engine.execute(&script_path, &request) {
                            Ok(Some(response)) => make_script_response(response),
                            Ok(None) => make_empty_response(),
                            Err(error) => {
                                eprintln!("Lua script error: {}", error);

                                make_error_response(
                                    SERVER_ERROR,
                                    "40 Server error",
                                    &format!("Lua script error: {}", error),
                                )
                            }
                        };
                    }
                }
            } else if engine_name == "rhai" {
                if let Some(engine) = &state.rhai_engine {
                    if engine.has_script(&script_path) {
                        return match engine.execute(&script_path, &request) {
                            Ok(Some(response)) => make_script_response(response),
                            Ok(None) => make_empty_response(),
                            Err(error) => {
                                eprintln!("Rhai script error: {}", error);

                                make_error_response(
                                    SERVER_ERROR,
                                    "40 Server error",
                                    &format!("Rhai script error: {}", error),
                                )
                            }
                        };
                    }
                }
            }
        }
    }

    // Static files
    match resolve_path(&state.root, &decoded_path) {
        Ok(Some(full_path)) => match fs::read(&full_path) {
            Ok(content) => {
                if content.is_empty() {
                    make_empty_response()
                } else {
                    make_response(OK, &content)
                }
            }

            Err(error) => {
                eprintln!("Failed to read file '{}': {}", full_path.display(), error);

                make_error_response(
                    SERVER_ERROR,
                    "40 Server error",
                    "Failed to read requested file",
                )
            }
        },

        Ok(None) => make_error_response(
            NOT_FOUND,
            "31 Not found",
            &format!("Path '{}' not found", decoded_path),
        ),

        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            make_error_response(
                FORBIDDEN,
                "32 Forbidden",
                "Access to the requested path is forbidden",
            )
        }

        Err(error) => {
            eprintln!("Path resolution failed for '{}': {}", decoded_path, error);

            make_error_response(
                SERVER_ERROR,
                "40 Server error",
                "Failed to resolve requested path",
            )
        }
    }
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            raw.windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        })
}

// -----------------------------------------------------------------------------
// Response builders
// -----------------------------------------------------------------------------

fn make_script_response(response: Response) -> Vec<u8> {
    let status_text = status_code_to_text(response.status);
    let status_line = format!(
        "TMUTP/1.0 {} {}\n",
        response.status,
        status_text
    );

    let mut output = status_line;

    for (key, value) in &response.headers {
        output.push_str(&format!("{}: {}\n", key, value));
    }

    let body = response.body.as_deref().unwrap_or(&[]);

    output.push_str(&format!("Content-Length: {}\n\n", body.len()));

    let mut bytes = output.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn make_response(status: &str, body: &[u8]) -> Vec<u8> {
    let header = format!(
        "TMUTP/1.0 {}\nContent-Length: {}\n\n",
        status,
        body.len()
    );

    let mut response = header.into_bytes();
    response.extend_from_slice(body);
    response
}

fn make_empty_response() -> Vec<u8> {
    b"TMUTP/1.0 22 OK EMPTY\nContent-Length: 0\n\n".to_vec()
}

fn make_error_response(
    status: &str,
    title: &str,
    message: &str,
) -> Vec<u8> {
    let body = format!(
        "---tmk-meta\ntitle: \"{}\"\n---tmk-meta\n\n# {}\n\n{}\n\n[Back to main](/index.tmkup)",
        title,
        title,
        message
    );

    make_response(status, body.as_bytes())
}

// -----------------------------------------------------------------------------
// Filesystem and URL helpers
// -----------------------------------------------------------------------------

fn resolve_path(root: &str, path: &str) -> std::io::Result<Option<PathBuf>> {
    use std::io::{Error, ErrorKind};
    use std::path::Component;

    let canonical_root = fs::canonicalize(root)?;

    // Обратные слеши тоже считаем разделителями пути.
    let normalized_path = path.replace('\\', "/");
    let is_directory = normalized_path.is_empty() || normalized_path.ends_with('/');

    let mut relative = PathBuf::new();

    // Сначала проверяем выход за root лексически.
    // Это важно: canonicalize() сам по себе вернёт NotFound,
    // если атакующий указал несуществующий путь за пределами root.
    for component in PathBuf::from(&normalized_path).components() {
        match component {
            Component::Prefix(_) => {
                return Err(Error::new(ErrorKind::PermissionDenied, "Path is outside root"));
            }
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir => {
                if !relative.pop() {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "Path is outside root",
                    ));
                }
            }
        }
    }

    if is_directory {
        relative.push("index.tmkup");
    }

    if relative.as_os_str().is_empty() {
        relative.push("index.tmkup");
    }

    // Затем проверяем реальные пути с учётом симлинков.
    let mut current = canonical_root.clone();
    let components: Vec<_> = relative.components().collect();

    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            continue;
        };

        current.push(part);

        match fs::symlink_metadata(&current) {
            Ok(_) => {
                let canonical = fs::canonicalize(&current)?;

                if !canonical.starts_with(&canonical_root) {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "Path is outside root",
                    ));
                }

                current = canonical;

                if index + 1 < components.len() && !current.is_dir() {
                    return Ok(None);
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    }

    if current.is_file() {
        Ok(Some(current))
    } else {
        Ok(None)
    }
}

fn percent_decode(value: &str) -> String {
    use percent_encoding::percent_decode_str;

    percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}
