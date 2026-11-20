use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::Parser;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::BufReader as StdBufReader;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig as TlsServerConfig,
};
use tokio_rustls::TlsAcceptor;
use url::form_urlencoded;

mod script_engine;
use script_engine::{Request, Response, ScriptingConfig, ScriptEngine};
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
    support_first_version: bool,

    #[serde(default)]
    security: SecurityConfig,

    #[serde(default = "default_compression_minimum")]
    compression_minimum: usize,

    #[serde(default = "default_compression_cache")]
    compression_cache: String,
}

fn default_compression_minimum() -> usize {
    1024
}

fn default_compression_cache() -> String {
    "./compression_cache".to_string()
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
    support_first_version: bool,
    compression_minimum: usize,
    compression_cache: PathBuf,
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
const INVALID_RANGE: &str = "52 INVALID RANGE";
const RANGE_NOT_SATISFIABLE: &str = "53 RANGE NOT SATISFIABLE";
const UNSUPPORTED_RANGE: &str = "54 UNSUPPORTED RANGE";
const REQUIRE_SECURE: &str = "55 REQUIRE SECURE";

const TMUTP_VERSION: &str = "TMUTP/2.0";
const TMUTP_FIRST_VERSION: &str = "TMUTP/1.0";

/// Алгоритмы сжатия, которые сервер умеет применять.
/// Порядок в списке не важен — выбор идёт по порядку клиента.
const SUPPORTED_COMPRESSION: &[&str] = &["gzip", "zstd"];

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
        52 => "INVALID RANGE",
        53 => "RANGE NOT SATISFIABLE",
        54 => "UNSUPPORTED RANGE",
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

    fs::create_dir_all(&config.compression_cache).with_context(|| {
        format!(
            "Cannot create compression cache directory: {}",
            config.compression_cache
        )
    })?;

    let state = AppState {
        root: config.root.clone(),
        lua_engine,
        rhai_engine,
        scripting_config: config.scripting.clone(),
        require_secure: config.security.require_secure,
        support_first_version: config.support_first_version,
        compression_minimum: config.compression_minimum,
        compression_cache: PathBuf::from(&config.compression_cache),
    };

    let listener = TcpListener::bind(("0.0.0.0", config.port)).await?;

    println!("TMUTP server listening on port {}", config.port);
    println!("Serving files from {}", config.root);
    println!("Protocol version: {}", TMUTP_VERSION);
    println!(
        "TMUTP/1.0 compatibility: {}",
        state.support_first_version
    );
    println!("TSTS (require_secure): {}", state.require_secure);
    println!("TLS enabled: {}", tls_acceptor.is_some());
    println!("SSH enabled: {}", ssh_config.is_some());
    println!(
        "Compression: {} (minimum {} bytes, cache {})",
        SUPPORTED_COMPRESSION.join(", "),
        state.compression_minimum,
        state.compression_cache.display(),
    );

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
// Compression helpers
// -----------------------------------------------------------------------------

/// Выбирает алгоритм сжатия по заголовку Accept-Compression.
/// Приоритет — порядок клиента. Возвращает имя алгоритма или None.
fn negotiate_compression(accept: Option<&str>) -> Option<&'static str> {
    let value = accept?;

    for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let alg = token.to_ascii_lowercase();

        if let Some(&supported) = SUPPORTED_COMPRESSION
            .iter()
            .find(|&&s| s == alg)
        {
            return Some(supported);
        }
    }

    None
}

/// Сжимает тело выбранным алгоритмом.
/// Возвращает None, если тело пустое или сжатие не удалось.
fn compress_body(body: &[u8], alg: &str) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }

    match alg {
        "gzip" => {
            let mut encoder = flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            );
            encoder.write_all(body).ok()?;
            encoder.finish().ok()
        }
        "zstd" => {
            let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).ok()?;
            encoder.write_all(body).ok()?;
            encoder.finish().ok()
        }
        _ => None,
    }
}

/// Путь к файлу кэша для (source_path, algorithm).
fn cache_path(cache_dir: &Path, source_path: &Path, alg: &str) -> PathBuf {
    let path_hash = Sha256::digest(source_path.to_string_lossy().as_bytes());
    let hex = format!("{:x}", path_hash);
    cache_dir.join(format!("{}.{}", hex, alg))
}

/// Возвращает сжатые данные из кэша или создаёт их.
/// В файле кэша хранится [32 байта SHA-256 исходника][сжатые данные].
/// Если хэш не совпадает — кэш удаляется и пересоздаётся.
fn get_compressed_cached(
    cache_dir: &Path,
    source_path: &Path,
    body: &[u8],
    alg: &str,
) -> Option<Vec<u8>> {
    let cache_file = cache_path(cache_dir, source_path, alg);
    let current_hash = Sha256::digest(body);

    if let Ok(data) = fs::read(&cache_file) {
        if data.len() >= 32 && data[..32] == current_hash[..] {
            return Some(data[32..].to_vec());
        }

        // Кэш устарел — удаляем сразу.
        let _ = fs::remove_file(&cache_file);
    }

    let compressed = compress_body(body, alg)?;

    let mut cache_data = Vec::with_capacity(32 + compressed.len());
    cache_data.extend_from_slice(&current_hash);
    cache_data.extend_from_slice(&compressed);

    // Ошибку записи кэша игнорируем — просто вернём сжатые данные.
    let _ = fs::write(&cache_file, &cache_data);

    Some(compressed)
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

        loop {
            let n = stream.read(&mut chunk).await?;

            if n == 0 {
                stream.shutdown().await?;
                return Ok(());
            }

            buffer.extend_from_slice(&chunk[..n]);

            if buffer.len() > 16 * 1024 * 1024 {
                let response = make_error_response(
                    BAD_REQUEST,
                    "30 Bad request",
                    "The request exceeds the server limit",
                );

                stream.write_all(&response).await?;
                stream.flush().await?;
                stream.shutdown().await?;
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
                                stream.shutdown().await?;
                                return Ok(());
                            }

                            pending.extend_from_slice(&chunk[..n]);

                            if pending.len() > 16 * 1024 * 1024 {
                                stream.shutdown().await?;
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

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

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
            let response = process_request(&request, &self.state);

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

    let request_line = raw[..header_end]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();

    let request_version = match std::str::from_utf8(request_line) {
        Ok(line) => line.trim().split_whitespace().next(),
        Err(_) => None,
    };

    let response_version = match request_version {
        Some("TMUTP/2.0") => TMUTP_VERSION,
        Some("TMUTP/1.0") if state.support_first_version => TMUTP_FIRST_VERSION,
        Some("TMUTP/1.0") => {
            return make_version_error_response(
                TMUTP_VERSION,
                "TMUTP/1.0 support is disabled on this server",
            );
        }
        Some(_) => {
            return make_version_error_response(
                TMUTP_VERSION,
                "Server supports TMUTP/2.0",
            );
        }
        None => {
            return make_error_response(
                BAD_REQUEST,
                "30 Bad request",
                "Request line is missing or invalid",
            );
        }
    };

    let mut response = process_request_inner(raw, state);

    replace_response_version(&mut response, response_version);

    response
}

fn replace_response_version(response: &mut Vec<u8>, version: &str) {
    let header_end = response.iter().position(|byte| *byte == b'\n');

    let Some(line_end) = header_end else {
        return;
    };

    let first_line = &response[..line_end];

    let Some(space_position) = first_line.iter().position(|byte| *byte == b' ') else {
        return;
    };

    response.splice(
        0..space_position,
        version.as_bytes().iter().copied(),
    );
}

fn make_version_error_response(version: &str, message: &str) -> Vec<u8> {
    let body = format!(
        "---tmk-meta\ntitle: \"51 Version not supported\"\n---tmk-meta\n\n# 51 Version not supported\n\n{}\n",
        message
    );

    let header = format!(
        "{} 51 VERSION NOT SUPPORTED\nContent-Type: text/tmkup\nContent-Length: {}\n\n",
        version,
        body.len()
    );

    let mut response = header.into_bytes();
    response.extend_from_slice(body.as_bytes());
    response
}

fn process_request_inner(raw: &[u8], state: &AppState) -> Vec<u8> {
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

    if parts.len() != 3 {
        return make_error_response(
            BAD_REQUEST,
            "30 Bad request",
            "Request must contain version, method and path",
        );
    }

    let method = parts[1];
    let raw_path = parts[2];

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

    // Сохраняем Range до перемещения request_headers в Request.
    let range_header = request_headers.get("range").cloned();

    // Переговоры о сжатии.
    let accept_compression_header = request_headers.get("accept-compression").cloned();
    let accept_compression_present = accept_compression_header.is_some();
    let compression = negotiate_compression(accept_compression_header.as_deref());

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
                            Ok(Some(response)) => make_script_response(
                                response,
                                compression,
                                state.compression_minimum,
                                accept_compression_present,
                            ),
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
                            Ok(Some(response)) => make_script_response(
                                response,
                                compression,
                                state.compression_minimum,
                                accept_compression_present,
                            ),
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
                let modified = fs::metadata(&full_path)
                    .ok()
                    .and_then(|metadata| metadata.modified().ok());

                if method == "GET" {
                    if let Some(range_value) = range_header.as_deref() {
                        return make_range_response(
                            &content,
                            modified,
                            range_value,
                            compression,
                            state.compression_minimum,
                            accept_compression_present,
                        );
                    }
                }

                make_file_response(
                    &content,
                    modified,
                    compression,
                    state.compression_minimum,
                    &state.compression_cache,
                    &full_path,
                    accept_compression_present,
                )
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
// Range support
// -----------------------------------------------------------------------------

enum RangeParseResult {
    Valid(usize, usize),
    Invalid,
    Unsupported,
}

fn parse_range(value: &str) -> RangeParseResult {
    let Some((unit, range)) = value.trim().split_once('=') else {
        return RangeParseResult::Invalid;
    };

    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return RangeParseResult::Unsupported;
    }

    let range = range.trim();

    // TMUTP/2.0 currently supports exactly one bytes=start-end range.
    if range.contains(',') {
        return RangeParseResult::Unsupported;
    }

    let Some((start, end)) = range.split_once('-') else {
        return RangeParseResult::Unsupported;
    };

    // Open-ended and suffix ranges are not supported by this form.
    if start.is_empty() || end.is_empty() {
        return RangeParseResult::Unsupported;
    }

    let start = match start.parse::<usize>() {
        Ok(value) => value,
        Err(_) => return RangeParseResult::Invalid,
    };

    let end = match end.parse::<usize>() {
        Ok(value) => value,
        Err(_) => return RangeParseResult::Invalid,
    };

    if start > end {
        return RangeParseResult::Invalid;
    }

    RangeParseResult::Valid(start, end)
}

fn make_range_response(
    content: &[u8],
    modified: Option<SystemTime>,
    range_header: &str,
    compression: Option<&str>,
    compression_minimum: usize,
    announce_compression: bool,
) -> Vec<u8> {
    let source_length = content.len();

    let (start, end) = match parse_range(range_header) {
        RangeParseResult::Valid(start, end) => (start, end),

        RangeParseResult::Invalid => {
            return make_range_error_response(
                INVALID_RANGE,
                range_header,
                "invalid-range",
                source_length,
            );
        }

        RangeParseResult::Unsupported => {
            let reason = if range_header.contains(',') {
                "multiple-ranges-not-supported"
            } else {
                "range-form-not-supported"
            };

            return make_range_error_response(
                UNSUPPORTED_RANGE,
                range_header,
                reason,
                source_length,
            );
        }
    };

    if start >= source_length || end >= source_length {
        return make_range_error_response(
            RANGE_NOT_SATISFIABLE,
            range_header,
            "outside-source",
            source_length,
        );
    }

    let range_content = &content[start..=end];

    // Сжатие range-фрагмента (без кэша — фрагменты разные).
    let (body, content_encoding) = if let Some(alg) = compression {
        if range_content.len() >= compression_minimum {
            match compress_body(range_content, alg) {
                Some(data) => (data, Some(alg)),
                None => (range_content.to_vec(), None),
            }
        } else {
            (range_content.to_vec(), None)
        }
    } else {
        (range_content.to_vec(), None)
    };

    let hash = Sha256::digest(content);
    let hash_hex = format!("{:x}", hash);

    let mut header = format!(
        "{} {}\n\
         Content-Type: text/tmkup\n\
         Content-Length: {}\n\
         Content-Range: bytes {}-{}/{}\n\
         FILE-SHA256: {}\n\
         SOURCE-CONTENT-LENGTH: {}\n",
        TMUTP_VERSION,
        OK,
        body.len(),
        start,
        end,
        source_length,
        hash_hex,
        source_length,
    );

    if announce_compression {
        header.push_str(&format!(
            "Supported-Compression: {}\n",
            SUPPORTED_COMPRESSION.join(", ")
        ));
    }

    if let Some(alg) = content_encoding {
        header.push_str(&format!("Content-Encoding: {}\n", alg));
    }

    if let Some(modified) = modified {
        let date: DateTime<Utc> = modified.into();

        header.push_str(&format!(
            "Last-Modified: {}\n",
            date.format("%Y-%m-%d")
        ));
    }

    header.push('\n');

    let mut response = header.into_bytes();
    response.extend_from_slice(&body);

    response
}

fn make_range_error_response(
    status: &str,
    requested_range: &str,
    reason: &str,
    source_length: usize,
) -> Vec<u8> {
    let (title, heading, message) = match status {
        INVALID_RANGE => (
            "52 — Invalid Range",
            "52 Invalid Range",
            "The requested byte range is invalid.",
        ),
        RANGE_NOT_SATISFIABLE => (
            "53 — Range Not Satisfiable",
            "53 Range Not Satisfiable",
            "The requested range is not available.",
        ),
        UNSUPPORTED_RANGE => (
            "54 — Unsupported Range",
            "54 Unsupported Range",
            "The requested range form is not supported.",
        ),
        _ => (
            "Range Error",
            "Range Error",
            "The requested byte range cannot be provided.",
        ),
    };

    let body = format!(
        "---tmk-meta\n\
         title: \"{}\"\n\
         ---tmk-meta\n\n\
         # {}\n\n\
         {}\n",
        title,
        heading,
        message,
    );

    let header = format!(
        "{} {}\n\
         Content-Type: text/tmkup\n\
         Content-Length: {}\n\
         SOURCE-CONTENT-LENGTH: {}\n\
         Range-Error: {}; {}\n\n",
        TMUTP_VERSION,
        status,
        body.len(),
        source_length,
        requested_range,
        reason,
    );

    let mut response = header.into_bytes();
    response.extend_from_slice(body.as_bytes());

    response
}

// -----------------------------------------------------------------------------
// Response builders
// -----------------------------------------------------------------------------

fn make_script_response(
    response: Response,
    compression: Option<&str>,
    compression_minimum: usize,
    announce_compression: bool,
) -> Vec<u8> {
    let status_text = status_code_to_text(response.status);
    let status_line = format!(
        "{} {} {}\n",
        TMUTP_VERSION,
        response.status,
        status_text
    );

    let mut output = status_line;
    let mut has_content_type = false;
    let mut has_content_encoding = false;

    for (key, value) in &response.headers {
        if key.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }

        if key.eq_ignore_ascii_case("content-encoding") {
            has_content_encoding = true;
        }

        output.push_str(&format!("{}: {}\n", key, value));
    }

    if !has_content_type {
        output.push_str("Content-Type: text/tmkup\n");
    }

    if announce_compression {
        output.push_str(&format!(
            "Supported-Compression: {}\n",
            SUPPORTED_COMPRESSION.join(", ")
        ));
    }

    let original_body = response.body.as_deref().unwrap_or(&[]);

    // Сжимаем только если скрипт сам не выставил Content-Encoding.
    let (body, content_encoding) = if !has_content_encoding {
        if let Some(alg) = compression {
            if original_body.len() >= compression_minimum {
                match compress_body(original_body, alg) {
                    Some(data) => (data, Some(alg)),
                    None => (original_body.to_vec(), None),
                }
            } else {
                (original_body.to_vec(), None)
            }
        } else {
            (original_body.to_vec(), None)
        }
    } else {
        (original_body.to_vec(), None)
    };

    if let Some(alg) = content_encoding {
        output.push_str(&format!("Content-Encoding: {}\n", alg));
    }

    output.push_str(&format!("Content-Length: {}\n\n", body.len()));

    let mut bytes = output.into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

fn make_response(status: &str, body: &[u8]) -> Vec<u8> {
    let header = format!(
        "{} {}\n\
         Content-Type: text/tmkup\n\
         Content-Length: {}\n\n",
        TMUTP_VERSION,
        status,
        body.len()
    );

    let mut response = header.into_bytes();
    response.extend_from_slice(body);
    response
}

fn make_file_response(
    content: &[u8],
    modified: Option<SystemTime>,
    compression: Option<&str>,
    compression_minimum: usize,
    cache_dir: &Path,
    source_path: &Path,
    announce_compression: bool,
) -> Vec<u8> {
    let status = if content.is_empty() {
        OK_EMPTY
    } else {
        OK
    };

    let hash = Sha256::digest(content);
    let hash_hex = format!("{:x}", hash);

    // Сжатие тела (с кэшем по пути исходного файла).
    let (body, content_encoding) = if let Some(alg) = compression {
        if content.len() >= compression_minimum {
            match get_compressed_cached(cache_dir, source_path, content, alg) {
                Some(data) => (data, Some(alg)),
                None => (content.to_vec(), None),
            }
        } else {
            (content.to_vec(), None)
        }
    } else {
        (content.to_vec(), None)
    };

    let mut header = format!(
        "{} {}\n\
         Content-Type: text/tmkup\n\
         Content-Length: {}\n\
         FILE-SHA256: {}\n\
         SOURCE-CONTENT-LENGTH: {}\n",
        TMUTP_VERSION,
        status,
        body.len(),
        hash_hex,
        content.len(),
    );

    if announce_compression {
        header.push_str(&format!(
            "Supported-Compression: {}\n",
            SUPPORTED_COMPRESSION.join(", ")
        ));
    }

    if let Some(alg) = content_encoding {
        header.push_str(&format!("Content-Encoding: {}\n", alg));
    }

    if let Some(modified) = modified {
        let date: DateTime<Utc> = modified.into();

        header.push_str(&format!(
            "Last-Modified: {}\n",
            date.format("%Y-%m-%d")
        ));
    }

    header.push('\n');

    let mut response = header.into_bytes();
    response.extend_from_slice(&body);

    response
}

fn make_empty_response() -> Vec<u8> {
    make_response(OK_EMPTY, &[])
}

fn make_error_response(
    status: &str,
    title: &str,
    message: &str,
) -> Vec<u8> {
    let body = format!(
        "---tmk-meta\n\
         title: \"{}\"\n\
         ---tmk-meta\n\n\
         # {}\n\n\
         {}\n\n\
         [Back to main](/index.tmkup)",
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

    let normalized_path = path.replace('\\', "/");
    let is_directory = normalized_path.is_empty() || normalized_path.ends_with('/');

    let mut relative = PathBuf::new();

    for component in PathBuf::from(&normalized_path).components() {
        match component {
            Component::Prefix(_) => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "Path is outside root",
                ));
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