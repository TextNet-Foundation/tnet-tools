use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::Parser;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader as StdBufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig as TlsServerConfig,
};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    support_first_version: bool,
    protocols: Vec<Protocol>,
    #[serde(default)]
    explore: ExploreConfig,
    #[serde(default)]
    security: SecurityConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct SecurityConfig {
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

#[derive(Debug, Deserialize, Default, Clone)]
struct ExploreConfig {
    #[serde(default)]
    nodes: Vec<ExploreNode>,
}

#[derive(Debug, Deserialize, Clone)]
struct ExploreNode {
    version: String,
    host: String,
    description: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Protocol {
    name: String,
    version: String,
    host: String,
    port: u16,
    #[serde(default)]
    security: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "./utnp-config.toml")]
    config: String,
}

#[derive(Clone)]
struct AppState {
    protocols: Arc<Vec<Protocol>>,
    explore_nodes: Arc<Vec<ExploreNode>>,
    support_first_version: bool,
    enabled_security: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config_content = fs::read_to_string(&args.config)
        .with_context(|| format!("Cannot read config file: {}", args.config))?;
    let config: Config = toml::from_str(&config_content).context("Invalid UTNP config")?;

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

    let mut enabled_security = Vec::new();
    if tls_acceptor.is_some() {
        enabled_security.push("tls".to_string());
    }
    if ssh_config.is_some() {
        enabled_security.push("ssh".to_string());
    }

    let state = AppState {
        protocols: Arc::new(config.protocols),
        explore_nodes: Arc::new(config.explore.nodes),
        support_first_version: config.support_first_version,
        enabled_security,
    };

    let listener = TcpListener::bind("0.0.0.0:34").await?;
    println!("UTNP server listening on port 34");
    println!("Loaded {} protocols", state.protocols.len());
    println!(
        "UTNP/2.0 enabled; UTNP/1.0 compatibility: {}",
        state.support_first_version
    );
    println!("TLS enabled: {}", tls_acceptor.is_some());
    println!("SSH enabled: {}", ssh_config.is_some());
    if ssh_config.is_some() {
        println!("SSH authentication: none (transport only)");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tls_acceptor = tls_acceptor.clone();
        let ssh_config = ssh_config.clone();
        tokio::spawn(async move {
            if let Err(error) = dispatch_connection(
                stream,
                peer,
                state,
                tls_acceptor,
                ssh_config,
            )
            .await
            {
                eprintln!("{peer}: {error:#}");
            }
        });
    }
}

fn load_tls_acceptor(security: &SecurityConfig) -> Result<TlsAcceptor> {
    if security.tls_public_path.is_empty() || security.tls_private_path.is_empty() {
        return Err(anyhow!(
            "enable_tls=true requires tls_public_path and tls_private_path"
        ));
    }
    let cert_file = fs::File::open(&security.tls_public_path)
        .with_context(|| format!("Cannot open TLS certificate: {}", security.tls_public_path))?;
    let mut cert_reader = StdBufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("TLS certificate file contains no certificates"));
    }

    let key_file = fs::File::open(&security.tls_private_path)
        .with_context(|| format!("Cannot open TLS private key: {}", security.tls_private_path))?;
    let mut key_reader = StdBufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("TLS private key file contains no supported private key"))?;

    let tls_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS certificate and private key do not match or are invalid")?;
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

fn load_ssh_config(security: &SecurityConfig) -> Result<Arc<russh::server::Config>> {
    let path = &security.ssh_host_key_path;
    let key = russh::keys::load_secret_key(path, None)
        .with_context(|| format!("Cannot load SSH host key: {path}"))?;

    // SSH's "none" authentication is intentionally enabled: SSH supplies the
    // encrypted, integrity-protected transport and the host key authenticates
    // the server. UTNP itself has no user-authentication layer.
    let mut methods = russh::MethodSet::empty();
    methods.push(MethodKind::None);
    let config = russh::server::Config {
        methods,
        keys: vec![key],
        ..Default::default()
    };
    Ok(Arc::new(config))
}

async fn dispatch_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    ssh_config: Option<Arc<russh::server::Config>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let transport = sniff_transport(&stream).await?;
    match transport.as_str() {
        "tls" => {
            let acceptor = tls_acceptor.ok_or_else(|| anyhow!("TLS handshake received but TLS is disabled"))?;
            let tls = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                acceptor.accept(stream),
            )
            .await
            .context("TLS handshake timed out")??;
            serve_utnp(tls, state).await?;
        }
        "ssh" => {
            let config = ssh_config.ok_or_else(|| anyhow!("SSH handshake received but SSH is disabled"))?;
            let handler = SshHandler {
                state,
                buffers: HashMap::new(),
            };
            let session = russh::server::run_stream(config, stream, handler).await?;
            session.await?;
        }
        _ => serve_utnp(stream, state).await?,
    }
    let _ = peer;
    Ok(())
}

async fn sniff_transport(stream: &TcpStream) -> Result<String> {
    let mut peek = [0u8; 8];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let n = stream.peek(&mut peek).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "client closed before sending data",
                ));
            }
            if n >= 4 || (n >= 2 && peek[0] == 0x16) {
                return Ok(n);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("Timed out while identifying connection transport")??;

    if n >= 4 && &peek[..4] == b"SSH-" {
        return Ok("ssh".into());
    }
    if n >= 2 && peek[0] == 0x16 && peek[1] == 0x03 {
        return Ok("tls".into());
    }
    Ok("plain".into())
}

async fn serve_utnp<S>(stream: S, state: AppState) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    loop {
        let mut first = String::new();
        let n = reader.read_line(&mut first).await?;
        if n == 0 {
            return Ok(());
        }
        let first_line = first.trim_end_matches(['\r', '\n']);
        let legacy = first_line.starts_with("UTNP/1.0 ");
        let mut frame = first.into_bytes();
        if !legacy {
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    return Ok(());
                }
                let done = line == "\n" || line == "\r\n";
                frame.extend_from_slice(line.as_bytes());
                if done {
                    break;
                }
            }
        }
        let response = process_request(&frame, &state);
        reader.get_mut().write_all(&response).await?;
        reader.get_mut().flush().await?;
    }
}

fn process_request(frame: &[u8], state: &AppState) -> Vec<u8> {
    let text = match std::str::from_utf8(frame) {
        Ok(value) => value,
        Err(_) => return error_response("2.0", "Invalid request"),
    };
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("").trim_end_matches('\r');
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.is_empty() {
        return error_response("2.0", "Invalid request");
    }

    let (version, legacy) = match parts[0] {
        "UTNP/2.0" => ("2.0", false),
        "UTNP/1.0" if state.support_first_version => ("1.0", true),
        "UTNP/1.0" => {
            return b"UTNP ERROR - UNSUPPORTED UTNP VERSION, SUPPORTED UTNP/2.0\n".to_vec()
        }
        _ => return b"UTNP ERROR - UNSUPPORTED UTNP VERSION, SUPPORTED UTNP/2.0\n".to_vec(),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    if !legacy {
        for line in lines {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            } else {
                return error_response(version, "Invalid header");
            }
        }
    }

    if parts.len() < 2 {
        return error_response(version, "Invalid request");
    }
    match parts[1] {
        "LIST" if parts.len() == 2 => {
            if legacy {
                available_v1(&state.protocols)
            } else {
                available_v2(&state.protocols, state.support_first_version, &state.enabled_security)
            }
        }
        "NEGOTIATE" if parts.len() == 3 => {
            if legacy {
                negotiate_v1(parts[2], &state.protocols)
            } else {
                let values: Vec<&str> = headers
                    .iter()
                    .filter(|(name, _)| name == "supported-versions")
                    .map(|(_, value)| value.as_str())
                    .collect();
                if values.is_empty() {
                    error_response(version, "Unsupported protocol version")
                } else if values.len() != 1 {
                    error_response(version, "Invalid request")
                } else {
                    negotiate_v2(
                        parts[2],
                        values[0],
                        &state.protocols,
                        state.support_first_version,
                        &state.enabled_security,
                    )
                }
            }
        }
        "EXPLORE" if !legacy && parts.len() == 2 => explore_response(&state.explore_nodes),
        _ => error_response(version, "Invalid request"),
    }
}

fn error_response(version: &str, message: &str) -> Vec<u8> {
    format!("UTNP/{version} ERROR {message}\n").into_bytes()
}

fn version_rank(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    (
        parts.next().and_then(|s| s.parse().ok()).unwrap_or(0),
        parts.next().and_then(|s| s.parse().ok()).unwrap_or(0),
    )
}

fn supported_protocol_versions(protocol: &Protocol, support_first_version: bool) -> Vec<String> {
    let mut versions = vec![protocol.version.clone()];
    if support_first_version && protocol.version == "2.0" {
        versions.push("1.0".to_string());
    }
    versions
}

fn enabled_security_for_protocol(configured: &[String], enabled: &[String]) -> Vec<String> {
    configured
        .iter()
        .filter(|mechanism| enabled.iter().any(|value| value.eq_ignore_ascii_case(mechanism)))
        .cloned()
        .collect()
}

fn append_security(output: &mut String, mechanisms: &[String]) {
    if !mechanisms.is_empty() {
        output.push_str(&format!("Security: {}\n", mechanisms.join(",")));
    }
}

fn available_v1(protocols: &[Protocol]) -> Vec<u8> {
    let mut output = String::from("UTNP/1.0 AVAILABLE\n");
    for protocol in protocols {
        output.push_str(&format!(
            "{} 1.0 {} {}\n",
            protocol.name, protocol.host, protocol.port
        ));
    }
    output.into_bytes()
}

fn available_v2(protocols: &[Protocol], support_first_version: bool, enabled: &[String]) -> Vec<u8> {
    let mut output = String::from("UTNP/2.0 AVAILABLE\n");
    for protocol in protocols {
        for version in supported_protocol_versions(protocol, support_first_version) {
            output.push_str(&format!(
                "{} {} {} {}\n",
                protocol.name, version, protocol.host, protocol.port
            ));
            append_security(
                &mut output,
                &enabled_security_for_protocol(&protocol.security, enabled),
            );
        }
    }
    output.into_bytes()
}

fn negotiate_v1(requested: &str, protocols: &[Protocol]) -> Vec<u8> {
    for name in requested.split(',').map(str::trim) {
        if let Some(protocol) = protocols.iter().find(|protocol| protocol.name == name) {
            return format!(
                "UTNP/1.0 START PROTOCOL {} 1.0 {} {}\n",
                protocol.name, protocol.host, protocol.port
            )
            .into_bytes();
        }
    }
    let mut output = String::from("UTNP/1.0 ERROR Unsupported protocol\n");
    output.push_str(std::str::from_utf8(&available_v1(protocols)).unwrap());
    output.into_bytes()
}

fn negotiate_v2(
    requested: &str,
    client_versions: &str,
    protocols: &[Protocol],
    support_first_version: bool,
    enabled: &[String],
) -> Vec<u8> {
    if requested.is_empty() || requested.contains(',') {
        return error_response("2.0", "Invalid request");
    }
    let Some(protocol) = protocols.iter().find(|protocol| protocol.name == requested) else {
        let mut output = b"UTNP/2.0 ERROR Unsupported protocol\n".to_vec();
        output.extend_from_slice(&available_v2(protocols, support_first_version, enabled));
        return output;
    };
    let server_versions = supported_protocol_versions(protocol, support_first_version);
    let client: Vec<&str> = client_versions
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    let selected = server_versions
        .iter()
        .filter(|version| client.contains(&version.as_str()))
        .max_by_key(|version| version_rank(version));
    let Some(selected_version) = selected else {
        return error_response("2.0", "Unsupported protocol version");
    };

    let mut output = format!(
        "UTNP/2.0 START PROTOCOL {} {} {} {}\n",
        protocol.name, selected_version, protocol.host, protocol.port
    );
    append_security(
        &mut output,
        &enabled_security_for_protocol(&protocol.security, enabled),
    );
    output.into_bytes()
}

fn explore_response(nodes: &[ExploreNode]) -> Vec<u8> {
    let mut output = String::from("UTNP/2.0 EXPLORE AVAILABLE\n");
    for node in nodes {
        output.push_str(&format!(
            "utnp {} {} {}\n",
            node.version, node.host, node.description
        ));
    }
    output.into_bytes()
}

fn complete_frame_len(buffer: &[u8]) -> Option<usize> {
    let first_end = buffer.iter().position(|byte| *byte == b'\n')? + 1;
    let first = std::str::from_utf8(&buffer[..first_end]).ok()?.trim();
    if first.starts_with("UTNP/1.0 ") {
        return Some(first_end);
    }
    let mut position = first_end;
    loop {
        let relative = buffer[position..].iter().position(|byte| *byte == b'\n')?;
        let end = position + relative + 1;
        let line = &buffer[position..end];
        if line == b"\n" || line == b"\r\n" {
            return Some(end);
        }
        position = end;
    }
}

struct SshHandler {
    state: AppState,
    buffers: HashMap<ChannelId, Vec<u8>>,
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
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
        session.channel_failure(channel)?;
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
        if buffer.len() > 1024 * 1024 {
            self.buffers.remove(&channel);
            session.close(channel)?;
            return Ok(());
        }
        while let Some(frame_len) = complete_frame_len(buffer) {
            let frame: Vec<u8> = buffer.drain(..frame_len).collect();
            let response = process_request(&frame, &self.state);
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
