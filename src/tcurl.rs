use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use clap::Parser;
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use russh::ChannelMsg;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    BufReader as TokioBufReader,
};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

const MAX_RESPONSE_HEADER: usize = 64 * 1024;
const MAX_RESPONSE_BODY: usize = 256 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "TextNet protocol client"
)]
#[command(group(
    clap::ArgGroup::new("method")
        .args(["post", "head"])
        .multiple(false)
))]
#[command(group(
    clap::ArgGroup::new("transport")
        .args(["ssh", "tcp"])
        .multiple(false)
))]
struct Args {
    /// TextNet URI: tmutp://host/path or tbip://host/path
    uri: String,

    /// Use POST (TMUTP only)
    #[arg(long)]
    post: bool,

    /// Use HEAD
    #[arg(long)]
    head: bool,

    /// Try SSH, then TLS, then TCP
    #[arg(short = 's', long)]
    ssh: bool,

    /// Use TCP only
    #[arg(short = 't', long)]
    tcp: bool,

    /// Ignore security mechanisms advertised by UTNP
    #[arg(short = 'i', long = "ignore-utnp-security")]
    ignore_utnp_security: bool,

    /// Add request header
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// POST body
    #[arg(short = 'd', long)]
    data: Option<String>,

    /// POST body from file
    #[arg(long)]
    data_file: Option<PathBuf>,

    /// Save response body
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Save complete protocol response, including status line and headers
    #[arg(long = "output-header")]
    output_header: Option<PathBuf>,

    /// Additional trusted CA certificate in PEM format
    #[arg(long)]
    ca_cert: Option<PathBuf>,

    /// TLS SNI and certificate verification name
    #[arg(long)]
    verify_for_sni: Option<String>,

    /// Default UTNP port when URI has no port
    #[arg(long, default_value_t = 34)]
    utnp_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Tmutp,
    Tbip,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Tmutp => "tmutp",
            Self::Tbip => "tbip",
        }
    }

    fn version(self) -> &'static str {
        match self {
            Self::Tmutp => "TMUTP/1.0",
            Self::Tbip => "TBIP/1.0",
        }
    }

    fn utnp_version(self) -> &'static str {
        match self {
            Self::Tmutp => "1.0",
            Self::Tbip => "1.0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Head,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TransportMode {
    TlsThenTcp,
    SshThenTlsThenTcp,
    TcpOnly,
}

#[derive(Debug, Clone, Copy)]
enum FrameKind {
    Protocol { head: bool },
    Utnp,
}

#[derive(Debug)]
struct Target {
    protocol: Protocol,
    host: String,
    path_query: String,
    direct_port: Option<u16>,
    utnp_port: Option<u16>,
}

#[derive(Debug)]
struct Endpoint {
    host: String,
    port: u16,
}

#[derive(Debug)]
enum AttemptError {
    Unavailable(String),
    Fatal(anyhow::Error),
}

#[derive(Debug)]
enum SshAttemptError {
    Unavailable(String),
    Untrusted(String),
    Failed(anyhow::Error),
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let target = parse_target(&args.uri)?;

    let method = if args.post {
        Method::Post
    } else if args.head {
        Method::Head
    } else {
        Method::Get
    };

    if method == Method::Post && target.protocol != Protocol::Tmutp {
        bail!("POST is supported only by TMUTP");
    }

    if (args.data.is_some() || args.data_file.is_some())
        && method != Method::Post
    {
        bail!("--data and --data-file require --post");
    }

    if args.data.is_some() && args.data_file.is_some() {
        bail!("Use either --data or --data-file, not both");
    }

    if args.output.is_some()
        && args.output_header.is_some()
        && args.output == args.output_header
    {
        bail!("--output and --output-header must use different files");
    }

    let mode = if args.tcp {
        TransportMode::TcpOnly
    } else if args.ssh {
        TransportMode::SshThenTlsThenTcp
    } else {
        TransportMode::TlsThenTcp
    };

    let body = if let Some(data) = &args.data {
        data.as_bytes().to_vec()
    } else if let Some(path) = &args.data_file {
        tokio::fs::read(path)
            .await
            .with_context(|| format!("Cannot read POST body file: {}", path.display()))?
    } else {
        Vec::new()
    };

    let request = build_request(
        &target,
        method,
        &args.headers,
        &body,
        args.data.is_some(),
    )?;

    let endpoint = if let Some(port) = target.direct_port {
        Endpoint {
            host: target.host.clone(),
            port,
        }
    } else {
        let utnp_port = target.utnp_port.unwrap_or(args.utnp_port);

        println!(
            "Resolving {} through UTNP at {}:{}",
            target.protocol.name(),
            target.host,
            utnp_port
        );

        negotiate_endpoint(
            &target,
            utnp_port,
            mode,
            &args,
        )
        .await?
    };

    eprintln!(
        "Connecting to {}:{} using {}",
        endpoint.host,
        endpoint.port,
        target.protocol.name()
    );

    let response = exchange_with_fallback(
        &endpoint.host,
        endpoint.port,
        &request,
        FrameKind::Protocol {
            head: method == Method::Head,
        },
        mode,
        &args,
    )
    .await?;

    handle_response(
        &response,
        method == Method::Head,
        &args.output,
        &args.output_header,
    )
    .await?;

    Ok(())
}

// -----------------------------------------------------------------------------
// URI parsing
// -----------------------------------------------------------------------------

fn parse_target(input: &str) -> Result<Target> {
    let (normalized, utnp_port) = normalize_u_port(input)?;

    let url = Url::parse(&normalized)
        .with_context(|| format!("Invalid TextNet URI: {input}"))?;

    let protocol = match url.scheme() {
        "tmutp" => Protocol::Tmutp,
        "tbip" => Protocol::Tbip,
        other => bail!("Unsupported URI scheme: {other}"),
    };

    if !url.username().is_empty() || url.password().is_some() {
        bail!("User information in TextNet URIs is not supported");
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URI does not contain a host"))?
        .to_string();

    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    let mut path_query = path.to_string();

    if let Some(query) = url.query() {
        path_query.push('?');
        path_query.push_str(query);
    }

    let direct_port = if utnp_port.is_none() {
        url.port()
    } else {
        None
    };

    Ok(Target {
        protocol,
        host,
        path_query,
        direct_port,
        utnp_port,
    })
}

/// Converts host:u1234 into host:1234 for URL parsing,
/// while remembering that the port belongs to UTNP.
fn normalize_u_port(input: &str) -> Result<(String, Option<u16>)> {
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| anyhow!("URI must contain ://"))?;

    let authority_end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());

    let authority = &rest[..authority_end];
    let suffix = &rest[authority_end..];

    let Some((host_part, port_part)) = authority.rsplit_once(':') else {
        return Ok((input.to_string(), None));
    };

    if !port_part.starts_with('u') {
        return Ok((input.to_string(), None));
    }

    let digits = &port_part[1..];

    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Invalid UTNP port: {port_part}");
    }

    let port: u16 = digits
        .parse()
        .context("UTNP port is outside the valid range")?;

    if port == 0 {
        bail!("UTNP port cannot be zero");
    }

    let normalized = format!(
        "{scheme}://{host_part}:{port}{suffix}"
    );

    Ok((normalized, Some(port)))
}

// -----------------------------------------------------------------------------
// Request construction
// -----------------------------------------------------------------------------

fn build_request(
    target: &Target,
    method: Method,
    custom_headers: &[String],
    body: &[u8],
    data_was_text: bool,
) -> Result<Vec<u8>> {
    let mut headers = Vec::<(String, String)>::new();

    headers.push(("Host".to_string(), target.host.clone()));
    headers.push((
        "User-Agent".to_string(),
        "tcurl/0.1.0".to_string(),
    ));

    let mut has_content_type = false;

    for header in custom_headers {
        if header.contains('\r') || header.contains('\n') {
            bail!("Request header contains a newline");
        }

        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid header: {header}"))?;

        let name = name.trim();
        let value = value.trim();

        if name.is_empty() || value.contains('\0') {
            bail!("Invalid request header: {header}");
        }

        if name.eq_ignore_ascii_case("content-length") {
            bail!("Content-Length is managed automatically by tcurl");
        }

        if name.eq_ignore_ascii_case("host") {
            bail!("Host is determined by the URI");
        }

        if name.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }

        headers.push((name.to_string(), value.to_string()));
    }

    if method == Method::Post && !has_content_type {
        let content_type = if data_was_text {
            "application/x-www-form-urlencoded"
        } else {
            "application/octet-stream"
        };

        headers.push((
            "Content-Type".to_string(),
            content_type.to_string(),
        ));
    }

    if target.protocol == Protocol::Tmutp {
        headers.push((
            "Content-Length".to_string(),
            body.len().to_string(),
        ));
    }

    let mut request = format!(
        "{} {} {}\n",
        target.protocol.version(),
        method.as_str(),
        target.path_query
    );

    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\n"));
    }

    request.push('\n');

    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);

    Ok(bytes)
}

// -----------------------------------------------------------------------------
// UTNP negotiation
// -----------------------------------------------------------------------------

fn parse_utnp_security(response: &str) -> Vec<String> {
    response
        .lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;

            if !name.trim().eq_ignore_ascii_case("Security") {
                return None;
            }

            Some(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_ascii_lowercase)
                    .collect(),
            )
        })
        .unwrap_or_default()
}

async fn negotiate_endpoint(
    target: &Target,
    utnp_port: u16,
    mode: TransportMode,
    args: &Args,
) -> Result<Endpoint> {
    let request = format!(
        "UTNP/2.0 NEGOTIATE {}\nSupported-Versions: {}\n\n",
        target.protocol.name(),
        target.protocol.utnp_version()
    );

    let response = exchange_with_fallback(
        &target.host,
        utnp_port,
        request.as_bytes(),
        FrameKind::Utnp,
        mode,
        args,
    )
    .await
    .context("UTNP negotiation failed")?;

    let response_text = String::from_utf8_lossy(&response);
    let first_line = response_text
        .lines()
        .next()
        .ok_or_else(|| anyhow!("UTNP returned an empty response"))?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() != 7
        || parts[0] != "UTNP/2.0"
        || parts[1] != "START"
        || parts[2] != "PROTOCOL"
    {
        bail!("UTNP negotiation was rejected: {}", response_text.trim());
    }

    if !parts[3].eq_ignore_ascii_case(target.protocol.name()) {
        bail!("UTNP returned an unexpected protocol: {}", parts[3]);
    }

    if parts[4] != target.protocol.utnp_version() {
        bail!(
            "UTNP selected unsupported version {} (expected {})",
            parts[4],
            target.protocol.utnp_version()
        );
    }

    let port: u16 = parts[6]
        .parse()
        .context("UTNP returned an invalid protocol port")?;

    if port == 0 {
        bail!("UTNP returned port 0");
    }

    let host = parts[5].to_string();

    if host.is_empty() {
        bail!("UTNP returned an empty protocol host");
    }

    let supported_security = parse_utnp_security(&response_text);

    let required_security: &[&str] = match mode {
        TransportMode::TlsThenTcp => &["tls"],
        TransportMode::SshThenTlsThenTcp => &["ssh", "tls"],
        TransportMode::TcpOnly => &[],
    };

    let security_list = if supported_security.is_empty() {
        "none".to_string()
    } else {
        supported_security.join(", ")
    };

    eprintln!("UTNP Security: {}", security_list);

    if !required_security.is_empty() {
        let security_supported = required_security.iter().any(|required| {
            supported_security
                .iter()
                .any(|supported| supported.eq_ignore_ascii_case(required))
        });

        if !security_supported {
            let required = required_security.join(" or ");

            if !args.ignore_utnp_security {
                bail!(
                    "UTNP security mismatch: client requires {}, \
                     but server supports: {}. \
                     Use --ignore-utnp-security to override.",
                    required,
                    security_list
                );
            }

            eprintln!(
                "WARN: UTNP returned Security: {}",
                security_list
            );
            eprintln!(
                "WARN: --ignore-utnp-security is enabled; \
                 attempting connection anyway."
            );
        }
    }

    eprintln!(
        "UTNP selected {} {} at {}:{}",
        target.protocol.name(),
        target.protocol.version(),
        host,
        port
    );

    Ok(Endpoint { host, port })
}

// -----------------------------------------------------------------------------
// Transport fallback
// -----------------------------------------------------------------------------

async fn exchange_with_fallback(
    host: &str,
    port: u16,
    request: &[u8],
    frame: FrameKind,
    mode: TransportMode,
    args: &Args,
) -> Result<Vec<u8>> {
    if matches!(mode, TransportMode::SshThenTlsThenTcp) {
        eprintln!("Trying SSH...");

        match exchange_ssh(host, port, request, frame).await {
            Ok(response) => {
                eprintln!("Transport: SSH");
                return Ok(response);
            }

            Err(SshAttemptError::Untrusted(message)) => {
                bail!(
                    "SSH host key is not trusted; refusing fallback: {message}"
                );
            }

            Err(SshAttemptError::Failed(error)) => {
                return Err(error);
            }

            Err(SshAttemptError::Unavailable(message)) => {
                eprintln!("SSH unavailable: {message}");
            }
        }
    }

    if !matches!(mode, TransportMode::TcpOnly) {
        eprintln!("Trying TLS...");

        match exchange_tls(
            host,
            port,
            request,
            frame,
            args.ca_cert.as_deref(),
            args.verify_for_sni.as_deref(),
        )
        .await
        {
            Ok(response) => {
                eprintln!("Transport: TLS");
                return Ok(response);
            }

            Err(AttemptError::Fatal(error)) => {
                return Err(error);
            }

            Err(AttemptError::Unavailable(message)) => {
                eprintln!("TLS unavailable: {message}");
            }
        }
    }

    eprintln!("Using TCP");

    exchange_tcp(host, port, request, frame)
        .await
        .with_context(|| format!("Cannot connect to {host}:{port} using TCP"))
}

// -----------------------------------------------------------------------------
// TCP
// -----------------------------------------------------------------------------

async fn exchange_tcp(
    host: &str,
    port: u16,
    request: &[u8],
    frame: FrameKind,
) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("Cannot connect to {host}:{port}"))?;

    stream.set_nodelay(true)?;

    send_and_receive(&mut stream, request, frame).await
}

// -----------------------------------------------------------------------------
// TLS
// -----------------------------------------------------------------------------

async fn exchange_tls(
    host: &str,
    port: u16,
    request: &[u8],
    frame: FrameKind,
    ca_cert: Option<&Path>,
    verify_for_sni: Option<&str>,
) -> std::result::Result<Vec<u8>, AttemptError> {
    let mut roots = RootCertStore::empty();

    let native_certs = rustls_native_certs::load_native_certs();

    for error in &native_certs.errors {
        eprintln!("Warning: cannot load system CA certificate: {error}");
    }

    for cert in native_certs.certs {
        roots
            .add(cert)
            .map_err(anyhow::Error::from)
            .map_err(AttemptError::Fatal)?;
    }

    if let Some(path) = ca_cert {
        let file = std::fs::File::open(path)
            .map_err(anyhow::Error::from)
            .map_err(AttemptError::Fatal)?;

        let mut reader = BufReader::new(file);

        let certificates: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<_, _>>()
            .map_err(anyhow::Error::from)
            .map_err(AttemptError::Fatal)?;

        if certificates.is_empty() {
            return Err(AttemptError::Fatal(anyhow!(
                "CA certificate file contains no certificates"
            )));
        }

        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(anyhow::Error::from)
                .map_err(AttemptError::Fatal)?;
        }
    }

    if roots.is_empty() {
        return Err(AttemptError::Fatal(anyhow!(
            "No trusted CA certificates found"
        )));
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|error| AttemptError::Unavailable(error.to_string()))?;

    stream
        .set_nodelay(true)
        .map_err(|error| AttemptError::Fatal(error.into()))?;

    let tls_name = verify_for_sni.unwrap_or(host);

    let server_name = ServerName::try_from(tls_name.to_string())
        .map_err(|error| AttemptError::Fatal(error.into()))?;

    let mut tls_stream = match timeout(
        Duration::from_secs(15),
        connector.connect(server_name, stream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,

        Ok(Err(error)) => {
            return match error.kind() {
                std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe => {
                    Err(AttemptError::Unavailable(error.to_string()))
                }

                _ => Err(AttemptError::Fatal(anyhow!(
                    "TLS handshake or certificate verification failed: {error}"
                ))),
            };
        }

        Err(_) => {
            return Err(AttemptError::Unavailable(
                "TLS handshake timed out".to_string(),
            ));
        }
    };

    send_and_receive(&mut tls_stream, request, frame)
        .await
        .map_err(AttemptError::Fatal)
}

// -----------------------------------------------------------------------------
// Shared TCP/TLS framing
// -----------------------------------------------------------------------------

async fn send_and_receive<S>(
    stream: &mut S,
    request: &[u8],
    frame: FrameKind,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.flush().await?;

    match frame {
        FrameKind::Protocol { head } => {
            read_protocol_response(stream, head).await
        }

        FrameKind::Utnp => {
            // UTNP responses do not contain Content-Length.
            // Half-close tells the UTNP server that this request is complete.
            stream.shutdown().await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;

            if response.is_empty() {
                bail!("UTNP server returned an empty response");
            }

            Ok(response)
        }
    }
}

async fn read_protocol_response<S>(
    stream: &mut S,
    head: bool,
) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut reader = TokioBufReader::new(stream);
    let mut header = Vec::new();

    loop {
        let mut line = Vec::new();
        let count = reader.read_until(b'\n', &mut line).await?;

        if count == 0 {
            bail!("Connection closed before response headers were complete");
        }

        header.extend_from_slice(&line);

        if header.len() > MAX_RESPONSE_HEADER {
            bail!("Response headers exceed the size limit");
        }

        if line == b"\n" || line == b"\r\n" {
            break;
        }
    }

    let content_length = parse_content_length(&header)?;

    if content_length > MAX_RESPONSE_BODY {
        bail!("Response body exceeds the size limit");
    }

    let body_length = if head { 0 } else { content_length };

    let mut body = vec![0u8; body_length];
    if body_length > 0 {
        reader.read_exact(&mut body).await?;
    }

    header.extend_from_slice(&body);

    Ok(header)
}

fn parse_content_length(header: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(header)
        .context("Response headers are not valid UTF-8")?;

    for line in text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value
                    .trim()
                    .parse::<usize>()
                    .context("Invalid Content-Length in response");
            }
        }
    }

    bail!("Response does not contain Content-Length")
}

fn response_header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            response
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        })
}

// -----------------------------------------------------------------------------
// SSH
// -----------------------------------------------------------------------------

struct KnownHostsHandler {
    host: String,
    port: u16,
    key_checked: Arc<AtomicBool>,
    key_trusted: Arc<AtomicBool>,
}

impl client::Handler for KnownHostsHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        self.key_checked.store(true, Ordering::SeqCst);

        let public_key = server_public_key.public_key();

        let trusted = russh::keys::known_hosts::check_known_hosts(
            &self.host,
            self.port,
            &public_key,
        )
        .unwrap_or(false);

        self.key_trusted.store(trusted, Ordering::SeqCst);

        Ok(trusted)
    }
}

async fn exchange_ssh(
    host: &str,
    port: u16,
    request: &[u8],
    frame: FrameKind,
) -> std::result::Result<Vec<u8>, SshAttemptError> {
    let key_checked = Arc::new(AtomicBool::new(false));
    let key_trusted = Arc::new(AtomicBool::new(false));

    let handler = KnownHostsHandler {
        host: host.to_string(),
        port,
        key_checked: key_checked.clone(),
        key_trusted: key_trusted.clone(),
    };

    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };

    let mut session = match timeout(
        Duration::from_secs(15),
        client::connect(Arc::new(config), (host, port), handler),
    )
    .await
    {
        Ok(Ok(session)) => session,

        Ok(Err(error)) => {
            if key_checked.load(Ordering::SeqCst)
                && !key_trusted.load(Ordering::SeqCst)
            {
                return Err(SshAttemptError::Untrusted(error.to_string()));
            }

            if key_checked.load(Ordering::SeqCst) {
                return Err(SshAttemptError::Failed(anyhow!(
                    "SSH connection failed after host-key verification: {error}"
                )));
            }

            return Err(SshAttemptError::Unavailable(error.to_string()));
        }

        Err(_) => {
            if key_checked.load(Ordering::SeqCst) {
                return Err(SshAttemptError::Failed(anyhow!(
                    "SSH connection timed out after host-key exchange"
                )));
            }

            return Err(SshAttemptError::Unavailable(
                "SSH connection timed out".to_string(),
            ));
        }
    };

    let auth = session
        .authenticate_none("tcurl")
        .await
        .map_err(|error| {
            SshAttemptError::Failed(anyhow!("SSH authentication failed: {error}"))
        })?;

    if !auth.success() {
        return Err(SshAttemptError::Failed(anyhow!(
            "SSH server rejected none authentication"
        )));
    }

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|error| {
            SshAttemptError::Failed(anyhow!(
                "Cannot open SSH session channel: {error}"
            ))
        })?;

    // This requests the protocol channel. No operating-system shell is run
    // by the TextNet SSH server.
    channel
        .request_shell(true)
        .await
        .map_err(|error| {
            SshAttemptError::Failed(anyhow!(
                "SSH protocol channel was rejected: {error}"
            ))
        })?;

    channel
        .data_bytes(Bytes::from(request.to_vec()))
        .await
        .map_err(|error| {
            SshAttemptError::Failed(anyhow!(
                "Cannot send request over SSH: {error}"
            ))
        })?;

    channel.eof().await.map_err(|error| {
        SshAttemptError::Failed(anyhow!(
            "Cannot finish SSH request: {error}"
        ))
    })?;

    let mut response = Vec::new();

    loop {
        let wait_time = match frame {
            FrameKind::Protocol { .. } => Duration::from_secs(30),
            FrameKind::Utnp if response.is_empty() => Duration::from_secs(30),
            FrameKind::Utnp => Duration::from_secs(1),
        };

        let message = match timeout(wait_time, channel.wait()).await {
            Ok(message) => message,

            Err(_) if matches!(frame, FrameKind::Utnp) && !response.is_empty() => {
                break;
            }

            Err(_) => {
                return Err(SshAttemptError::Failed(anyhow!(
                    "Timed out waiting for SSH response"
                )));
            }
        };

        match message {
            Some(ChannelMsg::Data { data }) => {
                response.extend_from_slice(&data);
            }

            Some(ChannelMsg::ExtendedData { data, .. }) => {
                response.extend_from_slice(&data);
            }

            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                break;
            }

            Some(_) => {}
        }

        if let FrameKind::Protocol { head } = frame {
            if let Some(expected) = expected_response_length(&response, head)
                .map_err(SshAttemptError::Failed)?
            {
                if response.len() >= expected {
                    break;
                }
            }
        }
    }

    if response.is_empty() {
        return Err(SshAttemptError::Failed(anyhow!(
            "Server returned an empty SSH response"
        )));
    }

    let _ = channel.close().await;

    Ok(response)
}

fn expected_response_length(
    response: &[u8],
    head: bool,
) -> Result<Option<usize>> {
    let Some(header_end) = response_header_end(response) else {
        return Ok(None);
    };

    let content_length = parse_content_length(&response[..header_end])?;

    if content_length > MAX_RESPONSE_BODY {
        bail!("Response body exceeds the size limit");
    }

    Ok(Some(
        header_end + if head { 0 } else { content_length },
    ))
}

// -----------------------------------------------------------------------------
// Response output
// -----------------------------------------------------------------------------

async fn handle_response(
    response: &[u8],
    head: bool,
    output: &Option<PathBuf>,
    output_header: &Option<PathBuf>,
) -> Result<()> {
    let header_end = response_header_end(response)
        .ok_or_else(|| anyhow!("Server returned an incomplete response"))?;

    let header = &response[..header_end];
    let body = if head {
        &response[header_end..header_end]
    } else {
        &response[header_end..]
    };

    let header_text = String::from_utf8_lossy(header);

    for line in header_text.lines() {
        eprintln!("{line}");
    }

    if let Some(path) = output_header {
        tokio::fs::write(path, response)
            .await
            .with_context(|| {
                format!(
                    "Cannot save complete response to {}",
                    path.display()
                )
            })?;
    }

    if let Some(path) = output {
        tokio::fs::write(path, body)
            .await
            .with_context(|| {
                format!("Cannot save response body to {}",
                    path.display()
                )
            })?;
    } else {
        let mut stdout = tokio::io::stdout();
        stdout.write_all(body).await?;
        stdout.flush().await?;
    }

    Ok(())
}