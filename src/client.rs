
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use russh::ChannelMsg;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Клиент Universal Text Negotiation Protocol.
#[derive(Parser, Debug)]
#[command(author, version, about = "UTNP client")]
struct Args {
    /// Хост UTNP-сервера.
    #[arg(short = 'H', long, default_value = "localhost", global = true)]
    host: String,

    /// Порт UTNP-сервера.
    #[arg(short = 'p', long, default_value = "34", global = true)]
    port: u16,

    /// Использовать устаревшую версию UTNP/1.0.
    #[arg(long, global = true)]
    v1: bool,

    /// Использовать SSH вместо TLS.
    #[arg(short = 's', long, global = true)]
    ssh: bool,

    /// Дополнительный доверенный CA-сертификат в PEM.
    #[arg(long, global = true)]
    ca_cert: Option<PathBuf>,

    /// Имя хоста для TLS SNI и проверки сертификата.
    /// По умолчанию используется --host.
    #[arg(long, global = true)]
    verify_for_sni: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Получить список доступных протоколов.
    List,

    /// Получить список известных UTNP-узлов.
    Explore,

    /// Согласовать версию и endpoint протокола.
    Negotiate {
        /// Имя протокола, например tmutp или tbip.
        protocol: String,

        /// Поддерживаемые версии протокола.
        /// Если не указано, сервер использует default-version.
        #[arg(long)]
        versions: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.v1 && args.ssh {
        bail!("SSH is not supported by UTNP/1.0");
    }

    if args.v1 && args.ca_cert.is_some() {
        bail!("--ca-cert cannot be used with UTNP/1.0");
    }

    let request = build_request(&args.command, args.v1)?;

    println!("→ {}", request.trim_end());

    let response = if args.v1 {
        println!("Transport: TCP");
        exchange_tcp(&args.host, args.port, &request).await?
    } else {
        exchange_v2(&args, &request).await?
    };

    print_response(&response)?;

    Ok(())
}

fn build_request(
    command: &Command,
    legacy: bool,
) -> Result<String> {
    if legacy {
        return match command {
            Command::List => Ok("UTNP/1.0 LIST\n".to_string()),

            Command::Negotiate { protocol, .. } => {
                validate_protocol_name(protocol)?;

                Ok(format!(
                    "UTNP/1.0 NEGOTIATE {}\n",
                    protocol
                ))
            }

            Command::Explore => {
                bail!("EXPLORE is not supported by UTNP/1.0");
            }
        };
    }

    match command {
        Command::List => {
            Ok("UTNP/2.0 LIST\n\n".to_string())
        }

        Command::Explore => {
            Ok("UTNP/2.0 EXPLORE\n\n".to_string())
        }

        Command::Negotiate { protocol, versions } => {
            validate_protocol_name(protocol)?;

            match versions {
                Some(versions) => {
                    if versions.trim().is_empty() {
                        bail!("Supported versions cannot be empty");
                    }

                    Ok(format!(
                        "UTNP/2.0 NEGOTIATE {}\nSupported-Versions: {}\n\n",
                        protocol,
                        versions
                    ))
                }

                None => {
                    Ok(format!(
                        "UTNP/2.0 NEGOTIATE {}\n\n",
                        protocol
                    ))
                }
            }
        }
    }
}

fn validate_protocol_name(protocol: &str) -> Result<()> {
    if protocol.trim().is_empty() || protocol.contains(',') {
        bail!("NEGOTIATE requires exactly one protocol name");
    }

    Ok(())
}

async fn exchange_v2(
    args: &Args,
    request: &str,
) -> Result<Vec<u8>> {
    if args.ssh {
        println!("Transport: SSH");

        match exchange_ssh(&args.host, args.port, request).await {
            Ok(response) => return Ok(response),

            Err(SshAttemptError::Untrusted(message)) => {
                bail!(
                    "SSH host key verification failed. \
                     Refusing fallback: {message}"
                );
            }

            Err(SshAttemptError::Failed(error)) => {
                return Err(error);
            }

            Err(SshAttemptError::Unavailable(message)) => {
                eprintln!("SSH unavailable: {message}");
                eprintln!("Falling back to TLS...");
            }
        }
    }

    println!("Transport: TLS");

    match exchange_tls(
        &args.host,
        args.port,
        request,
        args.ca_cert.as_deref(),
        args.verify_for_sni.as_deref(),
    )
    .await
    {
        Ok(response) => return Ok(response),

        Err(TlsAttemptError::Fatal(error)) => {
            return Err(error);
        }

        Err(TlsAttemptError::Unavailable(message)) => {
            eprintln!("TLS unavailable: {message}");
            eprintln!("Falling back to plain TCP...");
        }
    }

    println!("Transport: TCP (fallback)");

    exchange_tcp(&args.host, args.port, request).await
}

async fn exchange_tcp(
    host: &str,
    port: u16,
    request: &str,
) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("Cannot connect to {host}:{port}"))?;

    stream.set_nodelay(true)?;

    send_request(&mut stream, request).await
}

enum TlsAttemptError {
    Unavailable(String),
    Fatal(anyhow::Error),
}

async fn exchange_tls(
    host: &str,
    port: u16,
    request: &str,
    ca_cert: Option<&std::path::Path>,
    verify_for_sni: Option<&str>,
) -> std::result::Result<Vec<u8>, TlsAttemptError> {
    // Загружаем системные корневые сертификаты.
    let native_certs = rustls_native_certs::load_native_certs();

    let mut roots = RootCertStore::empty();

    for error in &native_certs.errors {
        eprintln!("Warning: cannot load a system CA certificate: {error}");
    }

    for cert in native_certs.certs {
        roots
            .add(cert)
            .map_err(anyhow::Error::from)
            .map_err(TlsAttemptError::Fatal)?;
    }

    // Дополнительный CA пользователя.
    if let Some(path) = ca_cert {
        let file = std::fs::File::open(path)
            .map_err(anyhow::Error::from)
            .map_err(TlsAttemptError::Fatal)?;

        let mut reader = BufReader::new(file);

        let certificates: Vec<_> =
            rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<_, _>>()
                .map_err(anyhow::Error::from)
                .map_err(TlsAttemptError::Fatal)?;

        if certificates.is_empty() {
            return Err(TlsAttemptError::Fatal(
                anyhow!("CA certificate file contains no certificates")
            ));
        }

        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(anyhow::Error::from)
                .map_err(TlsAttemptError::Fatal)?;
        }
    }

    if roots.is_empty() {
        return Err(TlsAttemptError::Fatal(
            anyhow!(
                "No trusted CA certificates found in the system store or --ca-cert"
            )
        ));
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect((host, port))
        .await
        .map_err(anyhow::Error::from)
        .map_err(TlsAttemptError::Fatal)?;

    stream
        .set_nodelay(true)
        .map_err(anyhow::Error::from)
        .map_err(TlsAttemptError::Fatal)?;

    let tls_name = verify_for_sni.unwrap_or(host);

    let server_name = ServerName::try_from(tls_name.to_string())
        .map_err(anyhow::Error::from)
        .map_err(TlsAttemptError::Fatal)?;

    let mut tls_stream = match connector.connect(server_name, stream).await {
        Ok(stream) => stream,

        Err(error) => {
            // Ошибки проверки сертификата не должны приводить
            // к незаметному переходу на незашифрованный TCP.
            return match error.kind() {
                std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe => {
                    Err(TlsAttemptError::Unavailable(error.to_string()))
                }

                _ => {
                    Err(TlsAttemptError::Fatal(
                        anyhow!("TLS handshake failed: {error}")
                    ))
                }
            };
        }
    };

    send_request(&mut tls_stream, request)
        .await
        .map_err(TlsAttemptError::Fatal)
}

async fn send_request<S>(
    stream: &mut S,
    request: &str,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Один запрос на соединение.
    stream.shutdown().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    if response.is_empty() {
        bail!("UTNP server returned an empty response");
    }

    Ok(response)
}

enum SshAttemptError {
    Unavailable(String),
    Untrusted(String),
    Failed(anyhow::Error),
}

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
    request: &str,
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

    let config = Arc::new(config);

    let mut session = match timeout(
        Duration::from_secs(15),
        client::connect(config, (host, port), handler),
    )
    .await
    {
        Ok(Ok(session)) => session,

        Ok(Err(error)) => {
            if key_checked.load(Ordering::SeqCst) {
                if !key_trusted.load(Ordering::SeqCst) {
                    return Err(SshAttemptError::Untrusted(
                        "The server key is unknown or has changed. \
                         Check ~/.ssh/known_hosts."
                            .to_string()
                    ));
                }

                return Err(SshAttemptError::Failed(
                    anyhow!("SSH connection failed after host verification: {error}")
                ));
            }

            return Err(SshAttemptError::Unavailable(error.to_string()));
        }

        Err(_) => {
            if key_checked.load(Ordering::SeqCst) {
                return Err(SshAttemptError::Failed(
                    anyhow!("SSH connection timed out after host key exchange")
                ));
            }

            return Err(SshAttemptError::Unavailable(
                "SSH connection timed out".to_string()
            ));
        }
    };

    let auth = session
        .authenticate_none("utnp")
        .await
        .map_err(|error| {
            SshAttemptError::Failed(
                anyhow!("SSH authentication failed: {error}")
            )
        })?;

    if !auth.success() {
        return Err(SshAttemptError::Failed(
            anyhow!("SSH server rejected none authentication")
        ));
    }

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|error| {
            SshAttemptError::Failed(
                anyhow!("Cannot open SSH session channel: {error}")
            )
        })?;

    // Используем SSH session channel как транспорт UTNP.
    // Команды Linux shell не запускаются.
    channel
        .request_shell(true)
        .await
        .map_err(|error| {
            SshAttemptError::Failed(
                anyhow!("SSH session channel was rejected: {error}")
            )
        })?;

    channel
        .data_bytes(Bytes::from(request.as_bytes().to_vec()))
        .await
        .map_err(|error| {
            SshAttemptError::Failed(
                anyhow!("Cannot send UTNP request over SSH: {error}")
            )
        })?;

    channel
        .eof()
        .await
        .map_err(|error| {
            SshAttemptError::Failed(
                anyhow!("Cannot finish SSH request: {error}")
            )
        })?;

    let mut response = Vec::new();

    loop {
        let wait_duration = if response.is_empty() {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(1)
        };

        let message = match timeout(
            wait_duration,
            channel.wait(),
        )
        .await
        {
            Ok(message) => message,

            Err(_) if !response.is_empty() => break,

            Err(_) => {
                return Err(SshAttemptError::Failed(
                    anyhow!("Timed out waiting for UTNP response over SSH")
                ));
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
    }

    if response.is_empty() {
        return Err(SshAttemptError::Failed(
            anyhow!("UTNP server returned an empty SSH response")
        ));
    }

    let _ = channel.close().await;

    Ok(response)
}

fn print_response(response: &[u8]) -> Result<()> {
    let response = String::from_utf8_lossy(response);

    if response.is_empty() {
        bail!("UTNP server returned an empty response");
    }

    for line in response.lines() {
        println!("← {}", line);
    }

    Ok(())
}
