use anyhow::anyhow;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

pub enum TlsAttemptError {
    Unavailable(String),
    Fatal(anyhow::Error),
}

pub async fn exchange_tls(
    host: &str,
    port: u16,
    request: &str,
    ca_cert: Option<&Path>,
    verify_for_sni: Option<&str>,
) -> std::result::Result<Vec<u8>, TlsAttemptError> {
    // Загружаем системные корневые сертификаты.
    let native_certs = rustls_native_certs::load_native_certs();

    let mut roots = RootCertStore::empty();

    for error in &native_certs.errors {
        tracing::warn!(error = %error, "cannot load a system CA certificate");
    }

    for cert in native_certs.certs {
        roots
            .add(cert)
            .map_err(anyhow::Error::from)
            .map_err(TlsAttemptError::Fatal)?;
    }

    // Дополнительный CA пользователя.
    if let Some(path) = ca_cert {
        let bytes = fs::read(path)
            .await
            .map_err(anyhow::Error::from)
            .map_err(TlsAttemptError::Fatal)?;

        let mut reader = Cursor::new(bytes);

        let certificates: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<_, _>>()
            .map_err(anyhow::Error::from)
            .map_err(TlsAttemptError::Fatal)?;

        if certificates.is_empty() {
            return Err(TlsAttemptError::Fatal(anyhow!(
                "CA certificate file contains no certificates"
            )));
        }

        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(anyhow::Error::from)
                .map_err(TlsAttemptError::Fatal)?;
        }
    }

    if roots.is_empty() {
        return Err(TlsAttemptError::Fatal(anyhow!(
            "No trusted CA certificates found in the system store or --ca-cert"
        )));
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

                _ => Err(TlsAttemptError::Fatal(anyhow!(
                    "TLS handshake failed: {error}"
                ))),
            };
        }
    };

    super::send_request(&mut tls_stream, request)
        .await
        .map_err(TlsAttemptError::Fatal)
}
