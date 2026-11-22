use crate::transport::tcp::send_and_receive;
use crate::types::{AttemptError, FrameKind};
use anyhow::anyhow;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

pub async fn exchange_tls(
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
        tracing::warn!(error = %error, "cannot load system CA certificate");
    }

    for cert in native_certs.certs {
        roots
            .add(cert)
            .map_err(anyhow::Error::from)
            .map_err(AttemptError::Fatal)?;
    }

    if let Some(path) = ca_cert {
        let bytes = fs::read(path)
            .await
            .map_err(anyhow::Error::from)
            .map_err(AttemptError::Fatal)?;

        let mut reader = Cursor::new(bytes);

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
