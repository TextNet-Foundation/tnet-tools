use crate::config::SecurityConfig;
use anyhow::{Context, Result, anyhow};
use std::io::Cursor;
use std::sync::Arc;
use tokio::fs;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ServerConfig as TlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};

pub async fn load_tls_acceptor(security: &SecurityConfig) -> Result<TlsAcceptor> {
    if security.tls_public_path.is_empty() || security.tls_private_path.is_empty() {
        return Err(anyhow!(
            "enable_tls=true requires tls_public_path and tls_private_path"
        ));
    }

    let cert_bytes = fs::read(&security.tls_public_path)
        .await
        .with_context(|| format!("cannot open TLS certificate: {}", security.tls_public_path))?;

    let mut cert_reader = Cursor::new(cert_bytes);

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<_, _>>()?;

    if certs.is_empty() {
        return Err(anyhow!("TLS certificate file contains no certificates"));
    }

    let key_bytes = fs::read(&security.tls_private_path)
        .await
        .with_context(|| format!("cannot open TLS private key: {}", security.tls_private_path))?;

    let mut key_reader = Cursor::new(key_bytes);

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("TLS private key file contains no supported private key"))?;

    let tls_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS certificate and private key do not match or are invalid")?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

pub async fn load_ssh_config(security: &SecurityConfig) -> Result<Arc<russh::server::Config>> {
    let path = &security.ssh_host_key_path;

    let secret = fs::read_to_string(path)
        .await
        .with_context(|| format!("cannot load SSH host key: {path}"))?;

    let key = russh::keys::decode_secret_key(&secret, None)
        .with_context(|| format!("cannot parse SSH host key: {path}"))?;

    // SSH provides encrypted and integrity-protected transport.
    // UTNP itself does not implement user authentication.
    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::None);
    let config = russh::server::Config {
        methods,
        keys: vec![key],
        ..Default::default()
    };

    Ok(Arc::new(config))
}
