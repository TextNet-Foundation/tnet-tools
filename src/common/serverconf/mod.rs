//! Configuration pieces shared by the TMUTP and TBIP servers: the `[security]` section,
//! TLS/SSH loading and startup validation.

mod validate;

use validate::{
	prepare_cache_dir, resolve_cache_dir, validate_bind_address, validate_port,
	validate_script_extensions,
};

use super::compression::{DiskCachePolicy, configure_disk_cache};
use super::file_cache::configure_file_cache;
use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
	ServerConfig as TlsServerConfig,
	pki_types::{CertificateDer, PrivateKeyDer},
};

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
	#[serde(default)]
	pub require_secure: bool,

	#[serde(default)]
	pub enable_ssh: bool,

	#[serde(default)]
	pub enable_tls: bool,

	#[serde(default)]
	pub tls_public_path: String,

	#[serde(default)]
	pub tls_private_path: String,

	#[serde(default = "default_ssh_host_key_path")]
	pub ssh_host_key_path: String,
}

impl Default for SecurityConfig {
	fn default() -> Self {
		Self {
			require_secure: false,
			enable_ssh: false,
			enable_tls: false,
			tls_public_path: String::new(),
			tls_private_path: String::new(),
			ssh_host_key_path: default_ssh_host_key_path(),
		}
	}
}

fn default_ssh_host_key_path() -> String {
	"./ssh_host_ed25519_key".to_string()
}

/// The parts of a server config that are validated and applied at startup.
pub struct RuntimeSettings<'a> {
	pub port: u16,
	pub bind_address: &'a str,
	pub root: &'a str,
	pub config_path: &'a str,
	pub compression_cache: &'a str,
	pub compression_cache_enable: bool,
	pub compression_cache_source_maximum: u64,
	pub max_file_size: u64,
	pub file_cache_budget: u64,
	pub script_extensions: [(&'a str, Option<&'a str>); 2],
}

/// Validates the settings, installs the process-wide cache limits and prepares the
/// compression cache directory. Returns the absolute cache directory.
pub fn apply_runtime(settings: &RuntimeSettings<'_>) -> Result<PathBuf> {
	validate_port(settings.port)?;
	validate_bind_address(settings.bind_address)?;
	validate_script_extensions(&settings.script_extensions)?;

	let cache_dir = resolve_cache_dir(
		settings.compression_cache,
		Path::new(settings.config_path),
		Path::new(settings.root),
	)?;

	if settings.compression_cache_enable {
		prepare_cache_dir(&cache_dir)?;
	}

	configure_file_cache(settings.max_file_size, settings.file_cache_budget);
	configure_disk_cache(DiskCachePolicy {
		enable: settings.compression_cache_enable,
		source_maximum: settings.compression_cache_source_maximum,
	});

	Ok(cache_dir)
}

/// Warns when a private key can be read by group or others (should be 0600).
pub fn warn_if_key_exposed(path: &Path, what: &str) {
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;

		if let Ok(metadata) = std::fs::metadata(path)
			&& metadata.permissions().mode() & 0o077 != 0
		{
			tracing::warn!(
				path = %path.display(),
				mode = format!("{:04o}", metadata.permissions().mode() & 0o7777),
				"{what} is accessible by group/others; chmod 600 it"
			);
		}
	}

	#[cfg(not(unix))]
	let _ = (path, what);
}

pub async fn load_tls_acceptor(security: &SecurityConfig) -> Result<TlsAcceptor> {
	if security.tls_public_path.is_empty() || security.tls_private_path.is_empty() {
		return Err(anyhow!(
			"enable_tls=true requires tls_public_path and tls_private_path"
		));
	}

	let cert_bytes = tokio::fs::read(&security.tls_public_path)
		.await
		.with_context(|| format!("Cannot read TLS certificate: {}", security.tls_public_path))?;

	let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut Cursor::new(cert_bytes))
		.collect::<std::result::Result<_, _>>()?;

	if certs.is_empty() {
		return Err(anyhow!("TLS certificate file contains no certificates"));
	}

	warn_if_key_exposed(Path::new(&security.tls_private_path), "TLS private key");

	let key_bytes = tokio::fs::read(&security.tls_private_path)
		.await
		.with_context(|| format!("Cannot read TLS private key: {}", security.tls_private_path))?;

	let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
		.ok_or_else(|| anyhow!("TLS private key file contains no supported key"))?;

	let tls_config = TlsServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.context("TLS certificate and private key are invalid or do not match")?;

	Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

pub fn load_ssh_config(security: &SecurityConfig) -> Result<Arc<russh::server::Config>> {
	let path = &security.ssh_host_key_path;

	warn_if_key_exposed(Path::new(path), "SSH host key");

	let key = russh::keys::load_secret_key(path, None)
		.with_context(|| format!("Cannot load SSH host key: {}", path))?;

	let mut methods = russh::MethodSet::empty();
	methods.push(russh::MethodKind::None);

	let config = russh::server::Config {
		methods,
		keys: vec![key],
		..Default::default()
	};

	Ok(Arc::new(config))
}

#[cfg(test)]
#[path = "serverconf_tests.rs"]
mod tests;
