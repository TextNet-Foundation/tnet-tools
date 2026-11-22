use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde::Deserialize;
use std::io::Cursor;
use std::sync::Arc;
use tokio_rustls::rustls::{
	ServerConfig as TlsServerConfig,
	pki_types::{CertificateDer, PrivateKeyDer},
};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
	pub port: u16,
	pub root: String,
	pub scripting: crate::script_engine::ScriptingConfig,

	#[serde(default)]
	pub support_first_version: bool,

	#[serde(default)]
	pub security: SecurityConfig,

	#[serde(default = "default_compression_minimum")]
	pub compression_minimum: usize,

	#[serde(default = "default_compression_cache")]
	pub compression_cache: String,

	#[serde(default = "default_compression_cache_enable")]
	pub compression_cache_enable: bool,

	#[serde(default = "default_compression_cache_source_maximum")]
	pub compression_cache_source_maximum: u64,
}

fn default_compression_minimum() -> usize {
	1024
}

fn default_compression_cache() -> String {
	"./compression_cache".to_string()
}

fn default_compression_cache_enable() -> bool {
	true
}

fn default_compression_cache_source_maximum() -> u64 {
	64 * 1024 * 1024
}

#[derive(Debug, Deserialize, Default, Clone)]
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

fn default_ssh_host_key_path() -> String {
	"./ssh_host_ed25519_key".to_string()
}

#[derive(Parser, Debug)]
#[command(
	author,
	version,
	about = "TBIP server (TNet Binary Information Protocol)"
)]
pub struct Args {
	#[arg(short = 'c', long = "config", default_value = "./tbip-config.toml")]
	pub config: String,
}

#[derive(Clone)]
pub struct AppState {
	pub root: String,
	pub lua_engine: Option<Arc<crate::script_engine::lua::LuaEngine>>,
	pub rhai_engine: Option<Arc<crate::script_engine::rhai::RhaiEngine>>,
	pub scripting_config: crate::script_engine::ScriptingConfig,
	pub require_secure: bool,
	pub support_first_version: bool,
	pub compression_minimum: usize,
	pub compression_cache: std::path::PathBuf,
	pub compression_cache_enable: bool,
	pub compression_cache_source_maximum: u64,
}

// -----------------------------------------------------------------------------
// Protocol versions
// -----------------------------------------------------------------------------

pub const TBIP_VERSION: &str = "TBIP/2.0";
pub const TBIP_FIRST_VERSION: &str = "TBIP/1.0";

// -----------------------------------------------------------------------------
// Status codes
// -----------------------------------------------------------------------------

pub const OK: &str = "20 OK";
pub const OK_EMPTY: &str = "22 OK EMPTY";
pub const BAD_REQUEST: &str = "30 BAD REQUEST";
pub const NOT_FOUND: &str = "31 NOT FOUND";
pub const FORBIDDEN: &str = "32 FORBIDDEN";
pub const SERVER_ERROR: &str = "40 SERVER ERROR";
pub const METHOD_NOT_ALLOWED: &str = "50 METHOD NOT ALLOWED";
pub const VERSION_NOT_SUPPORTED: &str = "51 VERSION NOT SUPPORTED";
pub const INVALID_RANGE: &str = "52 INVALID RANGE";
pub const RANGE_NOT_SATISFIABLE: &str = "53 RANGE NOT SATISFIABLE";
pub const UNSUPPORTED_RANGE: &str = "54 UNSUPPORTED RANGE";
pub const REQUIRE_SECURE: &str = "55 REQUIRE SECURE";

pub const SUPPORTED_COMPRESSION: &[&str] = &["gzip", "zstd"];

pub fn status_code_to_text(code: u16) -> &'static str {
	match code {
		20 => "OK",
		21 => "MOVED",
		22 => "OK EMPTY",
		30 => "BAD REQUEST",
		31 => "NOT FOUND",
		32 => "FORBIDDEN",
		40 => "SERVER ERROR",
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
// TLS / SSH configuration
// -----------------------------------------------------------------------------

pub async fn load_tls_acceptor(security: &SecurityConfig) -> Result<tokio_rustls::TlsAcceptor> {
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

	let key_bytes = tokio::fs::read(&security.tls_private_path)
		.await
		.with_context(|| format!("Cannot read TLS private key: {}", security.tls_private_path))?;

	let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
		.ok_or_else(|| anyhow!("TLS private key file contains no supported key"))?;

	let tls_config = TlsServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.context("TLS certificate and private key are invalid or do not match")?;

	Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
}

pub fn load_ssh_config(security: &SecurityConfig) -> Result<Arc<russh::server::Config>> {
	let path = &security.ssh_host_key_path;

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
