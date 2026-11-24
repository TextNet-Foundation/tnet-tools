use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

use crate::common::conn::{
	DEFAULT_MAX_CONNECTION_SECS, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_PER_IP,
};
use crate::common::{DEFAULT_CACHE_BUDGET, DEFAULT_MAX_FILE_SIZE, DiskCachePolicy};
use crate::common::{RuntimeSettings, apply_runtime};
pub use crate::common::{
	SUPPORTED_COMPRESSION, SecurityConfig, load_ssh_config, load_tls_acceptor,
};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	pub port: u16,
	pub root: String,

	/// Address to listen on (default `0.0.0.0`).
	#[serde(default = "default_bind_address")]
	pub bind_address: String,

	#[serde(default)]
	pub scripting: crate::script_engine::ScriptingConfig,

	#[serde(default)]
	pub support_first_version: bool,

	#[serde(default)]
	pub security: SecurityConfig,

	#[serde(default = "default_compression_minimum")]
	pub compression_minimum: usize,

	/// Relative paths are resolved against the config file's directory, never against `root`.
	#[serde(default = "default_compression_cache")]
	pub compression_cache: String,

	#[serde(default = "default_compression_cache_enable")]
	pub compression_cache_enable: bool,

	#[serde(default = "default_compression_cache_source_maximum")]
	pub compression_cache_source_maximum: u64,

	/// Files larger than this are not served (they would have to be held in memory).
	#[serde(default = "default_max_file_size")]
	pub max_file_size: u64,

	/// Total bytes of file content kept in the in-memory file cache.
	#[serde(default = "default_file_cache_budget")]
	pub file_cache_budget: u64,

	/// Maximum number of simultaneous connections.
	#[serde(default = "default_max_connections")]
	pub max_connections: usize,

	#[serde(default = "default_max_connections_per_ip")]
	pub max_connections_per_ip: usize,

	/// Hard lifetime limit of a single connection, in seconds.
	#[serde(default = "default_max_connection_secs")]
	pub max_connection_secs: u64,

	/// Largest accepted request body in bytes.
	#[serde(default = "default_max_body")]
	pub max_body: usize,
}

fn default_bind_address() -> String {
	"127.0.0.1".to_string()
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

fn default_max_file_size() -> u64 {
	DEFAULT_MAX_FILE_SIZE
}

fn default_file_cache_budget() -> u64 {
	DEFAULT_CACHE_BUDGET
}

fn default_max_connections() -> usize {
	DEFAULT_MAX_CONNECTIONS
}

fn default_max_connections_per_ip() -> usize {
	DEFAULT_MAX_PER_IP
}

fn default_max_connection_secs() -> u64 {
	DEFAULT_MAX_CONNECTION_SECS
}

fn default_max_body() -> usize {
	DEFAULT_MAX_BODY
}

const MAX_BODY_LIMIT: usize = 256 * 1024 * 1024;

fn validate_max_body(max_body: usize) -> Result<()> {
	if !(1..=MAX_BODY_LIMIT).contains(&max_body) {
		return Err(anyhow!(
			"max_body must be in 1..={MAX_BODY_LIMIT} bytes, got {max_body}"
		));
	}
	Ok(())
}

impl Config {
	/// Parses the TOML text and normalizes it; this is the only way the server builds its config.
	pub fn prepare(content: &str, config_path: &str) -> Result<Self> {
		let config: Config = toml::from_str(content).context("Failed to parse TMUTP config")?;
		config.normalized(config_path)
	}

	/// Validates the config, installs process-wide cache limits and returns the config
	/// with `compression_cache` replaced by its absolute, checked location.
	/// Fails if the cache directory would lie inside `root`.
	pub fn normalized(self, config_path: &str) -> Result<Self> {
		validate_max_body(self.max_body)?;

		let cache_dir = apply_runtime(&RuntimeSettings {
			port: self.port,
			bind_address: &self.bind_address,
			root: &self.root,
			config_path,
			compression_cache: &self.compression_cache,
			compression_cache_enable: self.compression_cache_enable,
			max_file_size: self.max_file_size,
			file_cache_budget: self.file_cache_budget,
			max_connections: self.max_connections,
			max_connections_per_ip: self.max_connections_per_ip,
			max_connection_secs: self.max_connection_secs,
			script_extensions: [
				("lua_extension", self.scripting.lua_extension.as_deref()),
				("rhai_extension", self.scripting.rhai_extension.as_deref()),
			],
		})?;

		Ok(Self {
			compression_cache: cache_dir.to_string_lossy().into_owned(),
			..self
		})
	}
}

#[derive(Parser, Debug)]
#[command(author, version, about = "TMUTP server (TMkUp Transfer Protocol)")]
pub struct Args {
	#[arg(short = 'c', long = "config", default_value = "./tmutp-config.toml")]
	pub config: String,
}

/// Largest request body accepted by default.
pub const DEFAULT_MAX_BODY: usize = 1024 * 1024;

/// Where compressed responses are cached on disk and under which policy.
#[derive(Clone)]
pub struct DiskCache {
	pub dir: PathBuf,
	pub policy: DiskCachePolicy,
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
	pub compression_cache: DiskCache,
	pub max_body: usize,
}

// -----------------------------------------------------------------------------
// TMUTP status codes
// -----------------------------------------------------------------------------

pub const OK: &str = "20 OK";
pub const OK_EMPTY: &str = "22 OK EMPTY";
pub const BAD_REQUEST: &str = "30 BAD REQUEST";
pub const NOT_FOUND: &str = "31 NOT FOUND";
pub const FORBIDDEN: &str = "32 FORBIDDEN";
pub const SERVER_ERROR: &str = "40 SERVER ERROR";
pub const METHOD_NOT_ALLOWED: &str = "50 METHOD NOT ALLOWED";
pub const INVALID_RANGE: &str = "52 INVALID RANGE";
pub const RANGE_NOT_SATISFIABLE: &str = "53 RANGE NOT SATISFIABLE";
pub const UNSUPPORTED_RANGE: &str = "54 UNSUPPORTED RANGE";
pub const REQUIRE_SECURE: &str = "55 REQUIRE SECURE";

pub const TMUTP_VERSION: &str = "TMUTP/2.0";
pub const TMUTP_FIRST_VERSION: &str = "TMUTP/1.0";

pub fn status_code_to_text(code: u16) -> &'static str {
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

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
