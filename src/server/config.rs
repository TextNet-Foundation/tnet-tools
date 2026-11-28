use crate::conn::ServerLimits;
use anyhow::{Result, anyhow};
use clap::Parser;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	#[serde(default = "default_server_port")]
	pub port: u16,
	#[serde(default = "default_bind_address")]
	pub bind_address: String,
	#[serde(default = "default_max_connections")]
	pub max_connections: usize,
	#[serde(default = "default_max_connections_per_ip")]
	pub max_connections_per_ip: usize,
	/// Общий максимум жизни соединения в секундах.
	#[serde(default = "default_max_connection_secs")]
	pub max_connection_secs: u64,
	#[serde(default)]
	pub support_first_version: bool,
	pub protocols: Vec<Protocol>,
	#[serde(default)]
	pub explore: ExploreConfig,
	#[serde(default)]
	pub security: SecurityConfig,
}

fn default_server_port() -> u16 {
	34
}

fn default_bind_address() -> String {
	"127.0.0.1".to_string()
}

fn default_max_connections() -> usize {
	ServerLimits::default().max_connections
}

fn default_max_connections_per_ip() -> usize {
	ServerLimits::default().max_per_ip
}

fn default_max_connection_secs() -> u64 {
	ServerLimits::default().max_connection.as_secs()
}

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
	/// Ошибка (а не предупреждение), если приватный ключ доступен группе/всем (по умолчанию).
	#[serde(default = "default_strict_key_permissions")]
	pub strict_key_permissions: bool,
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
			strict_key_permissions: default_strict_key_permissions(),
		}
	}
}

fn default_strict_key_permissions() -> bool {
	true
}

fn default_ssh_host_key_path() -> String {
	"./ssh_host_ed25519_key".to_string()
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExploreConfig {
	#[serde(default)]
	pub nodes: Vec<ExploreNode>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExploreNode {
	pub version: String,
	pub host: String,
	pub description: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
	pub name: String,
	pub version: Vec<String>,
	#[serde(rename = "default-version")]
	pub default_version: usize,
	pub host: String,
	pub port: u16,
	#[serde(default)]
	pub security: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
	#[arg(short = 'c', long = "config", default_value = "./utnp-config.toml")]
	pub config: String,
}

#[derive(Clone)]
pub struct AppState {
	pub protocols: Arc<Vec<Protocol>>,
	pub explore_nodes: Arc<Vec<ExploreNode>>,
	pub support_first_version: bool,
	pub enabled_security: Vec<String>,
	pub require_secure: bool,
}

pub fn validate_protocols(protocols: &[Protocol]) -> Result<()> {
	for protocol in protocols {
		if protocol.name.trim().is_empty() {
			return Err(anyhow!("Protocol name cannot be empty"));
		}

		if protocol.version.is_empty() {
			return Err(anyhow!(
				"Protocol '{}' has an empty version array",
				protocol.name
			));
		}

		if protocol
			.version
			.iter()
			.any(|version| version.trim().is_empty())
		{
			return Err(anyhow!(
				"Protocol '{}' contains an empty version",
				protocol.name
			));
		}

		for (index, version) in protocol.version.iter().enumerate() {
			if protocol
				.version
				.iter()
				.take(index)
				.any(|existing| existing == version)
			{
				return Err(anyhow!(
					"Protocol '{}' contains duplicate version '{}'",
					protocol.name,
					version
				));
			}
		}

		if protocol.default_version == 0 || protocol.default_version > protocol.version.len() {
			return Err(anyhow!(
				"Protocol '{}': default-version={} is out of range (valid range: 1..={})",
				protocol.name,
				protocol.default_version,
				protocol.version.len()
			));
		}
	}

	Ok(())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
