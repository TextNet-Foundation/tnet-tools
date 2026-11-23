pub mod accept;
pub mod dispatch;
pub mod stream;

use crate::config::{self, AppState, Args, Config};
use crate::conn::ServerLimits;
use crate::tls;
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

pub async fn run() -> Result<()> {
	let args = Args::parse();

	let config_content = tokio::fs::read_to_string(&args.config)
		.await
		.with_context(|| format!("cannot read config file: {:?}", args.config))?;

	let config: Config = toml::from_str(&config_content).context("invalid UTNP config")?;

	// Validate protocol versions before initializing transports or listening.
	config::validate_protocols(&config.protocols)?;

	let tls_acceptor = if config.security.enable_tls {
		Some(tls::load_tls_acceptor(&config.security).await?)
	} else {
		None
	};

	let ssh_config = if config.security.enable_ssh {
		Some(tls::load_ssh_config(&config.security).await?)
	} else {
		None
	};

	let mut enabled_security = Vec::with_capacity(2);

	if tls_acceptor.is_some() {
		enabled_security.push("tls".to_string());
	}

	if ssh_config.is_some() {
		enabled_security.push("ssh".to_string());
	}

	if config.security.require_secure && enabled_security.is_empty() {
		return Err(anyhow!(
			"security.require_secure=true requires at least one enabled protected transport (TLS or SSH)"
		));
	}

	let state = AppState {
		protocols: Arc::new(config.protocols),
		explore_nodes: Arc::new(config.explore.nodes),
		support_first_version: config.support_first_version,
		enabled_security,
		require_secure: config.security.require_secure,
	};

	let listener = TcpListener::bind((config.bind_address.as_str(), config.port))
		.await
		.with_context(|| format!("cannot bind {}:{}", config.bind_address, config.port))?;

	tracing::info!(bind = ?config.bind_address, port = config.port, "UTNP server listening");
	tracing::info!(protocols = state.protocols.len(), "loaded protocols");
	tracing::info!(
		support_first_version = state.support_first_version,
		"UTNP/2.0 enabled; UTNP/1.0 compatibility"
	);
	tracing::info!(tls = tls_acceptor.is_some(), "TLS enabled");
	tracing::info!(ssh = ssh_config.is_some(), "SSH enabled");
	tracing::info!(
		require_secure = state.require_secure,
		"USTS (secure transport required)"
	);

	if ssh_config.is_some() {
		tracing::info!("SSH authentication: none (transport only)");
	}

	let limits = ServerLimits {
		max_connections: config.max_connections,
		max_per_ip: config.max_connections_per_ip,
		max_connection: Duration::from_secs(config.max_connection_secs),
	};

	accept::run_accept_loop(listener, state, tls_acceptor, ssh_config, limits).await?;

	tracing::info!("UTNP server stopped");

	Ok(())
}
