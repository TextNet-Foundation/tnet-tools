pub mod accept;
pub mod dispatch;
pub mod stream;

use crate::config::{self, AppState, Args, Config};
use crate::tls;
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

pub async fn run() -> Result<()> {
	let args = Args::parse();

	let config_content = tokio::fs::read_to_string(&args.config)
		.await
		.with_context(|| format!("cannot read config file: {}", args.config))?;

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

	let listener = TcpListener::bind(("0.0.0.0", config.port)).await?;

	tracing::info!(port = config.port, "UTNP server listening");
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

	let semaphore = Arc::new(Semaphore::new(256));

	loop {
		tokio::select! {
			_ = tokio::signal::ctrl_c() => {
				tracing::info!("UTNP server shutting down");
				break;
			}
			accept_result = listener.accept() => {
				let (stream, peer) = match accept_result {
					Ok(v) => v,
					Err(error) => {
						tracing::error!(error = %error, "accept error");
						continue;
					}
				};

				accept::handle_accepted(
					stream,
					peer,
					state.clone(),
					tls_acceptor.clone(),
					ssh_config.clone(),
					semaphore.clone(),
				)
				.await;
			}
		}
	}

	Ok(())
}
