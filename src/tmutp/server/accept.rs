use crate::common::conn::{ServerLimits, harden_ssh_config, serve};
use crate::config::*;
use crate::handler::make_error_response;
use crate::server::dispatch_connection;
use anyhow::Context;
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

pub async fn run() -> anyhow::Result<()> {
	let _ = tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
		)
		.try_init();

	let args = Args::parse();

	let config_content = tokio::fs::read_to_string(&args.config)
		.await
		.with_context(|| format!("Failed to read config: {}", args.config))?;

	let config: Config = toml::from_str(&config_content).context("Failed to parse TMUTP config")?;
	let config = config.normalized(&args.config)?;

	let lua_engine = if config.scripting.enabled {
		let ext = config
			.scripting
			.lua_extension
			.clone()
			.unwrap_or_else(|| ".script.lua".to_string());

		let hot_reload = config.scripting.hot_reload.unwrap_or(true);

		Some(Arc::new(crate::script_engine::lua::LuaEngine::new(
			&config.root,
			Some(ext),
			hot_reload,
		)))
	} else {
		None
	};

	let rhai_engine = if config.scripting.enabled {
		let ext = config
			.scripting
			.rhai_extension
			.clone()
			.unwrap_or_else(|| ".script.rhai".to_string());

		let hot_reload = config.scripting.hot_reload.unwrap_or(true);

		Some(Arc::new(crate::script_engine::rhai::RhaiEngine::new(
			&config.root,
			Some(ext),
			hot_reload,
		)))
	} else {
		None
	};

	let tls_acceptor = if config.security.enable_tls {
		Some(load_tls_acceptor(&config.security).await?)
	} else {
		None
	};

	let ssh_config = if config.security.enable_ssh {
		let mut loaded = load_ssh_config(&config.security)?;

		if let Some(ssh) = Arc::get_mut(&mut loaded) {
			harden_ssh_config(ssh);
		}

		Some(loaded)
	} else {
		None
	};

	let compression_cache = {
		let p = std::path::PathBuf::from(&config.compression_cache);
		if p.is_absolute() {
			p
		} else {
			std::path::PathBuf::from(&config.root).join(p)
		}
	};

	tokio::fs::create_dir_all(&compression_cache)
		.await
		.with_context(|| {
			format!(
				"Cannot create compression cache directory: {}",
				compression_cache.display()
			)
		})?;

	let state = AppState {
		root: config.root.clone(),
		lua_engine,
		rhai_engine,
		scripting_config: config.scripting.clone(),
		require_secure: config.security.require_secure,
		support_first_version: config.support_first_version,
		compression_minimum: config.compression_minimum,
		compression_cache,
	};

	let listener = TcpListener::bind((config.bind_address.as_str(), config.port)).await?;

	info!(port = config.port, "TMUTP server listening");
	info!(root = ?config.root, "serving files");
	info!(version = TMUTP_VERSION, "protocol version");
	info!(
		compat_v1 = state.support_first_version,
		"TMUTP/1.0 compatibility"
	);
	info!(require_secure = state.require_secure, "TSTS");
	info!(tls = tls_acceptor.is_some(), "TLS enabled");
	info!(ssh = ssh_config.is_some(), "SSH enabled");
	info!(
		"Compression: {} (minimum {} bytes, cache {})",
		SUPPORTED_COMPRESSION.join(", "),
		state.compression_minimum,
		state.compression_cache.display(),
	);

	if config.scripting.enabled {
		info!(
			"Scripting enabled (Lua: {}, Rhai: {})",
			state.lua_engine.is_some(),
			state.rhai_engine.is_some()
		);

		info!(
			"hide_scripts_behind: {}",
			state.scripting_config.hide_scripts_behind.unwrap_or(true)
		);
	} else {
		info!("Scripting disabled");
	}

	let busy_reply = make_error_response(
		"42 SERVICE UNAVAILABLE",
		"42 Service unavailable",
		"The server is at its connection limit",
	);

	let limits = ServerLimits::default();

	serve(listener, &limits, &busy_reply, move |stream, peer| {
		let state = state.clone();
		let tls = tls_acceptor.clone();
		let ssh = ssh_config.clone();

		async move {
			tracing::debug!(%peer, "connection accepted");
			dispatch_connection(stream, state, tls, ssh).await
		}
	})
	.await?;

	info!("TMUTP server stopped");

	Ok(())
}
