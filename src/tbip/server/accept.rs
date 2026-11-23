use crate::common::conn::{ServerLimits, harden_ssh_config, serve};
use crate::config::{
	AppState, Args, Config, SUPPORTED_COMPRESSION, TBIP_VERSION, load_ssh_config, load_tls_acceptor,
};
use crate::handler::response::make_error_response;
use crate::script_engine::lua::LuaEngine;
use crate::script_engine::rhai::RhaiEngine;
use crate::server::dispatch::dispatch_connection;
use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info};

pub async fn run() -> Result<()> {
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

	let config: Config = toml::from_str(&config_content).context("Failed to parse TBIP config")?;
	let config = config.normalized(&args.config)?;

	let lua_engine = if config.scripting.enabled {
		let ext = config
			.scripting
			.lua_extension
			.clone()
			.unwrap_or_else(|| ".script.lua".to_string());

		let hot_reload = config.scripting.hot_reload.unwrap_or(true);

		Some(Arc::new(LuaEngine::new(
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

		Some(Arc::new(RhaiEngine::new(
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

	if config.compression_cache_enable {
		tokio::fs::create_dir_all(&config.compression_cache)
			.await
			.with_context(|| {
				format!(
					"Cannot create compression cache directory: {}",
					config.compression_cache
				)
			})?;
	}

	let state = AppState {
		root: config.root.clone(),
		lua_engine,
		rhai_engine,
		scripting_config: config.scripting.clone(),
		require_secure: config.security.require_secure,
		support_first_version: config.support_first_version,
		compression_minimum: config.compression_minimum,
		compression_cache: PathBuf::from(&config.compression_cache),
		compression_cache_enable: config.compression_cache_enable,
		compression_cache_source_maximum: config.compression_cache_source_maximum,
	};

	let listener = TcpListener::bind((config.bind_address.as_str(), config.port)).await?;

	info!("TBIP server listening on port {}", config.port);
	info!("Serving files from {}", config.root);
	info!("Protocol version: {}", TBIP_VERSION);
	info!("TBIP/1.0 compatibility: {}", state.support_first_version);
	info!("TSTS (require_secure): {}", state.require_secure);
	info!("TLS enabled: {}", tls_acceptor.is_some());
	info!("SSH enabled: {}", ssh_config.is_some());
	info!(
		"Compression: {} (minimum {} bytes, cache {} [enabled: {}, source max: {} bytes])",
		SUPPORTED_COMPRESSION.join(", "),
		state.compression_minimum,
		state.compression_cache.display(),
		state.compression_cache_enable,
		state.compression_cache_source_maximum,
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
			debug!(%peer, "connection accepted");
			dispatch_connection(stream, state, tls, ssh).await
		}
	})
	.await?;

	info!("TBIP server stopped");

	Ok(())
}
