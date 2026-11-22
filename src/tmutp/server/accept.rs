use crate::config::*;
use crate::server::dispatch_connection;
use anyhow::Context;
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use tracing::error;

pub async fn run() -> anyhow::Result<()> {
	let _ = tracing_subscriber::fmt()
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		.try_init();

	let args = Args::parse();

	let config_content = tokio::fs::read_to_string(&args.config)
		.await
		.with_context(|| format!("Failed to read config: {}", args.config))?;

	let config: Config = toml::from_str(&config_content).context("Failed to parse TMUTP config")?;

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
		Some(load_ssh_config(&config.security)?)
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

	let listener = TcpListener::bind(("0.0.0.0", config.port)).await?;

	println!("TMUTP server listening on port {}", config.port);
	println!("Serving files from {}", config.root);
	println!("Protocol version: {}", TMUTP_VERSION);
	println!("TMUTP/1.0 compatibility: {}", state.support_first_version);
	println!("TSTS (require_secure): {}", state.require_secure);
	println!("TLS enabled: {}", tls_acceptor.is_some());
	println!("SSH enabled: {}", ssh_config.is_some());
	println!(
		"Compression: {} (minimum {} bytes, cache {})",
		SUPPORTED_COMPRESSION.join(", "),
		state.compression_minimum,
		state.compression_cache.display(),
	);

	if config.scripting.enabled {
		println!(
			"Scripting enabled (Lua: {}, Rhai: {})",
			state.lua_engine.is_some(),
			state.rhai_engine.is_some()
		);

		println!(
			"hide_scripts_behind: {}",
			state.scripting_config.hide_scripts_behind.unwrap_or(true)
		);
	} else {
		println!("Scripting disabled");
	}

	let semaphore = Arc::new(Semaphore::new(256));

	loop {
		tokio::select! {
			_ = tokio::signal::ctrl_c() => {
				println!("TMUTP server shutting down");
				break;
			}
			accept_result = listener.accept() => {
				let (stream, peer) = match accept_result {
					Ok(v) => v,
					Err(error) => {
						error!(error = %error, "accept error");
						continue;
					}
				};

				let permit = match semaphore.clone().acquire_owned().await {
					Ok(p) => p,
					Err(_) => continue,
				};

				let state = state.clone();
				let tls = tls_acceptor.clone();
				let ssh = ssh_config.clone();

				tokio::spawn(async move {
					let _permit = permit;
					let result = timeout(Duration::from_secs(120), dispatch_connection(stream, state, tls, ssh)).await;
					match result {
						Err(_) => error!(%peer, "connection timed out"),
						Ok(Err(error)) => error!(%peer, error = %error, "connection failed"),
						Ok(Ok(())) => {}
					}
				});
			}
		}
	}

	Ok(())
}
