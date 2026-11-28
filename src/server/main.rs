mod config;

#[path = "../common/conn/mod.rs"]
mod conn;

mod protocol;
mod server;
mod tls;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
		)
		.init();

	server::run().await
}
