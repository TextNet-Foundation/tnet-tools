#[path = "../common/mod.rs"]
mod common;

mod compression;
mod config;
mod handler;
mod server;

#[path = "../script_engine/mod.rs"]
mod script_engine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	server::run().await
}
