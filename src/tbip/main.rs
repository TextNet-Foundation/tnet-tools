#[path = "../common/mod.rs"]
mod common;

#[path = "../script_engine/mod.rs"]
mod script_engine;

mod compression;
mod config;
mod handler;
mod path;
mod server;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
	server::run().await
}
