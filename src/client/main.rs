mod cli;
mod request;
mod sanitize;
mod transport;

use anyhow::{Result, bail};
use clap::Parser;
use cli::Args;
use request::{build_request, print_response};

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
		)
		.init();

	let args = Args::parse();

	if args.v1 && args.ssh {
		bail!("SSH is not supported by UTNP/1.0");
	}

	if args.v1 && args.ca_cert.is_some() {
		bail!("--ca-cert cannot be used with UTNP/1.0");
	}

	let request = build_request(&args.command, args.v1)?;

	println!("→ {}", request.trim_end());

	let response = if args.v1 {
		println!("Transport: TCP");
		transport::exchange_tcp(
			&args.host,
			args.port,
			&request,
			transport::policy_from_args(&args).connect_timeout,
		)
		.await?
	} else {
		transport::exchange_v2(&args, &request).await?
	};

	print_response(&response)?;

	Ok(())
}
