mod args;
mod request;
mod response;
mod target;
mod transport;
mod types;
mod utnp;

use anyhow::Context;
use args::Args;
use clap::Parser;
use request::build_request;
use response::handle_response;
use target::parse_target;
use transport::exchange_with_fallback;
use types::{FrameKind, Method, Protocol, TransportTarget};
use utnp::negotiate_endpoint;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
		)
		.init();

	let args = Args::parse();

	let target = parse_target(&args.uri)?;

	let method = if args.post {
		Method::Post
	} else if args.head {
		Method::Head
	} else {
		Method::Get
	};

	if method == Method::Post && target.protocol != Protocol::Tmutp {
		anyhow::bail!("POST is supported only by TMUTP");
	}

	if args.v1 && (args.ssh || args.us || args.bs || args.ts) {
		anyhow::bail!("SSH cannot be used with --v1; version 1.0 mode uses TCP only");
	}

	if args.v1 && args.ca_cert.is_some() {
		anyhow::bail!("--ca-cert cannot be used with --v1; version 1.0 mode uses TCP only");
	}

	if (args.us && args.utcp) || (args.bs && args.btcp) || (args.ts && args.ttcp) {
		anyhow::bail!("SSH and TCP cannot both be selected for the same protocol");
	}

	if (args.data.is_some() || args.data_file.is_some()) && method != Method::Post {
		anyhow::bail!("--data and --data-file require --post");
	}

	if args.data.is_some() && args.data_file.is_some() {
		anyhow::bail!("Use either --data or --data-file, not both");
	}

	if args.output.is_some() && args.output_header.is_some() && args.output == args.output_header {
		anyhow::bail!("--output and --output-header must use different files");
	}

	let utnp_mode = args::transport_mode(&args, TransportTarget::Utnp)?;

	let protocol_mode = match target.protocol {
		Protocol::Tmutp => args::transport_mode(&args, TransportTarget::Tmutp)?,
		Protocol::Tbip => args::transport_mode(&args, TransportTarget::Tbip)?,
	};

	let body = if let Some(data) = &args.data {
		data.as_bytes().to_vec()
	} else if let Some(path) = &args.data_file {
		tokio::fs::read(path)
			.await
			.with_context(|| format!("Cannot read POST body file: {}", path.display()))?
	} else {
		Vec::new()
	};

	let request = build_request(
		&target,
		method,
		&args.headers,
		&body,
		args.data.is_some(),
		request::protocol_uses_v1(&target, &args),
	)?;

	let endpoint = if let Some(port) = target.direct_port {
		types::Endpoint {
			host: target.host,
			port,
		}
	} else {
		let utnp_port = target.utnp_port.unwrap_or(args.utnp_port);

		println!(
			"Resolving {} through UTNP at {}:{}",
			target.protocol.name(),
			target.host,
			utnp_port
		);

		negotiate_endpoint(&target, utnp_port, utnp_mode, &args).await?
	};

	eprintln!(
		"Connecting to {}:{} using {}",
		endpoint.host,
		endpoint.port,
		target.protocol.name()
	);

	let response = exchange_with_fallback(
		&endpoint.host,
		endpoint.port,
		&request,
		FrameKind::Protocol {
			head: method == Method::Head,
		},
		protocol_mode,
		&args,
	)
	.await?;

	handle_response(
		&response,
		method == Method::Head,
		&args.output,
		&args.output_header,
	)
	.await?;

	Ok(())
}
