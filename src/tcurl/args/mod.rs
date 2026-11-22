use crate::types::{TransportMode, TransportTarget};
use anyhow::{Result, bail};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "TextNet protocol client")]
#[command(group(
    clap::ArgGroup::new("method")
        .args(["post", "head"])
        .multiple(false)
))]
#[command(group(
    clap::ArgGroup::new("transport")
        .args(["ssh", "tcp"])
        .multiple(false)
))]
pub struct Args {
	/// TextNet URI: tmutp://host/path or tbip://host/path
	pub uri: String,

	/// Use POST (TMUTP only)
	#[arg(long)]
	pub post: bool,

	/// Use HEAD
	#[arg(long)]
	pub head: bool,

	/// Use UTNP/1.0 for service negotiation
	#[arg(long)]
	pub uv1: bool,

	/// Use TBIP/1.0 for binary transfers
	#[arg(long)]
	pub bv1: bool,

	/// Use TMUTP/1.0 for document transfers
	#[arg(long)]
	pub tv1: bool,

	/// Use version 1.0 of all protocols and force TCP only
	#[arg(long)]
	pub v1: bool,

	/// Use SSH for UTNP negotiation
	#[arg(long)]
	pub us: bool,

	/// Use SSH for TBIP
	#[arg(long)]
	pub bs: bool,

	/// Use SSH for TMUTP
	#[arg(long)]
	pub ts: bool,

	/// Use TCP only for UTNP negotiation
	#[arg(long)]
	pub utcp: bool,

	/// Use TCP only for TBIP
	#[arg(long)]
	pub btcp: bool,

	/// Use TCP only for TMUTP
	#[arg(long)]
	pub ttcp: bool,

	/// Try SSH, then TLS, then TCP
	#[arg(short = 's', long)]
	pub ssh: bool,

	/// Use TCP only
	#[arg(short = 't', long)]
	pub tcp: bool,

	/// Ignore security mechanisms advertised by UTNP
	#[arg(short = 'i', long = "ignore-utnp-security")]
	pub ignore_utnp_security: bool,

	/// Add request header
	#[arg(short = 'H', long = "header")]
	pub headers: Vec<String>,

	/// POST body
	#[arg(short = 'd', long)]
	pub data: Option<String>,

	/// POST body from file
	#[arg(long)]
	pub data_file: Option<PathBuf>,

	/// Save response body
	#[arg(short = 'o', long)]
	pub output: Option<PathBuf>,

	/// Save complete protocol response, including status line and headers
	#[arg(long = "output-header")]
	pub output_header: Option<PathBuf>,

	/// Additional trusted CA certificate in PEM format
	#[arg(long)]
	pub ca_cert: Option<PathBuf>,

	/// TLS SNI and certificate verification name
	#[arg(long)]
	pub verify_for_sni: Option<String>,

	/// Default UTNP port when URI has no port
	#[arg(long, default_value_t = 34)]
	pub utnp_port: u16,
}

/// Determines the transport independently for UTNP, TBIP and TMUTP.
///
/// Specific protocol flags override global -s / -t settings.
pub fn transport_mode(args: &Args, target: TransportTarget) -> Result<TransportMode> {
	let (specific_ssh, specific_tcp) = match target {
		TransportTarget::Utnp => (args.us, args.utcp),
		TransportTarget::Tmutp => (args.ts, args.ttcp),
		TransportTarget::Tbip => (args.bs, args.btcp),
	};

	if specific_ssh && specific_tcp {
		bail!("SSH and TCP cannot both be selected for the same protocol");
	}

	// Global legacy mode always forces TCP.
	if args.v1 {
		return Ok(TransportMode::TcpOnly);
	}

	// Protocol-specific settings have priority over global settings.
	if specific_tcp {
		return Ok(TransportMode::TcpOnly);
	}

	if specific_ssh {
		return Ok(TransportMode::SshThenTlsThenTcp);
	}

	// Global settings are used when no specific setting exists.
	if args.tcp {
		return Ok(TransportMode::TcpOnly);
	}

	if args.ssh {
		return Ok(TransportMode::SshThenTlsThenTcp);
	}

	Ok(TransportMode::TlsThenTcp)
}
