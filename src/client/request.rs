use anyhow::{Result, bail};
use std::fmt::Write;

pub fn build_request(command: &crate::cli::Command, legacy: bool) -> Result<String> {
	if legacy {
		return match command {
			crate::cli::Command::List => Ok("UTNP/1.0 LIST\n".to_string()),

			crate::cli::Command::Negotiate { protocol, .. } => {
				validate_protocol_name(protocol)?;

				let mut output = String::with_capacity(32);
				let _ = writeln!(output, "UTNP/1.0 NEGOTIATE {}", protocol);
				Ok(output)
			}

			crate::cli::Command::Explore => {
				bail!("EXPLORE is not supported by UTNP/1.0");
			}
		};
	}

	match command {
		crate::cli::Command::List => Ok("UTNP/2.0 LIST\n\n".to_string()),

		crate::cli::Command::Explore => Ok("UTNP/2.0 EXPLORE\n\n".to_string()),

		crate::cli::Command::Negotiate { protocol, versions } => {
			validate_protocol_name(protocol)?;

			match versions {
				Some(versions) => {
					if versions.trim().is_empty() {
						bail!("Supported versions cannot be empty");
					}

					let mut output = String::with_capacity(64);
					let _ = write!(
						output,
						"UTNP/2.0 NEGOTIATE {}\nSupported-Versions: {}\n\n",
						protocol, versions
					);
					Ok(output)
				}

				None => {
					let mut output = String::with_capacity(32);
					let _ = write!(output, "UTNP/2.0 NEGOTIATE {}\n\n", protocol);
					Ok(output)
				}
			}
		}
	}
}

fn validate_protocol_name(protocol: &str) -> Result<()> {
	if protocol.trim().is_empty() || protocol.contains(',') {
		bail!("NEGOTIATE requires exactly one protocol name");
	}

	Ok(())
}

pub fn print_response(response: &[u8]) -> Result<()> {
	let response = String::from_utf8_lossy(response);

	if response.is_empty() {
		bail!("UTNP server returned an empty response");
	}

	for line in response.lines() {
		println!("← {}", line);
	}

	Ok(())
}
