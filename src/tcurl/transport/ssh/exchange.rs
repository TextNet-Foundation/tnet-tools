use crate::transport::framing::trim_and_check;
use crate::transport::ssh::handler::KnownHostsHandler;
use crate::types::{FrameKind, MAX_UTNP_RESPONSE, Policy, SECURE_FAILED, SshAttemptError};
use anyhow::anyhow;
use bytes::Bytes;
use russh::ChannelMsg;
use russh::client;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const RESPONSE_WAIT: Duration = Duration::from_secs(30);

/// UTNP has no framing. The TextNet servers close the channel after the
/// answer, and `Eof`/`Close` is the authoritative end marker. Only for a
/// server that keeps the channel open we infer the end from this much silence
/// after the last data (and warn that the answer might be cut).
const UTNP_SILENCE: Duration = Duration::from_secs(3);

/// Classifies a failure that happened before the server key was seen.
///
/// `ConnectionRefused` means that no SSH server listens here and is
/// `Unavailable`. Any other failure (reset, EOF, timeout, a peer that does not
/// speak SSH) could be an attacker forcing a downgrade, so it is `Failed`
/// unless the user allowed insecure fallback.
pub fn classify_connect_error(error: &russh::Error, allow_insecure: bool) -> SshAttemptError {
	let refused = matches!(
		error,
		russh::Error::IO(io) if io.kind() == std::io::ErrorKind::ConnectionRefused
	);

	if refused || allow_insecure {
		return SshAttemptError::Unavailable(error.to_string());
	}

	SshAttemptError::Failed(anyhow!("{SECURE_FAILED}: SSH connection failed: {error}"))
}

pub async fn exchange_ssh(
	host: &str,
	port: u16,
	request: &[u8],
	frame: FrameKind,
	policy: Policy,
) -> std::result::Result<Vec<u8>, SshAttemptError> {
	let key_checked = Arc::new(AtomicBool::new(false));
	let key_trusted = Arc::new(AtomicBool::new(false));

	let handler = KnownHostsHandler {
		host: host.to_string(),
		port,
		key_checked: key_checked.clone(),
		key_trusted: key_trusted.clone(),
	};

	let config = client::Config {
		inactivity_timeout: Some(Duration::from_secs(30)),
		..Default::default()
	};

	let mut session = match tokio::time::timeout(
		policy.connect_timeout,
		client::connect(Arc::new(config), (host, port), handler),
	)
	.await
	{
		Ok(Ok(session)) => session,

		Ok(Err(error)) => {
			if key_checked.load(Ordering::SeqCst) && !key_trusted.load(Ordering::SeqCst) {
				return Err(SshAttemptError::Untrusted(error.to_string()));
			}

			if key_checked.load(Ordering::SeqCst) {
				return Err(SshAttemptError::Failed(anyhow!(
					"SSH connection failed after host-key verification: {error}"
				)));
			}

			return Err(classify_connect_error(&error, policy.allow_insecure));
		}

		Err(_) => {
			if key_checked.load(Ordering::SeqCst) {
				return Err(SshAttemptError::Failed(anyhow!(
					"SSH connection timed out after host-key exchange"
				)));
			}

			return Err(if policy.allow_insecure {
				SshAttemptError::Unavailable("SSH connection timed out".to_string())
			} else {
				SshAttemptError::Failed(anyhow!("{SECURE_FAILED}: SSH connection timed out"))
			});
		}
	};

	let auth = session
		.authenticate_none("tcurl")
		.await
		.map_err(|error| SshAttemptError::Failed(anyhow!("SSH authentication failed: {error}")))?;

	if !auth.success() {
		return Err(SshAttemptError::Failed(anyhow!(
			"SSH server rejected none authentication"
		)));
	}

	let mut channel = session.channel_open_session().await.map_err(|error| {
		SshAttemptError::Failed(anyhow!("Cannot open SSH session channel: {error}"))
	})?;

	// This requests the protocol channel. No operating-system shell is run
	// by the TextNet SSH server.
	channel.request_shell(true).await.map_err(|error| {
		SshAttemptError::Failed(anyhow!("SSH protocol channel was rejected: {error}"))
	})?;

	channel
		.data_bytes(Bytes::from(request.to_vec()))
		.await
		.map_err(|error| {
			SshAttemptError::Failed(anyhow!("Cannot send request over SSH: {error}"))
		})?;

	channel
		.eof()
		.await
		.map_err(|error| SshAttemptError::Failed(anyhow!("Cannot finish SSH request: {error}")))?;

	let mut response = Vec::new();
	let mut complete = false;

	loop {
		let wait_time = match frame {
			FrameKind::Utnp if !response.is_empty() => UTNP_SILENCE,
			_ => RESPONSE_WAIT,
		};

		let message = match tokio::time::timeout(wait_time, channel.wait()).await {
			Ok(message) => message,

			Err(_) if matches!(frame, FrameKind::Utnp) && !response.is_empty() => {
				eprintln!(
					"WARN: SSH UTNP response end was inferred from {} s of silence; it may be incomplete",
					UTNP_SILENCE.as_secs()
				);
				break;
			}

			Err(_) => {
				return Err(SshAttemptError::Failed(anyhow!(
					"Timed out waiting for SSH response"
				)));
			}
		};

		match message {
			// Only the data stream carries the response; stderr is ignored.
			Some(ChannelMsg::Data { data }) => {
				response.extend_from_slice(&data);
			}

			Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
				break;
			}

			Some(_) => {}
		}

		match frame {
			FrameKind::Protocol { head } => {
				complete = trim_and_check(&mut response, head).map_err(SshAttemptError::Failed)?;

				if complete {
					break;
				}
			}

			FrameKind::Utnp if response.len() > MAX_UTNP_RESPONSE => {
				return Err(SshAttemptError::Failed(anyhow!(
					"UTNP response exceeds the size limit"
				)));
			}

			FrameKind::Utnp => {}
		}
	}

	let _ = channel.close().await;

	if response.is_empty() {
		return Err(SshAttemptError::Failed(anyhow!(
			"Server returned an empty SSH response"
		)));
	}

	if matches!(frame, FrameKind::Protocol { .. }) && !complete {
		return Err(SshAttemptError::Failed(anyhow!(
			"SSH channel closed before the response was complete"
		)));
	}

	Ok(response)
}

#[cfg(test)]
#[path = "exchange_tests.rs"]
mod tests;
