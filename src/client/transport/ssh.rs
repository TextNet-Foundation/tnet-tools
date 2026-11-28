use anyhow::anyhow;
use bytes::Bytes;
use russh::ChannelMsg;
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::timeout;

use super::MAX_UTNP_RESPONSE;

/// UTNP has no framing. The TextNet servers close the channel after the
/// answer, and `Eof`/`Close` is the authoritative end marker. Only for a
/// server that keeps the channel open the end is inferred from this much
/// silence after the last data (with a warning).
const UTNP_SILENCE: Duration = Duration::from_secs(3);

pub enum SshAttemptError {
	Unavailable(String),
	Untrusted(String),
	Failed(anyhow::Error),
}

pub struct KnownHostsHandler {
	host: String,
	port: u16,
	key_checked: Arc<AtomicBool>,
	key_trusted: Arc<AtomicBool>,
}

impl client::Handler for KnownHostsHandler {
	type Error = russh::Error;

	async fn check_server_key(
		&mut self,
		server_public_key: &PublicKeyOrCertificate,
	) -> std::result::Result<bool, Self::Error> {
		self.key_checked.store(true, Ordering::SeqCst);

		let public_key = server_public_key.public_key();

		let trusted =
			russh::keys::known_hosts::check_known_hosts(&self.host, self.port, &public_key)
				.unwrap_or(false);

		self.key_trusted.store(trusted, Ordering::SeqCst);

		Ok(trusted)
	}
}

/// Classifies a failure that happened before the server key was seen.
///
/// `ConnectionRefused` means that no SSH server listens here: `Unavailable`.
/// Any other failure (reset, EOF, timeout, a peer that does not speak SSH)
/// may be an attacker forcing a downgrade, so it is `Failed` unless the user
/// passed --allow-insecure-fallback.
pub(super) fn classify_connect_error(
	error: &russh::Error,
	allow_insecure: bool,
) -> SshAttemptError {
	let refused = matches!(
		error,
		russh::Error::IO(io) if io.kind() == std::io::ErrorKind::ConnectionRefused
	);

	if refused || allow_insecure {
		return SshAttemptError::Unavailable(error.to_string());
	}

	SshAttemptError::Failed(anyhow!(
		"{}: SSH connection failed: {error}",
		super::SECURE_FAILED
	))
}

pub async fn exchange_ssh(
	host: &str,
	port: u16,
	request: &str,
	policy: super::Policy,
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

	let config = Arc::new(config);

	let mut session = match timeout(
		policy.connect_timeout,
		client::connect(config, (host, port), handler),
	)
	.await
	{
		Ok(Ok(session)) => session,

		Ok(Err(error)) => {
			if key_checked.load(Ordering::SeqCst) {
				if !key_trusted.load(Ordering::SeqCst) {
					return Err(SshAttemptError::Untrusted(
						"The server key is unknown or has changed. \
                         Check ~/.ssh/known_hosts."
							.to_string(),
					));
				}

				return Err(SshAttemptError::Failed(anyhow!(
					"SSH connection failed after host verification: {error}"
				)));
			}

			return Err(classify_connect_error(&error, policy.allow_insecure));
		}

		Err(_) => {
			if key_checked.load(Ordering::SeqCst) {
				return Err(SshAttemptError::Failed(anyhow!(
					"SSH connection timed out after host key exchange"
				)));
			}

			return Err(if policy.allow_insecure {
				SshAttemptError::Unavailable("SSH connection timed out".to_string())
			} else {
				SshAttemptError::Failed(anyhow!(
					"{}: SSH connection timed out",
					super::SECURE_FAILED
				))
			});
		}
	};

	let auth = session
		.authenticate_none("utnp")
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

	// Используем SSH session channel как транспорт UTNP.
	// Команды Linux shell не запускаются.
	channel.request_shell(true).await.map_err(|error| {
		SshAttemptError::Failed(anyhow!("SSH session channel was rejected: {error}"))
	})?;

	channel
		.data_bytes(Bytes::from(request.as_bytes().to_vec()))
		.await
		.map_err(|error| {
			SshAttemptError::Failed(anyhow!("Cannot send UTNP request over SSH: {error}"))
		})?;

	channel
		.eof()
		.await
		.map_err(|error| SshAttemptError::Failed(anyhow!("Cannot finish SSH request: {error}")))?;

	let mut response = Vec::new();

	loop {
		let wait_duration = if response.is_empty() {
			Duration::from_secs(30)
		} else {
			UTNP_SILENCE
		};

		let message = match timeout(wait_duration, channel.wait()).await {
			Ok(message) => message,

			Err(_) if !response.is_empty() => {
				eprintln!(
					"WARN: SSH response end was inferred from {} s of silence; it may be incomplete",
					UTNP_SILENCE.as_secs()
				);
				break;
			}

			Err(_) => {
				return Err(SshAttemptError::Failed(anyhow!(
					"Timed out waiting for UTNP response over SSH"
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

		if response.len() > MAX_UTNP_RESPONSE {
			return Err(SshAttemptError::Failed(anyhow!(
				"UTNP response exceeds the size limit"
			)));
		}
	}

	let _ = channel.close().await;

	if response.is_empty() {
		return Err(SshAttemptError::Failed(anyhow!(
			"UTNP server returned an empty SSH response"
		)));
	}

	Ok(response)
}
