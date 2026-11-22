use anyhow::anyhow;
use bytes::Bytes;
use russh::ChannelMsg;
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::timeout;

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

pub async fn exchange_ssh(
    host: &str,
    port: u16,
    request: &str,
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
        Duration::from_secs(15),
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

            return Err(SshAttemptError::Unavailable(error.to_string()));
        }

        Err(_) => {
            if key_checked.load(Ordering::SeqCst) {
                return Err(SshAttemptError::Failed(anyhow!(
                    "SSH connection timed out after host key exchange"
                )));
            }

            return Err(SshAttemptError::Unavailable(
                "SSH connection timed out".to_string(),
            ));
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
            Duration::from_secs(1)
        };

        let message = match timeout(wait_duration, channel.wait()).await {
            Ok(message) => message,

            Err(_) if !response.is_empty() => break,

            Err(_) => {
                return Err(SshAttemptError::Failed(anyhow!(
                    "Timed out waiting for UTNP response over SSH"
                )));
            }
        };

        match message {
            Some(ChannelMsg::Data { data }) => {
                response.extend_from_slice(&data);
            }

            Some(ChannelMsg::ExtendedData { data, .. }) => {
                response.extend_from_slice(&data);
            }

            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                break;
            }

            Some(_) => {}
        }
    }

    if response.is_empty() {
        return Err(SshAttemptError::Failed(anyhow!(
            "UTNP server returned an empty SSH response"
        )));
    }

    let _ = channel.close().await;

    Ok(response)
}
