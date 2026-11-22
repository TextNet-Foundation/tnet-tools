use crate::transport::framing::expected_response_length;
use crate::transport::ssh::handler::KnownHostsHandler;
use crate::types::{FrameKind, SshAttemptError};
use anyhow::anyhow;
use bytes::Bytes;
use russh::ChannelMsg;
use russh::client;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub async fn exchange_ssh(
    host: &str,
    port: u16,
    request: &[u8],
    frame: FrameKind,
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
        Duration::from_secs(15),
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

            return Err(SshAttemptError::Unavailable(error.to_string()));
        }

        Err(_) => {
            if key_checked.load(Ordering::SeqCst) {
                return Err(SshAttemptError::Failed(anyhow!(
                    "SSH connection timed out after host-key exchange"
                )));
            }

            return Err(SshAttemptError::Unavailable(
                "SSH connection timed out".to_string(),
            ));
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

    loop {
        let wait_time = match frame {
            FrameKind::Protocol { .. } => Duration::from_secs(30),
            FrameKind::Utnp if response.is_empty() => Duration::from_secs(30),
            FrameKind::Utnp => Duration::from_secs(1),
        };

        let message = match tokio::time::timeout(wait_time, channel.wait()).await {
            Ok(message) => message,

            Err(_) if matches!(frame, FrameKind::Utnp) && !response.is_empty() => {
                break;
            }

            Err(_) => {
                return Err(SshAttemptError::Failed(anyhow!(
                    "Timed out waiting for SSH response"
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

        if let FrameKind::Protocol { head } = frame
            && let Some(expected) =
                expected_response_length(&response, head).map_err(SshAttemptError::Failed)?
            && response.len() >= expected
        {
            break;
        }
    }

    if response.is_empty() {
        return Err(SshAttemptError::Failed(anyhow!(
            "Server returned an empty SSH response"
        )));
    }

    let _ = channel.close().await;

    Ok(response)
}
