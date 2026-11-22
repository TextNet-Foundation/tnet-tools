use crate::config::AppState;
use crate::handler::request::process_request;
use anyhow::Context;
use bytes::Bytes;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::stream::serve_stream;

pub async fn sniff_transport(stream: &TcpStream) -> anyhow::Result<&'static str> {
    let mut peek = [0u8; 8];

    let n = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let n = stream.peek(&mut peek).await?;

            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Client closed before sending data",
                ));
            }

            if n >= 4 || (n >= 2 && peek[0] == 0x16) {
                return Ok(n);
            }

            let _ = stream.ready(tokio::io::Interest::READABLE).await;
        }
    })
    .await
    .context("Timed out while detecting transport")??;

    if n >= 4 && &peek[..4] == b"SSH-" {
        return Ok("ssh");
    }

    if n >= 2 && peek[0] == 0x16 && peek[1] == 0x03 {
        return Ok("tls");
    }

    Ok("plain")
}

pub async fn dispatch_connection(
    stream: TcpStream,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    ssh_config: Option<Arc<russh::server::Config>>,
) -> anyhow::Result<()> {
    use anyhow::Context;

    stream.set_nodelay(true)?;

    match sniff_transport(&stream).await? {
        "tls" => {
            let acceptor = tls_acceptor
                .ok_or_else(|| anyhow::anyhow!("TLS connection received, but TLS is disabled"))?;

            let tls_stream =
                tokio::time::timeout(std::time::Duration::from_secs(15), acceptor.accept(stream))
                    .await
                    .context("TLS handshake timed out")??;

            serve_stream(tls_stream, state, true).await?;
        }

        "ssh" => {
            let config = ssh_config
                .ok_or_else(|| anyhow::anyhow!("SSH connection received, but SSH is disabled"))?;

            let handler = TbipSshHandler {
                state,
                buffers: HashMap::new(),
            };

            let session = russh::server::run_stream(config, stream, handler).await?;

            session.await?;
        }

        _ => {
            serve_stream(stream, state, false).await?;
        }
    }

    Ok(())
}

pub struct TbipSshHandler {
    pub state: AppState,
    pub buffers: HashMap<ChannelId, Vec<u8>>,
}

impl Handler for TbipSshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.buffers.insert(channel.id(), Vec::new());
        reply.accept().await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let buffer = self.buffers.entry(channel).or_default();
        buffer.extend_from_slice(data);

        if buffer.len() > 16 * 1024 * 1024 {
            self.buffers.remove(&channel);
            session.close(channel)?;
            return Ok(());
        }

        while let Some(frame_len) = super::stream::complete_request_len(buffer) {
            let request: Vec<u8> = buffer.drain(..frame_len).collect();
            let response = process_request(&request, &self.state).await;
            session.data(channel, Bytes::from(response))?;
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.buffers.remove(&channel);
        Ok(())
    }
}
