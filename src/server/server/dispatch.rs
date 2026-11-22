use crate::config::AppState;
use crate::server::stream;
use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time;
use tokio_rustls::TlsAcceptor;

pub async fn dispatch_connection(
	stream: TcpStream,
	peer: SocketAddr,
	state: AppState,
	tls_acceptor: Option<TlsAcceptor>,
	ssh_config: Option<std::sync::Arc<russh::server::Config>>,
) -> Result<()> {
	stream.set_nodelay(true)?;

	let transport = sniff_transport(&stream).await?;

	match transport.as_str() {
		"tls" => {
			let acceptor = tls_acceptor
				.ok_or_else(|| anyhow!("TLS handshake received but TLS is disabled"))?;

			let tls = time::timeout(std::time::Duration::from_secs(15), acceptor.accept(stream))
				.await
				.context("TLS handshake timed out")??;

			stream::serve_stream(tls, state, true).await?;
		}

		"ssh" => {
			let config =
				ssh_config.ok_or_else(|| anyhow!("SSH handshake received but SSH is disabled"))?;

			let handler = SshHandler {
				state,
				buffers: std::collections::HashMap::new(),
			};

			let session = russh::server::run_stream(config, stream, handler).await?;
			session.await?;
		}

		_ => {
			stream::serve_stream(stream, state, false).await?;
		}
	}

	let _ = peer;
	Ok(())
}

pub async fn sniff_transport(stream: &TcpStream) -> Result<String> {
	let mut peek = [0u8; 8];

	let n = time::timeout(std::time::Duration::from_secs(10), async {
		loop {
			let n = stream.peek(&mut peek).await?;

			if n == 0 {
				return Err(std::io::Error::new(
					std::io::ErrorKind::UnexpectedEof,
					"client closed before sending data",
				));
			}

			if n >= 4 || (n >= 2 && peek[0] == 0x16) {
				return Ok(n);
			}

			let _ = stream.ready(tokio::io::Interest::READABLE).await;
		}
	})
	.await
	.context("Timed out while identifying connection transport")??;

	if n >= 4 && &peek[..4] == b"SSH-" {
		return Ok("ssh".into());
	}

	if n >= 2 && peek[0] == 0x16 && peek[1] == 0x03 {
		return Ok("tls".into());
	}

	Ok("plain".into())
}
use crate::protocol;
use bytes::Bytes;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use std::collections::HashMap;

struct SshHandler {
	state: AppState,
	buffers: HashMap<ChannelId, Vec<u8>>,
}

impl Handler for SshHandler {
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

		if buffer.len() > 1024 * 1024 {
			self.buffers.remove(&channel);
			session.close(channel)?;
			return Ok(());
		}

		while let Some(frame_len) = protocol::complete_frame_len(buffer) {
			let mut frame = Vec::with_capacity(frame_len);
			frame.extend(buffer.drain(..frame_len));

			let response = protocol::process_request(&frame, &self.state);

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
