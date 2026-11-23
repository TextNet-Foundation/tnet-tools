use crate::config::AppState;
use crate::conn::{MAX_SSH_CHANNELS, TLS_HANDSHAKE, Transport, sniff_transport};
use crate::protocol::{self, FrameStatus, Framer};
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

	match sniff_transport(&stream).await? {
		Transport::Tls => {
			let acceptor = tls_acceptor
				.ok_or_else(|| anyhow!("TLS handshake received but TLS is disabled"))?;

			let tls = time::timeout(TLS_HANDSHAKE, acceptor.accept(stream))
				.await
				.context("TLS handshake timed out")??;

			stream::serve_stream(tls, state, true).await?;
		}

		Transport::Ssh => {
			let config =
				ssh_config.ok_or_else(|| anyhow!("SSH handshake received but SSH is disabled"))?;

			let handler = SshHandler {
				state,
				buffers: std::collections::HashMap::new(),
			};

			let session = russh::server::run_stream(config, stream, handler).await?;
			session.await?;
		}

		Transport::Plain => {
			stream::serve_stream(stream, state, false).await?;
		}
	}

	tracing::debug!(%peer, "connection finished");
	Ok(())
}

use bytes::Bytes;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use std::collections::HashMap;

struct ChannelBuffer {
	data: Vec<u8>,
	framer: Framer,
}

struct SshHandler {
	state: AppState,
	buffers: HashMap<ChannelId, ChannelBuffer>,
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
		if self.buffers.len() >= MAX_SSH_CHANNELS {
			reply
				.reject(russh::ChannelOpenFailure::ResourceShortage)
				.await;
			return Ok(());
		}

		self.buffers.insert(
			channel.id(),
			ChannelBuffer {
				data: Vec::new(),
				framer: Framer::new(),
			},
		);
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
		let Some(channel_buffer) = self.buffers.get_mut(&channel) else {
			return Ok(());
		};

		channel_buffer.data.extend_from_slice(data);

		loop {
			match channel_buffer.framer.poll(&channel_buffer.data) {
				FrameStatus::Complete(length) => {
					let frame: Vec<u8> = channel_buffer.data.drain(..length).collect();
					channel_buffer.framer.reset();

					let response = protocol::process_request(&frame, &self.state);
					session.data(channel, Bytes::from(response))?;
				}
				FrameStatus::Incomplete => return Ok(()),
				FrameStatus::Invalid(reason) => {
					let response = protocol::error_response("2.0", reason);

					session.data(channel, Bytes::from(response))?;
					self.buffers.remove(&channel);
					session.close(channel)?;
					return Ok(());
				}
			}
		}
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
