//! Общий SSH-обработчик для tmutp/tbip: один код вместо двух копий.

use crate::common::conn::MAX_SSH_CHANNELS;
use crate::common::frame::{Frame, FrameParser};
use bytes::Bytes;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct ChannelBuffer {
	pub data: Vec<u8>,
	pub parser: FrameParser,
}

/// Обработчик запроса: (request bytes, state) -> response bytes.
pub type RequestHandler<S> =
	Arc<dyn Fn(Vec<u8>, Arc<S>) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> + Send + Sync>;

/// Обобщённый SSH-обработчик. `S` — тип состояния сервера (AppState tmutp/tbip).
pub struct SshHandler<S: Send + Sync + 'static> {
	pub state: Arc<S>,
	pub process: RequestHandler<S>,
	pub max_body: usize,
	pub buffers: HashMap<ChannelId, ChannelBuffer>,
}

impl<S: Send + Sync + 'static> SshHandler<S> {
	pub fn new(state: Arc<S>, process: RequestHandler<S>, max_body: usize) -> Self {
		Self {
			state,
			process,
			max_body,
			buffers: HashMap::new(),
		}
	}
}

impl<S: Send + Sync + 'static> Handler for SshHandler<S> {
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
				parser: FrameParser::new(self.max_body),
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
			match channel_buffer.parser.poll(&channel_buffer.data) {
				Frame::Complete(length) => {
					let request: Vec<u8> = channel_buffer.data.drain(..length).collect();
					channel_buffer.parser.reset();

					let response = (self.process)(request, self.state.clone()).await;
					session.data(channel, Bytes::from(response))?;
				}
				Frame::Incomplete => return Ok(()),
				Frame::Invalid(error) => {
					let response = format!(
						"ERROR 30 Bad request\nContent-Length: {}\n\n{}",
						error.message().len(),
						error.message()
					);
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
