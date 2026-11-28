use super::ssh::{RequestHandler, SshHandler};
use super::stream::{MAX_REQUEST_BODY, serve_stream};
use crate::common::conn::{TLS_HANDSHAKE, Transport, sniff_transport};
use crate::config::AppState;
use crate::handler::request::process_request;
use anyhow::Context;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub async fn dispatch_connection(
	stream: TcpStream,
	state: AppState,
	tls_acceptor: Option<TlsAcceptor>,
	ssh_config: Option<Arc<russh::server::Config>>,
) -> anyhow::Result<()> {
	stream.set_nodelay(true)?;

	match sniff_transport(&stream).await? {
		Transport::Tls => {
			let acceptor = tls_acceptor
				.ok_or_else(|| anyhow::anyhow!("TLS connection received, but TLS is disabled"))?;

			let tls_stream = tokio::time::timeout(TLS_HANDSHAKE, acceptor.accept(stream))
				.await
				.context("TLS handshake timed out")??;

			serve_stream(tls_stream, state, true).await?;
		}

		Transport::Ssh => {
			let config = ssh_config
				.ok_or_else(|| anyhow::anyhow!("SSH connection received, but SSH is disabled"))?;

			let state = Arc::new(state);
			let process: RequestHandler<AppState> =
				Arc::new(|req, st| Box::pin(async move { process_request(&req, &st).await }));

			let handler = SshHandler::new(state, process, MAX_REQUEST_BODY);

			let session = russh::server::run_stream(config, stream, handler).await?;
			session.await?;
		}

		Transport::Plain => {
			serve_stream(stream, state, false).await?;
		}
	}

	Ok(())
}
