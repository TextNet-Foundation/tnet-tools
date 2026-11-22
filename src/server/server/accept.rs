use crate::config::AppState;
use crate::server::dispatch;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsAcceptor;

pub async fn handle_accepted(
	stream: TcpStream,
	peer: std::net::SocketAddr,
	state: AppState,
	tls_acceptor: Option<TlsAcceptor>,
	ssh_config: Option<Arc<russh::server::Config>>,
	semaphore: Arc<Semaphore>,
) {
	let permit = match semaphore.acquire_owned().await {
		Ok(p) => p,
		Err(_) => return,
	};

	tokio::spawn(async move {
		let _permit = permit;
		let result = timeout(
			Duration::from_secs(120),
			dispatch::dispatch_connection(stream, peer, state, tls_acceptor, ssh_config),
		)
		.await;

		match result {
			Ok(Ok(())) => {}
			Ok(Err(error)) => {
				tracing::error!(peer = %peer, error = %error, "connection failed");
			}
			Err(_) => {
				tracing::warn!(peer = %peer, "connection timed out");
			}
		}
	});
}
