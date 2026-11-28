use crate::config::AppState;
use crate::conn::{ServerLimits, serve};
use crate::protocol::error_response;
use crate::server::dispatch;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Accept-цикл UTNP: лимиты соединений, отказ без ожидания, graceful shutdown.
pub async fn run_accept_loop(
	listener: TcpListener,
	state: AppState,
	tls_acceptor: Option<TlsAcceptor>,
	ssh_config: Option<Arc<russh::server::Config>>,
	limits: ServerLimits,
) -> anyhow::Result<()> {
	let busy_reply = error_response("2.0", "SERVICE UNAVAILABLE");

	serve(listener, &limits, &busy_reply, move |stream, peer| {
		let state = state.clone();
		let tls = tls_acceptor.clone();
		let ssh = ssh_config.clone();

		dispatch::dispatch_connection(stream, peer, state, tls, ssh)
	})
	.await
}
