use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
pub const DEFAULT_MAX_PER_IP: usize = 32;
/// Общий максимум жизни соединения; высокий, чтобы не рвать большие загрузки.
pub const DEFAULT_MAX_CONNECTION_SECS: u64 = 3600;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct ServerLimits {
	pub max_connections: usize,
	pub max_per_ip: usize,
	pub max_connection: Duration,
}

impl Default for ServerLimits {
	fn default() -> Self {
		Self {
			max_connections: DEFAULT_MAX_CONNECTIONS,
			max_per_ip: DEFAULT_MAX_PER_IP,
			max_connection: Duration::from_secs(DEFAULT_MAX_CONNECTION_SECS),
		}
	}
}

/// Счётчик соединений по IP.
#[derive(Clone)]
pub struct IpLimiter {
	counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
	max_per_ip: usize,
}

/// RAII: освобождает слот IP при drop.
pub struct IpGuard {
	counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
	ip: IpAddr,
}

impl IpLimiter {
	pub fn new(max_per_ip: usize) -> Self {
		Self {
			counts: Arc::default(),
			max_per_ip,
		}
	}

	pub fn try_acquire(&self, ip: IpAddr) -> Option<IpGuard> {
		let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
		let count = counts.entry(ip).or_insert(0);

		if *count >= self.max_per_ip {
			return None;
		}

		*count += 1;

		Some(IpGuard {
			counts: self.counts.clone(),
			ip,
		})
	}

	#[cfg(test)]
	pub fn tracked_ips(&self) -> usize {
		self.counts.lock().unwrap_or_else(|e| e.into_inner()).len()
	}
}

impl Drop for IpGuard {
	fn drop(&mut self) {
		let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());

		if let Some(count) = counts.get_mut(&self.ip) {
			*count = count.saturating_sub(1);

			if *count == 0 {
				counts.remove(&self.ip);
			}
		}
	}
}

/// Accept-цикл до Ctrl+C.
pub async fn serve<F, Fut>(
	listener: TcpListener,
	limits: &ServerLimits,
	busy_reply: &[u8],
	handler: F,
) -> anyhow::Result<()>
where
	F: Fn(TcpStream, SocketAddr) -> Fut,
	Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
	serve_until(
		listener,
		limits,
		busy_reply,
		handler,
		tokio::signal::ctrl_c(),
	)
	.await
}

/// Accept-цикл: при исчерпании лимитов соединение отклоняется сразу (accept не
/// блокируется), при остановке ждём активные соединения ограниченное время.
pub async fn serve_until<F, Fut, S>(
	listener: TcpListener,
	limits: &ServerLimits,
	busy_reply: &[u8],
	handler: F,
	shutdown: S,
) -> anyhow::Result<()>
where
	F: Fn(TcpStream, SocketAddr) -> Fut,
	Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
	S: Future,
{
	tokio::pin!(shutdown);

	let semaphore = Arc::new(Semaphore::new(limits.max_connections));
	let per_ip = IpLimiter::new(limits.max_per_ip);
	let mut tasks: JoinSet<()> = JoinSet::new();

	loop {
		tokio::select! {
			_ = &mut shutdown => break,
			Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
			accepted = listener.accept() => {
				let (stream, peer) = match accepted {
					Ok(value) => value,
					Err(error) => {
						tracing::error!(?error, "accept error");
						tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
						continue;
					}
				};

				let Ok(permit) = semaphore.clone().try_acquire_owned() else {
					tracing::warn!(%peer, "connection limit reached, refusing");
					refuse(&stream, busy_reply);
					continue;
				};

				let Some(guard) = per_ip.try_acquire(peer.ip()) else {
					tracing::warn!(%peer, "per-IP connection limit reached, refusing");
					refuse(&stream, busy_reply);
					continue;
				};

				let max_connection = limits.max_connection;
				let connection = handler(stream, peer);

				tasks.spawn(async move {
					let _permit = permit;
					let _guard = guard;

					match tokio::time::timeout(max_connection, connection).await {
						Ok(Ok(())) => {}
						Ok(Err(error)) => tracing::warn!(%peer, ?error, "connection failed"),
						Err(_) => tracing::warn!(%peer, "connection exceeded maximum lifetime"),
					}
				});
			}
		}
	}

	drop(listener);

	let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
		while tasks.join_next().await.is_some() {}
	})
	.await;

	if drained.is_err() {
		tracing::warn!(
			remaining = tasks.len(),
			"shutdown grace expired, aborting connections"
		);
		tasks.abort_all();
	}

	Ok(())
}

/// Best-effort уведомление без ожидания: сокет только что принят, буфер записи пуст.
fn refuse(stream: &TcpStream, reply: &[u8]) {
	if !reply.is_empty() {
		let _ = stream.try_write(reply);
	}
}

#[cfg(test)]
#[path = "tests/serve_tests.rs"]
mod tests;
