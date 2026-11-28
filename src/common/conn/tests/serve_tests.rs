use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn ip_limiter_releases_on_drop() {
	let limiter = IpLimiter::new(2);
	let ip: IpAddr = "127.0.0.1".parse().unwrap();
	let other: IpAddr = "127.0.0.2".parse().unwrap();

	let first = limiter.try_acquire(ip).unwrap();
	let _second = limiter.try_acquire(ip).unwrap();

	assert!(limiter.try_acquire(ip).is_none());
	assert!(limiter.try_acquire(other).is_some());

	drop(first);
	assert!(limiter.try_acquire(ip).is_some());
}

#[test]
fn ip_limiter_forgets_idle_ips() {
	let limiter = IpLimiter::new(1);
	let guard = limiter.try_acquire("10.0.0.1".parse().unwrap()).unwrap();

	assert_eq!(limiter.tracked_ips(), 1);
	drop(guard);
	assert_eq!(limiter.tracked_ips(), 0);
}

async fn start(
	limits: ServerLimits,
) -> (
	SocketAddr,
	tokio::sync::oneshot::Sender<()>,
	tokio::task::JoinHandle<()>,
) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let (tx, rx) = tokio::sync::oneshot::channel::<()>();

	let task = tokio::spawn(async move {
		let _ = serve_until(
			listener,
			&limits,
			b"BUSY\n",
			|mut stream, _| async move {
				let mut buf = [0u8; 16];
				let _ = stream.read(&mut buf).await?;
				Ok(())
			},
			rx,
		)
		.await;
	});

	(addr, tx, task)
}

#[tokio::test]
async fn refuses_over_per_ip_limit_without_blocking() {
	let limits = ServerLimits {
		max_per_ip: 1,
		..ServerLimits::default()
	};
	let (addr, stop, task) = start(limits).await;

	let _held = TcpStream::connect(addr).await.unwrap();
	let mut second = TcpStream::connect(addr).await.unwrap();

	let mut reply = Vec::new();
	let read = tokio::time::timeout(Duration::from_secs(2), second.read_to_end(&mut reply)).await;

	assert!(read.is_ok(), "refusal must not hang");
	assert_eq!(reply, b"BUSY\n");

	let _ = stop.send(());
	// held-соединение завершится по записи
	let mut held = _held;
	let _ = held.write_all(b"x").await;
	assert!(
		tokio::time::timeout(Duration::from_secs(5), task)
			.await
			.is_ok()
	);
}

#[tokio::test]
async fn shutdown_drains_active_connections() {
	let (addr, stop, task) = start(ServerLimits::default()).await;
	let mut conn = TcpStream::connect(addr).await.unwrap();

	tokio::time::sleep(Duration::from_millis(50)).await;
	let _ = stop.send(());
	tokio::time::sleep(Duration::from_millis(50)).await;
	assert!(!task.is_finished(), "waits for the active connection");

	conn.write_all(b"x").await.unwrap();
	assert!(
		tokio::time::timeout(Duration::from_secs(5), task)
			.await
			.is_ok()
	);
}
