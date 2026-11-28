use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[test]
fn classify_prefixes() {
	assert_eq!(classify(b""), None);
	assert_eq!(classify(b"S"), None);
	assert_eq!(classify(b"SSH"), None);
	assert_eq!(classify(b"SSH-"), Some(Transport::Ssh));
	assert_eq!(classify(b"SX"), Some(Transport::Plain));
	assert_eq!(classify(&[0x16]), None);
	assert_eq!(classify(&[0x16, 0x03]), Some(Transport::Tls));
	assert_eq!(classify(&[0x16, 0x01]), Some(Transport::Plain));
	assert_eq!(classify(b"UTNP"), Some(Transport::Plain));
	assert_eq!(classify(b"G"), Some(Transport::Plain));
}

#[tokio::test]
async fn partial_prefix_does_not_spin_and_times_out() {
	let calls = AtomicUsize::new(0);

	let result = sniff_with(Duration::from_millis(300), |buf: &mut [u8]| {
		calls.fetch_add(1, Ordering::Relaxed);
		buf[..2].copy_from_slice(b"SS");
		async { Ok(2usize) }
	})
	.await;

	assert!(result.is_err());
	// пауза растёт 5,10,20,40,80,100 мс: за 300 мс не больше десятка попыток
	let calls = calls.load(Ordering::Relaxed);
	assert!((2..=15).contains(&calls), "calls = {calls}");
}

#[tokio::test]
async fn real_socket_two_bytes_then_silence_times_out() {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();

	let client = tokio::spawn(async move {
		let mut conn = TcpStream::connect(addr).await.unwrap();
		conn.write_all(b"SS").await.unwrap();
		tokio::time::sleep(Duration::from_secs(2)).await;
	});

	let (stream, _) = listener.accept().await.unwrap();
	let started = std::time::Instant::now();

	// sniff_transport использует фиксированный SNIFF_TIMEOUT (10s),
	// поэтому для проверки таймаута через sniff_with нужен HRTB-совместимый closure.
	// Вместо этого проверяем, что 2 байта "SS" не дают классификацию за разумное время.
	let result = tokio::time::timeout(Duration::from_millis(300), sniff_transport(&stream)).await;

	assert!(result.is_err());
	assert!(started.elapsed() >= Duration::from_millis(290));
	client.abort();
}

#[tokio::test]
async fn data_arriving_later_is_classified() {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();

	tokio::spawn(async move {
		let mut conn = TcpStream::connect(addr).await.unwrap();
		conn.write_all(b"SS").await.unwrap();
		tokio::time::sleep(Duration::from_millis(50)).await;
		conn.write_all(b"H-2.0").await.unwrap();
		tokio::time::sleep(Duration::from_millis(500)).await;
	});

	let (stream, _) = listener.accept().await.unwrap();

	assert_eq!(sniff_transport(&stream).await.unwrap(), Transport::Ssh);
}

#[tokio::test]
async fn eof_is_an_error() {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();

	drop(TcpStream::connect(addr).await.unwrap());

	let (stream, _) = listener.accept().await.unwrap();

	assert!(sniff_transport(&stream).await.is_err());
}
