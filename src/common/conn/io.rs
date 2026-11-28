use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Допустимое время без прогресса записи одного куска ответа.
pub const WRITE_IDLE: Duration = Duration::from_secs(30);
/// Таймаут TLS-рукопожатия.
pub const TLS_HANDSHAKE: Duration = Duration::from_secs(15);

const WRITE_CHUNK: usize = 64 * 1024;

/// Максимум одновременных SSH-каналов на сессию.
pub const MAX_SSH_CHANNELS: usize = 4;

fn timed_out(what: &'static str) -> io::Error {
	io::Error::new(io::ErrorKind::TimedOut, what)
}

/// Чтение с таймаутом простоя.
pub async fn read_idle<R>(reader: &mut R, buf: &mut [u8], idle: Duration) -> io::Result<usize>
where
	R: AsyncRead + Unpin,
{
	tokio::time::timeout(idle, reader.read(buf))
		.await
		.map_err(|_| timed_out("read idle timeout"))?
}

/// Запись ответа кусками: таймаут действует на каждый кусок (прогресс), а не на
/// весь ответ, поэтому большие ответы на медленных каналах не обрываются.
pub async fn write_response<W>(writer: &mut W, data: &[u8]) -> io::Result<()>
where
	W: AsyncWrite + Unpin,
{
	for chunk in data.chunks(WRITE_CHUNK) {
		tokio::time::timeout(WRITE_IDLE, writer.write_all(chunk))
			.await
			.map_err(|_| timed_out("write idle timeout"))??;
	}

	tokio::time::timeout(WRITE_IDLE, writer.flush())
		.await
		.map_err(|_| timed_out("flush idle timeout"))?
}

/// Явные и более строгие лимиты SSH-сессии.
pub fn harden_ssh_config(config: &mut russh::server::Config) {
	config.inactivity_timeout = Some(Duration::from_secs(300));
	config.auth_rejection_time = Duration::from_secs(1);
	config.max_auth_attempts = 3;
}
