use russh::client;
use russh::keys::PublicKeyOrCertificate;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct KnownHostsHandler {
	pub host: String,
	pub port: u16,
	pub key_checked: Arc<AtomicBool>,
	pub key_trusted: Arc<AtomicBool>,
}

impl client::Handler for KnownHostsHandler {
	type Error = russh::Error;

	async fn check_server_key(
		&mut self,
		server_public_key: &PublicKeyOrCertificate,
	) -> std::result::Result<bool, Self::Error> {
		self.key_checked.store(true, Ordering::SeqCst);

		let public_key = server_public_key.public_key();

		let trusted =
			russh::keys::known_hosts::check_known_hosts(&self.host, self.port, &public_key)
				.unwrap_or(false);

		self.key_trusted.store(trusted, Ordering::SeqCst);

		Ok(trusted)
	}
}
