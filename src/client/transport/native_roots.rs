//! Process-wide cache of the parsed system root CA store.
//!
//! `rustls_native_certs::load_native_certs()` reads and DER-parses the whole
//! system store on every call; doing that per TLS connection is pure overhead,
//! so the parsed store is computed at most once per process and shared.

use std::sync::{Arc, LazyLock};
use tokio_rustls::rustls::RootCertStore;

static NATIVE_ROOTS: LazyLock<Result<Arc<RootCertStore>, String>> = LazyLock::new(|| {
	let native_certs = rustls_native_certs::load_native_certs();

	for error in &native_certs.errors {
		tracing::warn!(error = %error, "cannot load a system CA certificate");
	}

	let mut roots = RootCertStore::empty();

	for cert in native_certs.certs {
		roots.add(cert).map_err(|error| error.to_string())?;
	}

	Ok(Arc::new(roots))
});

/// The parsed system root certificates, loaded at most once per process.
///
/// The `Err` case is the first certificate that failed to parse, exactly what
/// an uncached per-connection load would have returned as a fatal error.
pub fn native_root_store() -> Result<Arc<RootCertStore>, String> {
	NATIVE_ROOTS.as_ref().map_err(String::clone).map(Arc::clone)
}
