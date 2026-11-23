//! Shared building blocks for the in-memory caches: weighted LRU, singleflight,
//! poison-tolerant locking and a helper that moves CPU-heavy work off the reactor.

mod singleflight;
mod weighted_lru;

pub use singleflight::SingleFlight;
pub use weighted_lru::WeightedLru;

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Bodies shorter than this are hashed/verified inline; longer ones go to `spawn_blocking`.
const INLINE_CPU_LIMIT: usize = 256 * 1024;

/// Locks a mutex, recovering the data if another thread panicked while holding it.
/// All guarded structures here are caches, so a half-updated state is harmless.
pub fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
	mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs `work` inline for small inputs and on the blocking pool for large ones.
/// Returns `None` only if the blocking task itself failed (panic or runtime shutdown).
pub async fn run_cpu<T, F>(input_len: usize, work: F) -> Option<T>
where
	T: Send + 'static,
	F: FnOnce() -> T + Send + 'static,
{
	if input_len < INLINE_CPU_LIMIT {
		return Some(work());
	}

	match tokio::task::spawn_blocking(work).await {
		Ok(value) => Some(value),
		Err(error) => {
			tracing::error!(error = %error, "blocking cpu task failed");
			None
		}
	}
}

#[cfg(test)]
#[path = "cache_util_tests.rs"]
mod tests;
