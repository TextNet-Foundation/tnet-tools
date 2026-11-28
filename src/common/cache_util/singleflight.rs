use super::lock_unpoisoned;
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

/// Collapses concurrent computations of the same key into one.
///
/// The first caller for a key runs the closure; everybody who arrives while it is
/// running awaits the same cell and receives a clone of the result. The map entry
/// is removed once the call finishes, so the map never grows past the in-flight set.
/// If the computation fails, the error goes to the caller that ran it and the next
/// waiter retries with its own closure.
pub struct SingleFlight<K, V> {
	cells: Mutex<HashMap<K, Arc<OnceCell<V>>>>,
}

impl<K: Hash + Eq + Clone, V: Clone> SingleFlight<K, V> {
	pub fn new() -> Self {
		Self {
			cells: Mutex::new(HashMap::new()),
		}
	}

	pub async fn run<F, Fut, E>(&self, key: K, work: F) -> Result<V, E>
	where
		F: FnOnce() -> Fut,
		Fut: Future<Output = Result<V, E>>,
	{
		let cell = lock_unpoisoned(&self.cells)
			.entry(key.clone())
			.or_insert_with(|| Arc::new(OnceCell::new()))
			.clone();

		let result = cell.get_or_try_init(work).await.cloned();

		let mut cells = lock_unpoisoned(&self.cells);
		if cells
			.get(&key)
			.is_some_and(|current| Arc::ptr_eq(current, &cell))
		{
			cells.remove(&key);
		}

		result
	}
}
