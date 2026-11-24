use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[test]
fn weighted_lru_evicts_by_weight_not_count() {
	let mut cache: WeightedLru<u32, &str> = WeightedLru::new(100);
	cache.put(1, "a", 40);
	cache.put(2, "b", 40);
	assert!(cache.get(&1).is_some());
	// Entry 2 is now the least recently used; inserting 40 more must evict it only.
	cache.put(3, "c", 40);
	assert!(cache.get(&2).is_none());
	assert!(cache.get(&1).is_some());
	assert!(cache.get(&3).is_some());
}

#[test]
fn weighted_lru_rejects_oversized_and_replaces_same_key() {
	let mut cache: WeightedLru<u32, &str> = WeightedLru::new(50);
	cache.put(1, "small", 10);
	cache.put(1, "huge", 500);
	assert!(cache.get(&1).is_none());

	cache.put(2, "x", 30);
	cache.put(2, "y", 30);
	cache.put(3, "z", 20);
	assert_eq!(cache.get(&2), Some(&"y"));
	assert_eq!(cache.get(&3), Some(&"z"));
}

#[test]
fn weighted_lru_shrinking_budget_evicts() {
	let mut cache: WeightedLru<u32, u32> = WeightedLru::new(100);
	cache.put(1, 1, 60);
	cache.put(2, 2, 30);
	cache.set_budget(40);
	assert!(cache.get(&1).is_none());
	assert!(cache.get(&2).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn singleflight_runs_work_once_for_concurrent_callers() {
	let flights: Arc<SingleFlight<u32, u32>> = Arc::new(SingleFlight::new());
	let counter = Arc::new(AtomicUsize::new(0));

	let mut handles = Vec::new();
	for _ in 0..20 {
		let flights = flights.clone();
		let counter = counter.clone();
		handles.push(tokio::spawn(async move {
			flights
				.run(7, || async move {
					counter.fetch_add(1, Ordering::SeqCst);
					tokio::time::sleep(Duration::from_millis(150)).await;
					Ok::<_, std::convert::Infallible>(42)
				})
				.await
		}));
	}

	for handle in handles {
		assert_eq!(handle.await.unwrap().unwrap(), 42);
	}
	assert_eq!(counter.load(Ordering::SeqCst), 1);

	// The entry is cleaned up: a later call computes again instead of reusing a stale cell.
	let again = flights
		.run(7, || async { Ok::<_, std::convert::Infallible>(43) })
		.await;
	assert_eq!(again, Ok(43));
}

#[tokio::test]
async fn singleflight_retries_after_error() {
	let flights: SingleFlight<u32, u32> = SingleFlight::new();
	assert!(
		flights
			.run(1, || async { Err::<u32, _>("boom") })
			.await
			.is_err()
	);
	assert_eq!(flights.run(1, || async { Ok::<_, &str>(5) }).await, Ok(5));
}

#[test]
fn lock_unpoisoned_survives_panic() {
	let mutex = Arc::new(Mutex::new(1u32));
	let clone = mutex.clone();
	let _ = std::thread::spawn(move || {
		let _guard = clone.lock().unwrap();
		panic!("poison");
	})
	.join();
	assert_eq!(*lock_unpoisoned(&mutex), 1);
}

#[test]
fn weighted_lru_zero_weight_entries_are_capped() {
	let mut cache: WeightedLru<u32, u32> = WeightedLru::new(1_000_000);

	for key in 0..200_000u32 {
		cache.put(key, key, 0);
	}

	let kept = (0..200_000u32)
		.filter(|key| cache.get(key).is_some())
		.count();
	assert!(kept <= weighted_lru::MAX_ENTRIES);
	assert!(cache.get(&0).is_none());
	assert!(cache.get(&199_999).is_some());
}
