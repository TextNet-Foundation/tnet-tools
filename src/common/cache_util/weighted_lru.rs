use lru::LruCache;
use std::hash::Hash;

/// LRU cache bounded by the summed weight (bytes) of its values instead of entry count.
pub struct WeightedLru<K: Hash + Eq, V> {
	inner: LruCache<K, (V, usize)>,
	total: usize,
	budget: usize,
}

impl<K: Hash + Eq, V> WeightedLru<K, V> {
	pub fn new(budget: usize) -> Self {
		Self {
			inner: LruCache::unbounded(),
			total: 0,
			budget,
		}
	}

	pub fn set_budget(&mut self, budget: usize) {
		self.budget = budget;
		self.evict();
	}

	pub fn get(&mut self, key: &K) -> Option<&V> {
		self.inner.get(key).map(|(value, _)| value)
	}

	/// Inserts a value. An entry heavier than the whole budget is not stored at all
	/// (and replaces nothing but removes a stale entry under the same key).
	pub fn put(&mut self, key: K, value: V, weight: usize) {
		if let Some((_, old_weight)) = self.inner.pop(&key) {
			self.total = self.total.saturating_sub(old_weight);
		}

		if weight > self.budget {
			return;
		}

		self.inner.put(key, (value, weight));
		self.total = self.total.saturating_add(weight);
		self.evict();
	}

	fn evict(&mut self) {
		while self.total > self.budget {
			match self.inner.pop_lru() {
				Some((_, (_, weight))) => self.total = self.total.saturating_sub(weight),
				None => {
					self.total = 0;
					break;
				}
			}
		}
	}
}
