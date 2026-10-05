use parking_lot::Mutex;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Default capacity reset to 200K in 1.5.0 after the memory audit. The 1M
/// cap inherited from 1.4 cost ~38 MiB of resident memory for a window that
/// only needed ~200K entries in practice (ingest rate ~1K unique/sec × 15-min
/// TTL = 900K theoretical max but real cross-log dedup converges much lower
/// because TTL eviction churns continuously). Operators who really want a
/// wider window can override via `CERTSTREAM_DEDUP_CAPACITY` or YAML
/// `dedup.capacity`; the trade-off is purely memory ↔ deeper cross-log
/// dedup, never correctness.
const DEFAULT_CAPACITY: usize = 200_000;
/// 15 minutes — comfortably covers the typical multi-log SCT propagation window
/// (a few minutes) plus headroom for slower static-ct shards. Configurable via
/// `dedup.ttl_secs` in YAML or `CERTSTREAM_DEDUP_TTL_SECS`.
const DEFAULT_TTL_SECS: u64 = 900;
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 15;

/// How many time slices the window is cut into. Expiry drops a whole slice at
/// once, so an entry is held between `ttl` and `ttl + ttl / GENERATIONS` after
/// it was first seen.
const GENERATIONS: u32 = 8;

/// A fingerprint seen within the window, kept as the first 128 bits of its
/// SHA-256. The digest is uniformly distributed, so a prefix is as good a key
/// as the whole thing: two different certificates share one with a probability
/// around 2^-129 per pair, about 10^-28 across a full 200K window. Held as
/// 32 bytes plus a timestamp in a `DashMap` the same entry cost ~160 bytes,
/// 32 MB at the default capacity; 16 bytes in a plain set is ~28.
type Fingerprint = u128;

/// One time slice of the window: everything first seen while it was the
/// newest. Expiring a slice is dropping its set, so there is no per-entry
/// timestamp and no sweep over the table.
struct Generation {
    born: Instant,
    keys: HashSet<Fingerprint, ahash::RandomState>,
}

struct Window {
    /// Oldest first; never empty.
    generations: VecDeque<Generation>,
}

pub struct DedupFilter {
    window: Mutex<Window>,
    /// Upper bound on entries. Enforced by dropping the oldest slice, which
    /// shortens the window; a filter over capacity loses dedup depth, never
    /// correctness.
    capacity: usize,
    /// Configured window.
    ttl: Duration,
}

impl DedupFilter {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_CAPACITY, Duration::from_secs(DEFAULT_TTL_SECS))
    }

    pub fn with_config(capacity: usize, ttl: Duration) -> Self {
        let mut generations = VecDeque::new();
        generations.push_back(Generation::new(Instant::now()));
        Self {
            window: Mutex::new(Window { generations }),
            capacity: capacity.max(1),
            ttl,
        }
    }

    fn slice(&self) -> Duration {
        (self.ttl / GENERATIONS).max(Duration::from_millis(1))
    }

    /// Returns true if this SHA-256 fingerprint has NOT been seen before (i.e., is new).
    /// Takes the raw 32-byte digest, no allocation on a hit.
    ///
    /// The check and the insert happen under one lock, so two concurrent calls
    /// with the same key can never both observe "not present".
    pub fn is_new(&self, sha256_raw: &[u8; 32]) -> bool {
        let key = Fingerprint::from_le_bytes(sha256_raw[..16].try_into().expect("16 bytes"));
        let now = Instant::now();
        let mut window = self.window.lock();
        window.advance(now, self.slice(), self.ttl);

        if window.generations.iter().any(|g| g.keys.contains(&key)) {
            metrics::counter!("certstream_duplicates_filtered").increment(1);
            return false;
        }
        window
            .generations
            .back_mut()
            .expect("the window always has a newest slice")
            .keys
            .insert(key);
        true
    }

    /// Applies expiry and the capacity bound, and publishes the gauges. Both
    /// also happen on every `is_new`, so this only matters while nothing is
    /// arriving.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut window = self.window.lock();
        let before = window.len();
        window.advance(now, self.slice(), self.ttl);
        let mut trimmed = 0;
        while window.len() > self.capacity && window.generations.len() > 1 {
            window.generations.pop_front();
            trimmed += 1;
        }
        if trimmed > 0 {
            metrics::counter!("certstream_dedup_capacity_trims").increment(trimmed);
        }
        let remaining = window.len();
        let effective = now.duration_since(window.generations[0].born).max(self.slice());
        if before > remaining {
            debug!(
                removed = before - remaining,
                remaining,
                effective_ttl_secs = effective.as_secs_f64(),
                "dedup cleanup"
            );
        }
        metrics::gauge!("certstream_dedup_cache_size").set(remaining as f64);
        metrics::gauge!("certstream_dedup_effective_ttl_seconds")
            .set(effective.min(self.ttl).as_secs_f64());
    }

    /// Snapshot of current entry count. Used by the heartbeat log and by
    /// tests; the `certstream_dedup_cache_size` Prometheus gauge carries
    /// the same value for scrape-based monitoring.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.window.lock().len()
    }

    pub fn start_cleanup_task(self: Arc<Self>, cancel: CancellationToken) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("dedup cleanup task stopping");
                        break;
                    }
                    _ = tick.tick() => {
                        self.cleanup();
                    }
                }
            }
        });
    }
}

impl Generation {
    fn new(born: Instant) -> Self {
        Self {
            born,
            keys: HashSet::with_hasher(ahash::RandomState::default()),
        }
    }
}

impl Window {
    fn len(&self) -> usize {
        self.generations.iter().map(|g| g.keys.len()).sum()
    }

    /// Starts a new slice when the newest is full, and drops the slices that
    /// are past the window. A slice goes only once every key in it is older
    /// than `ttl`: its keys were first seen at most `slice` after it was born.
    fn advance(&mut self, now: Instant, slice: Duration, ttl: Duration) {
        let newest = self.generations.back().expect("never empty").born;
        if now.duration_since(newest) >= slice {
            self.generations.push_back(Generation::new(now));
        }
        while self.generations.len() > 1
            && now.duration_since(self.generations[0].born) >= ttl + slice
        {
            self.generations.pop_front();
        }
    }
}

impl Default for DedupFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    fn numbered(seq: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&seq.to_be_bytes());
        k
    }

    #[test]
    fn test_is_new_first_seen() {
        let filter = DedupFilter::new();
        assert!(filter.is_new(&key(1)));
        assert!(filter.is_new(&key(2)));
    }

    #[test]
    fn test_is_new_duplicate() {
        let filter = DedupFilter::new();
        assert!(filter.is_new(&key(1)));
        assert!(!filter.is_new(&key(1)));
        assert!(!filter.is_new(&key(1)));
    }

    #[test]
    fn test_is_new_different_keys() {
        let filter = DedupFilter::new();
        assert!(filter.is_new(&key(1)));
        assert!(filter.is_new(&key(2)));
        assert!(filter.is_new(&key(3)));
        assert!(!filter.is_new(&key(1)));
        assert!(!filter.is_new(&key(2)));
    }

    #[test]
    fn a_key_is_new_again_once_the_window_has_passed() {
        let filter = DedupFilter::with_config(DEFAULT_CAPACITY, Duration::from_millis(80));
        let k = key(42);
        assert!(filter.is_new(&k));
        assert!(!filter.is_new(&k));

        // ttl plus one slice is the longest an entry can be held.
        thread::sleep(Duration::from_millis(80 + 80 / GENERATIONS as u64 + 30));
        assert!(filter.is_new(&k));
    }

    #[test]
    fn a_key_is_held_for_at_least_the_ttl() {
        let filter = DedupFilter::with_config(DEFAULT_CAPACITY, Duration::from_millis(400));
        assert!(filter.is_new(&key(1)));
        thread::sleep(Duration::from_millis(300));
        assert!(!filter.is_new(&key(1)), "still inside the window");
    }

    /// Only the first 128 bits of the digest are kept, which is the point of
    /// the compact form; this pins that down so a change to it is deliberate.
    #[test]
    fn only_the_first_128_bits_of_the_digest_identify_a_certificate() {
        let filter = DedupFilter::new();
        let mut a = [7u8; 32];
        let mut b = a;
        b[31] = 8;
        assert!(filter.is_new(&a));
        assert!(!filter.is_new(&b));
        a[0] = 9;
        assert!(filter.is_new(&a), "a change in the first 16 bytes is a different key");
    }

    #[test]
    fn sustained_load_stays_near_capacity() {
        const CAPACITY: usize = 400;
        const PER_ROUND: usize = 50;
        const ROUNDS: usize = 40;
        let filter = DedupFilter::with_config(CAPACITY, Duration::from_millis(800));

        let mut seq = 0;
        let mut sizes = Vec::new();
        for _ in 0..ROUNDS {
            for _ in 0..PER_ROUND {
                seq += 1;
                filter.is_new(&numbered(seq));
            }
            thread::sleep(Duration::from_millis(30));
            filter.cleanup();
            sizes.push(filter.len());
        }

        // Arrival is ~1600/s against an 0.8 s window, which would hold ~1300
        // entries; the bound has to hold it near 400. A slice is dropped whole,
        // so it can sit a slice's worth of arrivals above capacity.
        let settled = &sizes[ROUNDS / 2..];
        let worst = settled.iter().copied().max().unwrap();
        assert!(
            worst <= CAPACITY + PER_ROUND * 8,
            "sustained load settled at {worst} entries against a capacity of {CAPACITY}; sizes: {sizes:?}"
        );
    }

    #[test]
    fn over_capacity_drops_the_oldest_keys_and_keeps_the_newest() {
        let filter = DedupFilter::with_config(30, Duration::from_millis(800));
        for i in 0..40u64 {
            assert!(filter.is_new(&numbered(i)));
            if i % 5 == 4 {
                thread::sleep(Duration::from_millis(110));
            }
        }
        filter.cleanup();
        assert!(filter.len() < 40, "the oldest slice must have gone");
        assert!(filter.is_new(&numbered(0)), "the oldest key must be forgotten");
        assert!(!filter.is_new(&numbered(39)), "the newest key must still be held");
    }

    /// A burst that fits in one slice cannot be trimmed without forgetting
    /// the newest keys too, so it stays: nothing is wiped and re-broadcast.
    #[test]
    fn a_burst_inside_one_slice_is_not_wiped() {
        let filter = DedupFilter::with_config(5, Duration::from_secs(300));
        for i in 0u8..5 {
            assert!(filter.is_new(&key(i)));
        }
        assert!(filter.is_new(&key(255)));
        filter.cleanup();
        assert!(!filter.is_new(&key(0)));
        assert!(!filter.is_new(&key(4)));
        assert!(filter.len() >= 5);
    }

    #[test]
    fn nothing_under_capacity_is_dropped_early() {
        let filter = DedupFilter::with_config(1000, Duration::from_secs(300));
        for i in 0u8..10 {
            assert!(filter.is_new(&key(i)));
        }
        filter.cleanup();
        assert_eq!(filter.len(), 10);
    }

    #[test]
    fn test_is_new_atomic_under_contention() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 32 threads, each calls is_new on the same key 1000 times.
        // Exactly ONE call across all threads should ever return true.
        let filter = Arc::new(DedupFilter::new());
        let true_count = Arc::new(AtomicUsize::new(0));
        let k = key(7);

        let handles: Vec<_> = (0..32)
            .map(|_| {
                let f = Arc::clone(&filter);
                let c = Arc::clone(&true_count);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        if f.is_new(&k) {
                            c.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(true_count.load(Ordering::Relaxed), 1);
    }

    /// What the compact form is for: the same entries in a fraction of the
    /// memory. `HashSet<u128>` is 16 bytes a key plus a control byte, against
    /// 32 + 16 in the map it replaced.
    #[test]
    fn a_full_window_holds_a_key_in_well_under_forty_bytes() {
        let filter = DedupFilter::with_config(200_000, Duration::from_secs(900));
        for i in 0..100_000u64 {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_le_bytes());
            k[8..16].copy_from_slice(&(i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes());
            filter.is_new(&k);
        }
        let window = filter.window.lock();
        let buckets: usize = window.generations.iter().map(|g| g.keys.capacity()).sum();
        assert!(
            buckets * (16 + 1) < 100_000 * 40,
            "{} bytes for 100000 keys",
            buckets * 17
        );
    }
}
