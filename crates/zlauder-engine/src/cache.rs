//! Content-addressed, in-memory detection cache (Component 1).
//!
//! Claude Code re-sends the entire growing transcript on every turn, so the proxy
//! otherwise re-runs detection over byte-identical leaves turn after turn —
//! quadratic work, and catastrophic once the heavy optional ML recognizer is
//! `Ready`. This cache memoizes [`crate::detect::run_detection`]'s output per text
//! leaf so only genuinely *new* content pays for detection.
//!
//! ## What is cached (and what is NOT)
//! The OPERATOR-FREE, PLAINTEXT-FREE detection list: spans + entity_type + score +
//! source (+ the structural literal-token marker). Two deliberate exclusions:
//! - **Operators** are resolved at apply time from the live policy
//!   ([`crate::detect::resolve_operator`]), so an operator-rendering change applies
//!   WITHOUT invalidating the cache, and the deferred Component-3 burn is a clean
//!   apply-time override.
//! - **Plaintext / the masked string** is never stored — the apply loop slices the
//!   span out of the LIVE text being masked and replays the splice/mint, which is
//!   also REQUIRED for correctness (custom `literal_token` tokens unmask only via
//!   the per-call manifest, so the masked string can't simply be cached).
//!
//! ## Key
//! [`CacheKey`] = `{ text_hash: blake3(text) [full 256-bit], surface, policy_fp,
//! ml_fp }`. The FULL digest is the verification: a collision would return offsets
//! for a *different* string → wrong-span splice → silent leak, so `Eq` over all 32
//! bytes is load-bearing (invariant #1). `policy_fp` / `ml_fp` are fingerprints of
//! every detection-affecting input (Bazel/Salsa-style), so any such change yields a
//! fresh key space with nothing to hand-invalidate.
//!
//! ## Disk-persistence seam (DEFERRED — documented, not built)
//! A future `DiskBackend` would key by `HMAC(session_key, text)` (NOT a bare
//! content hash, so the file is not a confirmation oracle for "was value X here?")
//! and store AES-GCM-encrypted detection lists tagged with `(policy_fp, ml_fp)`. No
//! trait / serde is introduced until that backend exists; the in-memory cache
//! exposes a small `get` / `insert` / `set_cap` surface a backend can wrap. The
//! inert `detection_cache_persist` / `detection_cache_path` config flags reserve the
//! config surface only.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use lru::LruCache;

use crate::config::Operator;
use crate::surface::Surface;

/// blake3 domain tag for cache-key text hashing. MUST differ from the token
/// minting in `token.rs` (which prepends the 16-byte salt) and `hash_value` (bare
/// plaintext), so a cache key can never collide with a token hash (invariant #7).
const HASH_TEXT_DOMAIN: &[u8] = b"zlauder-detection-cache-key-v1";

/// Refuse to cache a pathologically large detection list (audit #8). The cap bounds
/// ENTRY count, not bytes, so one adversarial leaf carrying a huge number of spans
/// could otherwise blow memory past the implied bound. Such a leaf is rare;
/// recomputing it each turn is the safe ceiling. The ~95% empty/normal-leaf case is
/// far below this, so the common path is unaffected.
const MAX_CACHED_DETECTIONS: usize = 8192;

/// Which recognizer produced a detection. Informational (NOT part of the cache
/// key): it lets the deferred Component-3 burn distinguish ML-only spans from
/// regex/custom ones, and lets determinism tests assert per-source stability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Regex,
    Ml,
    Custom,
    /// A registered secret value matched exact-literal in Pass-0. Highest overlap
    /// priority, and exempt from allow-list suppression (a registered secret is
    /// never silently passed through).
    Secret,
}

/// A raw, operator-free, plaintext-free detection (the cached value element).
#[derive(Clone, Debug)]
pub(crate) struct CachedDetection {
    pub start: usize,
    pub end: usize,
    pub entity_type: String,
    pub score: f32,
    pub source: Source,
    /// True iff this came from a `literal_token` custom rule, whose operator is
    /// always `Token` regardless of per-type overrides. Cached because it is a
    /// STRUCTURAL property of the matched rule, not a policy-rendering choice — so
    /// (unlike the resolved operator) it is safe to memoize.
    pub literal: bool,
    /// The fixed token for a `literal_token` custom rule (else `None`).
    pub fixed_token: Option<String>,
    /// `Some(op)` iff this is a registered-secret detection (Pass-0); the operator
    /// (`Hash`/`Redact`/`Mask`/`Broker`) is resolved at registration and carried
    /// here. Safe to memoize because the secrets fingerprint (`secrets_fp`) is part
    /// of the cache key, so a registration/operator change yields a fresh key space.
    /// For a secret, `entity_type` holds the EXACT registered name (the broker mint /
    /// policy authority). `None` ⇒ ordinary PII/custom (operator resolved live).
    pub secret_op: Option<Operator>,
}

/// Full cache key. `text_hash` is the complete 256-bit blake3 digest of the leaf.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    pub text_hash: [u8; 32],
    pub surface: Surface,
    pub policy_fp: u64,
    pub ml_fp: u64,
    /// Fingerprint of the registered secret set (`secrets::secrets_fingerprint`).
    /// Folded in like `ml_fp` so registering/rotating a secret yields a fresh key
    /// space — stale detections (which lacked the Pass-0 secret spans) age out by
    /// LRU instead of needing a hand-flush.
    pub secrets_fp: u64,
}

/// blake3 of `text` under a cache-specific domain. The full 32-byte digest is
/// returned; the key compares all of it.
pub(crate) fn hash_text(text: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(HASH_TEXT_DOMAIN);
    h.update(text.as_bytes());
    *h.finalize().as_bytes()
}

/// Bounded, in-memory LRU detection cache.
///
/// `lru::LruCache::get` bumps recency, so it needs `&mut self`; a `RwLock` would
/// therefore take a WRITE lock on every hit — and the steady state is all-hits —
/// making "read-mostly" a fiction (audit #9). A plain `Mutex` is simpler and no
/// worse: the critical section is a single hashmap probe + recency splice (sub-µs),
/// orders of magnitude below the detection it gates.
pub(crate) struct DetectionCache {
    inner: Mutex<LruCache<CacheKey, Arc<Vec<CachedDetection>>>>,
    /// Live capacity (entry count). `0` ⇒ disabled (and cleared). This is the
    /// source of truth for enabled/disabled; the inner `LruCache`'s own capacity is
    /// kept ≥ 1 and synced on `set_cap`.
    cap: AtomicUsize,
}

impl DetectionCache {
    pub(crate) fn new(cap: usize) -> Self {
        let initial = NonZeroUsize::new(cap.max(1)).expect("max(1) is nonzero");
        Self {
            inner: Mutex::new(LruCache::new(initial)),
            cap: AtomicUsize::new(cap),
        }
    }

    /// Fetch a cached detection list, refreshing its LRU recency. `None` on a miss
    /// or when disabled (`cap == 0`).
    pub(crate) fn get(&self, k: &CacheKey) -> Option<Arc<Vec<CachedDetection>>> {
        let mut inner = self.inner.lock().expect("detection cache mutex poisoned");
        // Read cap INSIDE the lock; the mutex provides the happens-before vs a
        // concurrent `set_cap` (so Relaxed is sufficient).
        if self.cap.load(Ordering::Relaxed) == 0 {
            return None;
        }
        inner.get(k).cloned()
    }

    /// Insert a SUCCESSFUL detection result (callers never insert detection-error
    /// passthroughs — invariant #2). No-op when disabled. `cap` is re-read INSIDE the
    /// lock so a concurrent `set_cap(0)` (which clears under the same lock) can never
    /// be straddled by a late insert that resurrects an entry (audit #10).
    pub(crate) fn insert(&self, k: CacheKey, v: Arc<Vec<CachedDetection>>) {
        // Bound worst-case memory: a single leaf with an absurd number of spans is
        // not cached (recomputed each turn instead). See `MAX_CACHED_DETECTIONS`.
        if v.len() > MAX_CACHED_DETECTIONS {
            return;
        }
        let mut inner = self.inner.lock().expect("detection cache mutex poisoned");
        let cap = self.cap.load(Ordering::Relaxed);
        if cap == 0 {
            return;
        }
        // Keep the inner capacity in sync with a live `set_cap` (cheap insurance;
        // `set_cap` already resizes under this same lock).
        if inner.cap().get() != cap {
            inner.resize(NonZeroUsize::new(cap).expect("cap != 0 checked above"));
        }
        inner.put(k, v);
    }

    /// Live cap change. `0` clears + disables; `> 0` resizes (LRU-evicting the tail
    /// if shrinking). Both happen under the lock, atomically wrt `get`/`insert`.
    pub(crate) fn set_cap(&self, n: usize) {
        let mut inner = self.inner.lock().expect("detection cache mutex poisoned");
        self.cap.store(n, Ordering::Relaxed);
        match NonZeroUsize::new(n) {
            None => inner.clear(),
            Some(nz) => inner.resize(nz),
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("detection cache mutex poisoned")
            .len()
    }
}
