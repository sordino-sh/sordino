//! zlauder-engine — reversible PII masking for LLM traffic.
//!
//! Detection is delegated to `presidio-rs` (offline regex recognizers); tokens are
//! minted deterministically (blake3, session salt) and stored reversibly
//! (AES-256-GCM, per-session key). The four-arrow [`Surface`] model decides mask
//! vs unmask. This crate is runtime-free (synchronous); the proxy calls it from
//! async handlers.

mod cache;
mod config;
mod detect;
mod error;
mod manifest;
#[cfg(feature = "ml")]
pub mod ml;
mod store;
mod surface;
mod token;

pub use config::{
    AllowList, Category, CustomReplacement, EngineConfig, ExposureRedactionScope, MlConfig,
    Operator, Profile, RevealMarker, SaltScope,
};
pub use error::EngineError;
pub use manifest::{ManifestEntry, MaskOutcome, MaskStats, UnmaskManifest};
pub use surface::{Direction, Surface};
pub use token::{MAX_TOKEN_LEN, TOKEN_HASH_HEX_LEN, make_token, token_regex};

use std::sync::{Arc, Mutex, RwLock};

use cache::{CacheKey, CachedDetection, DetectionCache, hash_text};
use detect::{CompiledCustom, compile_customs, resolve_operator, run_detection};
use store::SessionStore;
use token::hash_value;

/// The masking *policy*: the config, its compiled custom rules, and a precomputed
/// fingerprint of every detection-affecting input. Stored as an immutable
/// `Arc<Policy>` behind an `RwLock` so the proxy can hot-swap it (e.g. a `/privacy`
/// toggle) without dropping the session store — token determinism (and the
/// prompt-cache prefix) survives a config change. `mask()` clones the `Arc` under a
/// brief lock and runs detection/apply against the snapshot, so a slow inference or
/// Ready-rescan never holds the lock and never starves a live `set_config` (audit
/// #2).
#[derive(Clone)]
struct Policy {
    config: EngineConfig,
    customs: Vec<CompiledCustom>,
    /// Fingerprint of all detection-affecting config (see
    /// [`EngineConfig::detection_fingerprint`]); folded into the cache key.
    policy_fp: u64,
}

impl Policy {
    fn new(config: EngineConfig) -> Result<Self, EngineError> {
        let customs = compile_customs(&config.custom_replacements)?;
        let policy_fp = config.detection_fingerprint();
        Ok(Self {
            config,
            customs,
            policy_fp,
        })
    }
}

/// Lifecycle of the optional ML recognizer (`openai/privacy-filter`). The proxy
/// loads the model in the *background*; this is what the status line and
/// `/zlauder:privacy status` report. While `Loading`, masking keeps running
/// regex-only — outbound text is NOT yet filtered through the ML model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlStatus {
    /// Not requested (or turned off live).
    #[default]
    Disabled,
    /// Requested; the model is downloading/loading. Masking is regex-only.
    Loading,
    /// Loaded and active.
    Ready,
    /// A load attempt failed (see the snapshot's error).
    Failed,
}

/// The live ML slot: status + the loaded recognizer, plus a generation counter
/// that makes stale background loads safe to discard.
struct MlRuntime {
    status: MlStatus,
    recognizer: Option<Arc<dyn presidio_core::Recognizer>>,
    error: Option<String>,
    /// Params of the load that is desired / in-flight / loaded, so a reconcile can
    /// tell whether a config change requires rebuilding the recognizer.
    desired: Option<MlConfig>,
    /// Bumped by every [`MaskEngine::ml_begin_load`] / [`MaskEngine::ml_disable`].
    /// A load task captures the generation at begin and only installs its result
    /// if it still matches — so a load that finishes AFTER an off / model-change
    /// can't resurrect a recognizer contrary to current config.
    generation: u64,
    /// Precomputed fingerprint of the ACTIVE ML recognizer identity (present?,
    /// model, revision, min_score), folded into the cache key. Recomputed by every
    /// mutator so it stays consistent with `status`/`recognizer`/`desired`, and read
    /// together with the recognizer under one `ml.read()` (audit #1). When the
    /// recognizer flips `Ready`, this changes → the whole transcript re-detects with
    /// ML coverage (the intended rescan).
    ml_fp: u64,
}

impl Default for MlRuntime {
    fn default() -> Self {
        let mut rt = Self {
            status: MlStatus::Disabled,
            recognizer: None,
            error: None,
            desired: None,
            generation: 0,
            ml_fp: 0,
        };
        rt.ml_fp = compute_ml_fp(&rt);
        rt
    }
}

/// Fingerprint of the active ML recognizer identity. Only a `Ready` recognizer
/// contributes its params; every non-active state shares the single "no ML" key
/// space (so regex-only results computed while `Loading`/`Disabled` are reused
/// across those states and abandoned the instant ML becomes `Ready`).
fn compute_ml_fp(rt: &MlRuntime) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"zlauder-ml-fp-v1");
    if rt.status == MlStatus::Ready && rt.recognizer.is_some() {
        h.update(&[1]);
        if let Some(d) = &rt.desired {
            h.update(d.model.as_bytes());
            h.update(&[0]);
            match &d.revision {
                Some(r) => {
                    h.update(&[1]);
                    h.update(r.as_bytes());
                }
                None => {
                    h.update(&[0]);
                }
            };
            match d.min_score {
                Some(s) => {
                    h.update(&[1]);
                    h.update(&s.to_bits().to_le_bytes());
                }
                None => {
                    h.update(&[0]);
                }
            };
            // `prefer_gpu` is a recognizer-identity param: `MlConfig::same_model_params`
            // (the single source of truth for "this is a DIFFERENT recognizer") includes
            // it, so a `prefer_gpu` flip rebuilds the recognizer — `ml_fp` MUST move with
            // it or a byte-identical leaf would be served stale cross-backend detections
            // (inert today since the GPU backends aren't compiled in, but the fingerprint
            // must stay complete). Keep this set in sync with `same_model_params`.
            h.update(&[d.prefer_gpu as u8]);
        }
    } else {
        h.update(&[0]);
    }
    u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().expect("32-byte digest"))
}

/// Public snapshot of the ML slot for status reporting.
#[derive(Clone, Debug)]
pub struct MlSnapshot {
    pub status: MlStatus,
    pub error: Option<String>,
    /// The model params currently desired/loaded (`None` when disabled).
    pub desired: Option<MlConfig>,
}

/// The masking engine. Cheap to share behind an `Arc`; interior mutability via an
/// `RwLock` on the hot-swappable policy, an `RwLock` on the hot-swappable ML
/// recognizer slot, and a `Mutex` on the session store. The regex analyzer is
/// fixed at construction (a `language` change needs a rebuild); the ML recognizer
/// is loaded/dropped live.
pub struct MaskEngine {
    analyzer: presidio_analyzer::AnalyzerEngine,
    policy: RwLock<Arc<Policy>>,
    ml: RwLock<MlRuntime>,
    store: Mutex<SessionStore>,
    /// Content-addressed detection memoization (Component 1).
    cache: DetectionCache,
    /// Serializes ML inference per leaf (default max-inflight 1): CPU
    /// token-classification already saturates the cores, so concurrent inferences
    /// just thrash. A `std::sync::Mutex` because ML inference ONLY ever runs inside
    /// a `spawn_blocking` thread (the proxy guarantees it — invariant #5), so the
    /// synchronous acquire never blocks the async executor; it serializes
    /// blocking-pool threads, which is exactly the intent. Acquired per-inference
    /// (not per-walk) so a Ready-rescan can't freeze a second window (Component 2).
    ml_gate: Mutex<()>,
}

impl MaskEngine {
    /// Build the analyzer (offline regex recognizers) and a fresh random session.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        Self::from_parts(config, SessionStore::new)
    }

    /// Build with an explicit session key + salt (proxy passes the SessionStart
    /// session bytes so token minting is stable for the whole session).
    pub fn with_session(
        config: EngineConfig,
        key: [u8; 32],
        salt: [u8; 16],
    ) -> Result<Self, EngineError> {
        Self::from_parts(config, move || SessionStore::with_key_and_salt(key, salt))
    }

    /// Build reusing only a `salt` (token determinism across a proxy restart) with
    /// a FRESH random encryption key. The proxy uses this so the on-disk state file
    /// never holds the AES key — the control token (see [`Self::control_token`]) is
    /// what gates the control plane, decoupling control access from decryption.
    pub fn with_salt(config: EngineConfig, salt: [u8; 16]) -> Result<Self, EngineError> {
        Self::from_parts(config, move || SessionStore::with_salt(salt))
    }

    /// Shared constructor: build the analyzer + policy + detection cache, deferring
    /// the (differently-seeded) session store to `make_store`.
    fn from_parts(
        config: EngineConfig,
        make_store: impl FnOnce() -> SessionStore,
    ) -> Result<Self, EngineError> {
        let analyzer = presidio_analyzer::default_analyzer(&config.language);
        let cache_cap = config.detection_cache_cap;
        let policy = Policy::new(config)?;
        Ok(Self {
            analyzer,
            policy: RwLock::new(Arc::new(policy)),
            ml: RwLock::new(MlRuntime::default()),
            store: Mutex::new(make_store()),
            cache: DetectionCache::new(cache_cap),
            ml_gate: Mutex::new(()),
        })
    }

    /// A control token derived from — but not revealing — the session key, used as
    /// the `x-zlauder-key` for the control/reveal plane. It is `blake3` of the key
    /// under a distinct domain, so leaking it (e.g. via the state file) grants
    /// control-plane access but NOT offline decryption of the transcript.
    pub fn control_token(&self) -> String {
        let store = self.store.lock().expect("store mutex poisoned");
        let mut h = blake3::Hasher::new();
        h.update(b"zlauder-control-token-v1");
        h.update(store.key());
        h.finalize().to_hex().to_string()
    }

    /// A clone of the current effective config (snapshot; not a live view).
    pub fn config_snapshot(&self) -> EngineConfig {
        self.policy
            .read()
            .expect("policy rwlock poisoned")
            .config
            .clone()
    }

    /// Whether masking is currently on (the config `enabled` master switch).
    pub fn is_enabled(&self) -> bool {
        self.policy
            .read()
            .expect("policy rwlock poisoned")
            .config
            .enabled
    }

    /// Flip the master switch live. `enabled` is NOT part of `policy_fp` (the
    /// disabled path is an un-cached early return), so the cache survives the toggle
    /// and determinism holds. Cheap: clones the small policy to swap one bool.
    pub fn set_enabled(&self, enabled: bool) {
        let mut slot = self.policy.write().expect("policy rwlock poisoned");
        if slot.config.enabled == enabled {
            return;
        }
        let mut next = (**slot).clone();
        next.config.enabled = enabled;
        *slot = Arc::new(next);
    }

    /// Hot-swap the whole policy. Recompiles custom rules and recomputes
    /// `policy_fp`; the session store (key/salt/minted tokens) is untouched, so
    /// already-minted tokens keep resolving and determinism is preserved across the
    /// swap. The detection cache is NOT flushed — any detection-affecting change
    /// moves `policy_fp`, so stale entries become unreachable and age out via LRU
    /// (fingerprint invalidation, not a flush). The cache cap is applied live. A
    /// change to `config.language` does NOT rebuild the analyzer — that needs a
    /// restart.
    pub fn set_config(&self, config: EngineConfig) -> Result<(), EngineError> {
        let cache_cap = config.detection_cache_cap;
        let policy = Policy::new(config)?;
        {
            let mut slot = self.policy.write().expect("policy rwlock poisoned");
            *slot = Arc::new(policy);
        }
        // Live cap (audit #10): `0` clears + disables the cache without a restart.
        self.cache.set_cap(cache_cap);
        Ok(())
    }

    /// Number of distinct tokens minted so far this session.
    pub fn token_count(&self) -> usize {
        self.store.lock().expect("store mutex poisoned").len()
    }

    // --- ML recognizer slot (hot-loaded in the background by the proxy) -------

    /// Begin (or restart) a background load for `desired`. Bumps the generation
    /// (invalidating any in-flight load), sets [`MlStatus::Loading`], and returns
    /// the new generation token the caller passes back to [`Self::ml_set_ready`] /
    /// [`Self::ml_set_failed`].
    pub fn ml_begin_load(&self, desired: MlConfig) -> u64 {
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        ml.generation += 1;
        ml.status = MlStatus::Loading;
        ml.recognizer = None;
        ml.error = None;
        ml.desired = Some(desired);
        ml.ml_fp = compute_ml_fp(&ml);
        ml.generation
    }

    /// Install a freshly-loaded recognizer — but ONLY if `generation` is still
    /// current (else the load was superseded by an off / model-change and is
    /// dropped).
    pub fn ml_set_ready(&self, generation: u64, recognizer: Arc<dyn presidio_core::Recognizer>) {
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        if ml.generation != generation {
            return;
        }
        ml.status = MlStatus::Ready;
        ml.recognizer = Some(recognizer);
        ml.error = None;
        ml.ml_fp = compute_ml_fp(&ml);
    }

    /// Record a failed load — ONLY if `generation` is still current.
    pub fn ml_set_failed(&self, generation: u64, error: String) {
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        if ml.generation != generation {
            return;
        }
        ml.status = MlStatus::Failed;
        ml.recognizer = None;
        ml.error = Some(error);
        ml.ml_fp = compute_ml_fp(&ml);
    }

    /// Turn ML off live: invalidate any in-flight load (bump generation) and drop
    /// the recognizer, so it stops affecting detection immediately.
    pub fn ml_disable(&self) {
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        ml.generation += 1;
        ml.status = MlStatus::Disabled;
        ml.recognizer = None;
        ml.error = None;
        ml.desired = None;
        ml.ml_fp = compute_ml_fp(&ml);
    }

    /// Snapshot the ML slot (status + last error + desired params) for reporting.
    pub fn ml_snapshot(&self) -> MlSnapshot {
        let ml = self.ml.read().expect("ml rwlock poisoned");
        MlSnapshot {
            status: ml.status,
            error: ml.error.clone(),
            desired: ml.desired.clone(),
        }
    }

    /// Whether ML inference is currently live (model `Ready`). Cheap.
    pub fn ml_active(&self) -> bool {
        self.ml.read().expect("ml rwlock poisoned").status == MlStatus::Ready
    }

    /// Whether the proxy should offload the mask walk to a blocking thread: true
    /// when a model is `Ready` OR `Loading`. Offloading while `Loading` is now cheap
    /// (no inference runs yet, so the per-inference `ml_gate` is never taken) and it
    /// CLOSES the `Loading -> Ready` race where inference could otherwise flip live
    /// mid-walk and run inline on the async executor thread (which would also acquire
    /// the std `ml_gate` off a blocking thread). The only residual inline edge is the
    /// rarer, user-initiated `Disabled -> Loading` flip, bounded to one request.
    pub fn ml_should_offload(&self) -> bool {
        matches!(
            self.ml.read().expect("ml rwlock poisoned").status,
            MlStatus::Loading | MlStatus::Ready
        )
    }

    /// The active recognizer (if `Ready`) together with the matching `ml_fp`, read
    /// under ONE `ml.read()` so the recognizer and the fingerprint keying its
    /// results can never tear across an ML transition (audit #1).
    fn ml_snapshot_with_fp(&self) -> (Option<Arc<dyn presidio_core::Recognizer>>, u64) {
        let ml = self.ml.read().expect("ml rwlock poisoned");
        let rec = if ml.status == MlStatus::Ready {
            ml.recognizer.clone()
        } else {
            None
        };
        (rec, ml.ml_fp)
    }

    /// Mask `text` (request path). Detect -> filter -> mint tokens -> splice.
    ///
    /// `surface` is a policy/audit label, not a direction gate: under
    /// unmask-on-the-wire the proxy masks every outbound field (including
    /// assistant-authored history, which the local transcript stores as
    /// plaintext) and unmasks every inbound field. Determinism makes the
    /// round-trip reproduce the original token form exactly.
    pub fn mask(&self, text: &str, surface: Surface) -> Result<MaskOutcome, EngineError> {
        // Snapshot the policy as a cheap `Arc` clone, then RELEASE the lock before
        // any detection/inference/apply work (audit #2): a slow miss or Ready-rescan
        // must never hold a read lock that could starve a live `set_config` write.
        let policy = Arc::clone(&self.policy.read().expect("policy rwlock poisoned"));

        // Master switch off, or this surface disabled by policy → transparent
        // passthrough on the mask path (unmask still runs on the response side). This
        // early return is NOT cached (so `enabled`/`disabled_surfaces` need not be in
        // `policy_fp`).
        if !policy.config.enabled || !policy.config.surface_enabled(surface) {
            return Ok(MaskOutcome::passthrough(text, MaskStats::disabled()));
        }

        // Peel a prior turn's reveal-marker decoration off re-sent assistant history
        // BEFORE anything else (detection, hashing, splicing). Claude Code stores the
        // un-masked (and, with the marker on, wrapped) reply in the transcript and
        // re-sends it as `AssistantText`; stripping the exact marker literals here
        // makes detection see the original value (no marker byte fused to the PII) and
        // makes the re-minted token byte-identical to a no-marker round-trip — so the
        // decoration adds zero noise upstream and keeps the prompt-cache prefix stable.
        // Cheap-guarded so a marker-free leaf never allocates; keyed on the cleaned
        // text below, so a marker change can't serve a stale entry.
        let stripped;
        let text: &str = if surface == Surface::AssistantText
            && policy.config.reveal_marker.is_active()
            && policy.config.reveal_marker.contained_in(text)
        {
            stripped = policy.config.reveal_marker.strip(text);
            &stripped
        } else {
            text
        };

        // Snapshot the ML recognizer + its fingerprint together (atomic across an ML
        // transition). `None` while loading/disabled ⇒ regex-only key space.
        let (ml, ml_fp) = self.ml_snapshot_with_fp();
        let key = CacheKey {
            text_hash: hash_text(text),
            surface,
            policy_fp: policy.policy_fp,
            ml_fp,
        };

        let mut stats = MaskStats {
            leaves: 1,
            ..Default::default()
        };

        // Resolve the detection list: cache hit, or a miss that runs detection.
        let dets: Arc<Vec<CachedDetection>> = match self.cache.get(&key) {
            Some(hit) => {
                stats.hit = 1;
                hit
            }
            None if ml.is_some() => {
                // ML miss: serialize inference through the engine gate (held only on
                // a `spawn_blocking` thread per invariant #5), and RE-CHECK the cache
                // under it so concurrent same-leaf misses single-flight (audit #6).
                // The gate guards a unit `()` (pure serialization, no protected data),
                // so we RECOVER a poisoned guard rather than propagate: a panic inside
                // a single ML inference must not permanently wedge all future masking.
                let _gate = self
                    .ml_gate
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match self.cache.get(&key) {
                    Some(hit) => {
                        stats.hit = 1;
                        hit
                    }
                    None => self.detect_and_cache(&policy, ml.as_deref(), text, surface, key, &mut stats)?,
                }
            }
            None => self.detect_and_cache(&policy, None, text, surface, key, &mut stats)?,
        };

        // Apply loop — runs EVERY call (hit or miss): resolve operators from the LIVE
        // policy snapshot, slice plaintext from the LIVE text, mint/redact, and
        // rebuild the per-call manifest. The replay is REQUIRED, not just for stats:
        // custom literal tokens unmask only via this manifest, so the masked string
        // cannot itself be cached.
        let mut manifest = UnmaskManifest::new();
        let mut out = text.to_string();
        // Splice back-to-front so original byte offsets stay valid.
        for d in dets.iter().rev() {
            // Detector offsets are char-aligned in practice (regex over `&str`), but
            // if one ever isn't, `&text[start..end]` would panic and poison the store
            // mutex — wedging the proxy while /healthz still says "ok". Snap OUTWARD
            // to char boundaries instead: we still mask the span (fail SAFE — never
            // panic, and never leave it as plaintext, which skipping the span would).
            let (start, end) = snap_to_char_boundary(text, d.start, d.end);
            let slice = &text[start..end];
            let replacement = match resolve_operator(&policy.config, d) {
                Operator::Keep => continue,
                Operator::Redact => "[REDACTED]".to_string(),
                Operator::Mask { char, from_end } => mask_value(slice, char, from_end),
                Operator::Hash => hash_value(&d.entity_type, slice),
                Operator::Token => {
                    let token = {
                        let mut store = self.store.lock().expect("store mutex poisoned");
                        if let Some(fixed) = &d.fixed_token {
                            store.intern_fixed(fixed.clone(), slice)?;
                            fixed.clone()
                        } else {
                            store.intern(&d.entity_type, slice)?
                        }
                    };
                    manifest.push(ManifestEntry {
                        canonical_form: slice.to_string(),
                        token_handle: token.clone(),
                        entity_kind: d.entity_type.clone(),
                        arrow_origin: surface,
                        exposed_at: None,
                    });
                    token
                }
            };
            out.replace_range(start..end, &replacement);
        }

        Ok(MaskOutcome {
            masked_text: out,
            manifest,
            stats,
        })
    }

    /// Run detection for a cache miss and (on success) populate the cache. A
    /// detection error is NEVER cached (invariant #2): under `fail_closed` it
    /// propagates (the proxy refuses the request); otherwise it is a fail-OPEN
    /// passthrough (empty detection list, `fail_open` counted) that is recomputed
    /// next turn rather than freezing a wrong "clean" result.
    fn detect_and_cache(
        &self,
        policy: &Policy,
        ml: Option<&dyn presidio_core::Recognizer>,
        text: &str,
        surface: Surface,
        key: CacheKey,
        stats: &mut MaskStats,
    ) -> Result<Arc<Vec<CachedDetection>>, EngineError> {
        if ml.is_some() {
            stats.ml_ran = 1;
        }
        match run_detection(&self.analyzer, &policy.config, &policy.customs, ml, text, surface) {
            Ok(d) => {
                stats.fresh_miss = 1;
                let d = Arc::new(d);
                self.cache.insert(key, Arc::clone(&d));
                Ok(d)
            }
            Err(e) => {
                if policy.config.fail_closed {
                    return Err(e);
                }
                tracing::warn!("detection failed, passing text through unmasked: {e}");
                stats.fail_open = 1;
                Ok(Arc::new(Vec::new()))
            }
        }
    }

    /// Unmask an UNMASK-direction surface (Arrow 2 / Arrow 3). Replaces every known
    /// token with its plaintext (manifest first, then session-store fallback for
    /// tokens minted in earlier turns). Never re-masks; unknown tokens are left
    /// verbatim.
    pub fn unmask(&self, text: &str, manifest: &UnmaskManifest) -> Result<String, EngineError> {
        self.unmask_inner(text, manifest, None)
    }

    /// Unmask assistant prose (Arrow 2 → display) and, when the live config's
    /// [`RevealMarker`] is active, wrap each value we actually un-masked with the
    /// marker so the operator can see which spans were restored. ONLY for
    /// `Surface::AssistantText` — tool inputs / results / citations / compaction
    /// must use [`Self::unmask`] so their bytes stay exact. A value left verbatim
    /// (unknown token) is never wrapped.
    pub fn unmask_assistant(
        &self,
        text: &str,
        manifest: &UnmaskManifest,
    ) -> Result<String, EngineError> {
        let policy = Arc::clone(&self.policy.read().expect("policy rwlock poisoned"));
        let marker = &policy.config.reveal_marker;
        self.unmask_inner(text, manifest, marker.is_active().then_some(marker))
    }

    /// Shared unmask body. With `marker = Some`, each successfully-resolved value is
    /// wrapped for display; unknown tokens pass through untouched (so nothing fake is
    /// ever decorated).
    fn unmask_inner(
        &self,
        text: &str,
        manifest: &UnmaskManifest,
        marker: Option<&RevealMarker>,
    ) -> Result<String, EngineError> {
        let store = self.store.lock().expect("store mutex poisoned");
        let re = token_regex();
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in re.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            let tok = m.as_str();
            // Resolve to plaintext (manifest first, then the cross-turn store); only a
            // genuine resolution is wrapped — an unknown token stays verbatim.
            let plain = manifest
                .lookup(tok)
                .map(str::to_string)
                .or_else(|| store.reveal(tok));
            match (plain, marker) {
                (Some(p), Some(mk)) => out.push_str(&mk.wrap(&p)),
                (Some(p), None) => out.push_str(&p),
                (None, _) => out.push_str(tok),
            }
            last = m.end();
        }
        out.push_str(&text[last..]);
        drop(store);

        // Custom literal tokens that don't match the standard token grammar.
        for e in &manifest.entries {
            if !re.is_match(&e.token_handle) {
                let replacement = match marker {
                    Some(mk) => mk.wrap(&e.canonical_form),
                    None => e.canonical_form.clone(),
                };
                out = out.replace(&e.token_handle, &replacement);
            }
        }
        Ok(out)
    }

    /// Reveal a single token to its plaintext (audit). `None` if unknown.
    pub fn reveal(&self, token: &str) -> Option<String> {
        self.store
            .lock()
            .expect("store mutex poisoned")
            .reveal(token)
    }

    /// Export the session key + salt so a sibling process can decrypt for audit.
    pub fn session_handle(&self) -> ([u8; 32], [u8; 16]) {
        let store = self.store.lock().expect("store mutex poisoned");
        (*store.key(), *store.salt())
    }
}

/// Widen `[start, end)` outward to the nearest UTF-8 char boundaries (and clamp to
/// `text.len()`), so slicing/splicing can never panic on a stray non-boundary
/// detector offset. A no-op for the normal (already-aligned) case.
fn snap_to_char_boundary(text: &str, start: usize, end: usize) -> (usize, usize) {
    let mut start = start.min(text.len());
    let mut end = end.min(text.len()).max(start);
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    (start, end)
}

/// `Mask` operator: keep the last `from_end` chars, replace the rest with `ch`.
fn mask_value(slice: &str, ch: char, from_end: usize) -> String {
    let chars: Vec<char> = slice.chars().collect();
    let n = chars.len();
    let keep = from_end.min(n);
    let mut s = String::with_capacity(slice.len());
    for _ in 0..(n - keep) {
        s.push(ch);
    }
    for c in &chars[n - keep..] {
        s.push(*c);
    }
    s
}

// Engine must be shareable across async tasks in the proxy.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MaskEngine>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> MaskEngine {
        MaskEngine::new(EngineConfig::default()).unwrap()
    }

    // T1 — mask -> unmask round-trip.
    #[test]
    fn round_trip_email() {
        let e = engine();
        let original = "contact me at alice@example.com please";
        let outcome = e.mask(original, Surface::UserMessage).unwrap();
        assert!(!outcome.masked_text.contains("alice@example.com"));
        assert!(outcome.masked_text.contains("[EMAIL_ADDRESS_"));
        let back = e.unmask(&outcome.masked_text, &outcome.manifest).unwrap();
        assert_eq!(back, original);
    }

    // T2 — determinism / cache stability.
    #[test]
    fn determinism_same_engine() {
        let e = engine();
        let a = e
            .mask("write to carol@example.com", Surface::UserMessage)
            .unwrap();
        let b = e
            .mask("write to carol@example.com", Surface::ToolResult)
            .unwrap();
        assert!(
            a.masked_text.contains("[EMAIL_ADDRESS_"),
            "got: {}",
            a.masked_text
        );
        assert_eq!(
            a.masked_text, b.masked_text,
            "same plaintext => identical token"
        );
    }

    #[test]
    fn determinism_shared_salt_vs_isolation() {
        let key = [7u8; 32];
        let salt = [9u8; 16];
        let e1 = MaskEngine::with_session(EngineConfig::default(), key, salt).unwrap();
        let e2 = MaskEngine::with_session(EngineConfig::default(), key, salt).unwrap();
        let t1 = e1.mask("alice@example.com", Surface::UserMessage).unwrap();
        let t2 = e2.mask("alice@example.com", Surface::UserMessage).unwrap();
        assert_eq!(
            t1.masked_text, t2.masked_text,
            "same (key,salt) => same token"
        );

        let e3 = MaskEngine::with_session(EngineConfig::default(), key, [1u8; 16]).unwrap();
        let t3 = e3.mask("alice@example.com", Surface::UserMessage).unwrap();
        assert_ne!(
            t1.masked_text, t3.masked_text,
            "different salt => different token"
        );
    }

    // T3 — reveal.
    #[test]
    fn reveal_token() {
        let e = engine();
        let outcome = e.mask("alice@example.com", Surface::UserMessage).unwrap();
        let token = outcome.manifest.entries[0].token_handle.clone();
        assert_eq!(e.reveal(&token).as_deref(), Some("alice@example.com"));
        assert_eq!(e.reveal("[EMAIL_ADDRESS_deadbeef0000]"), None);
    }

    // T4 — operator coverage.
    #[test]
    fn operators() {
        let mut cfg = EngineConfig::default();
        cfg.entity_operators.insert(
            "CREDIT_CARD".into(),
            Operator::Mask {
                char: '*',
                from_end: 4,
            },
        );
        cfg.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Redact);
        let e = MaskEngine::new(cfg).unwrap();

        let out = e
            .mask("card 4111111111111111 here", Surface::UserMessage)
            .unwrap();
        assert!(out.masked_text.contains("************1111"));
        assert!(out.manifest.is_empty(), "Mask produces no reversible entry");

        let out2 = e
            .mask("mail bob@example.com", Surface::UserMessage)
            .unwrap();
        assert!(out2.masked_text.contains("[REDACTED]"));
        assert!(!out2.masked_text.contains("bob@example.com"));
        // Unmasking redacted text is a no-op.
        let back = e.unmask(&out2.masked_text, &out2.manifest).unwrap();
        assert_eq!(back, out2.masked_text);
    }

    // T5 — allow-list + custom rules.
    #[test]
    fn allow_list_and_custom() {
        let mut cfg = EngineConfig::default();
        cfg.allow_list.add_exact("admin@example.com");
        cfg.custom_replacements.push(CustomReplacement {
            pattern: "ACME-CODENAME".into(),
            entity_type: "CODENAME".into(),
            is_regex: false,
            case_sensitive: true,
            priority: 0,
            literal_token: true,
            token: Some("[CODENAME_acme]".into()),
            apply_to_surfaces: None,
        });
        let e = MaskEngine::new(cfg).unwrap();

        let out = e
            .mask(
                "ping admin@example.com about ACME-CODENAME",
                Surface::UserMessage,
            )
            .unwrap();
        assert!(
            out.masked_text.contains("admin@example.com"),
            "allow-listed not masked"
        );
        assert!(out.masked_text.contains("[CODENAME_acme]"));
        let back = e.unmask(&out.masked_text, &out.manifest).unwrap();
        assert_eq!(back, "ping admin@example.com about ACME-CODENAME");
    }

    // presidio's strict UrlRecognizer (default) drops scheme-less filenames/code
    // (`CLAUDE.md`, `opts.la`) while still masking real URLs.
    #[test]
    fn strict_url_skips_filenames_keeps_real_urls() {
        let e = engine();
        let text = "edit CLAUDE.md and opts.la then open https://corp.example.com/secret and mail bob@example.com";
        let out = e.mask(text, Surface::UserMessage).unwrap();
        assert!(
            out.masked_text.contains("CLAUDE.md"),
            "filename masked: {}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("opts.la"),
            "code ident masked: {}",
            out.masked_text
        );
        assert!(
            !out.masked_text.contains("https://corp.example.com/secret"),
            "real URL not masked: {}",
            out.masked_text
        );
        assert!(!out.masked_text.contains("bob@example.com"));
        assert!(out.masked_text.contains("[URL_"));
        assert!(out.masked_text.contains("[EMAIL_ADDRESS_"));
    }

    // The control token is derived from the key (stable for a key) but is NOT the
    // key itself, so the state file it lands in carries no decryption material.
    #[test]
    fn control_token_is_decoupled_from_key() {
        let key = [7u8; 32];
        let salt = [9u8; 16];
        let e = MaskEngine::with_session(EngineConfig::default(), key, salt).unwrap();
        let tok = e.control_token();
        assert_eq!(tok.len(), 64, "blake3 → 64 hex");
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_ne!(tok, key_hex, "control token must not be the AES key");
        assert_eq!(tok, e.control_token(), "stable for the same key");

        // `with_salt` mints a fresh random key each time → distinct control tokens,
        // confirming the key (not just the token) is fresh and unpersisted.
        let a = MaskEngine::with_salt(EngineConfig::default(), salt).unwrap();
        let b = MaskEngine::with_salt(EngineConfig::default(), salt).unwrap();
        assert_ne!(a.control_token(), b.control_token());
    }

    #[test]
    fn snap_widens_off_boundary_spans() {
        let s = "héllo"; // 'é' occupies bytes 1..3
        assert_eq!(
            snap_to_char_boundary(s, 2, 2),
            (1, 3),
            "mid-char snaps outward"
        );
        assert_eq!(
            snap_to_char_boundary("hello", 1, 3),
            (1, 3),
            "aligned is unchanged"
        );
        let n = s.len();
        assert_eq!(
            snap_to_char_boundary(s, n + 5, n + 9),
            (n, n),
            "clamps past end"
        );
    }

    // Multibyte text around the match must not panic and must round-trip exactly
    // (the snap guard is a no-op here since presidio offsets are char-aligned).
    #[test]
    fn mask_round_trips_with_multibyte_text() {
        let e = engine();
        let original = "café 🎉 mail bob@example.com please";
        let out = e.mask(original, Surface::UserMessage).unwrap();
        assert!(!out.masked_text.contains("bob@example.com"));
        assert!(out.masked_text.contains("café") && out.masked_text.contains('🎉'));
        assert_eq!(e.unmask(&out.masked_text, &out.manifest).unwrap(), original);
    }

    // Master switch off ⇒ mask path is a transparent passthrough, but already
    // minted tokens still unmask on the response path.
    #[test]
    fn disabled_passes_through_but_still_unmasks() {
        let e = engine();
        // Mint a token while enabled.
        let on = e
            .mask("ping alice@example.com", Surface::UserMessage)
            .unwrap();
        let token = on.manifest.entries[0].token_handle.clone();

        // Now disable: a fresh outbound field is NOT masked.
        e.set_enabled(false);
        assert!(!e.is_enabled());
        let off = e
            .mask("ping bob@example.com", Surface::UserMessage)
            .unwrap();
        assert_eq!(
            off.masked_text, "ping bob@example.com",
            "should pass through verbatim"
        );
        assert!(off.manifest.is_empty());

        // ...yet the earlier token still decodes (unmask is not gated).
        let restored = e
            .unmask(&format!("reply to {token}"), &on.manifest)
            .unwrap();
        assert_eq!(restored, "reply to alice@example.com");

        // Re-enable and masking resumes, deterministically (same token as before).
        e.set_enabled(true);
        let again = e
            .mask("ping alice@example.com", Surface::UserMessage)
            .unwrap();
        assert_eq!(
            again.masked_text, on.masked_text,
            "determinism survives the toggle"
        );
    }

    // Live policy swap takes effect immediately and keeps the store (determinism).
    #[test]
    fn set_config_swaps_policy_live() {
        let e = engine();
        let before = e
            .mask("card 4111111111111111", Surface::UserMessage)
            .unwrap();
        assert!(
            before.masked_text.contains("[CREDIT_CARD_"),
            "default tokenizes CC"
        );

        // Swap to a config that masks CC with stars instead of a token.
        let mut cfg = e.config_snapshot();
        cfg.entity_operators.insert(
            "CREDIT_CARD".into(),
            Operator::Mask {
                char: '*',
                from_end: 4,
            },
        );
        e.set_config(cfg).unwrap();

        let after = e
            .mask("card 4111111111111111", Surface::UserMessage)
            .unwrap();
        assert!(
            after.masked_text.contains("************1111"),
            "got: {}",
            after.masked_text
        );
    }

    // ----- ML recognizer wiring (driven via the public slot API; no model) -----

    use presidio_core::{EntityType, NlpArtifacts, Recognizer, RecognizerResult};

    /// A stand-in `Recognizer` that flags a fixed name as a `PERSON` — lets us
    /// exercise the ML detection path without loading a real model.
    struct MockPerson {
        entities: Vec<EntityType>,
        name: &'static str,
    }
    impl MockPerson {
        fn new(name: &'static str) -> Self {
            Self {
                entities: vec!["PERSON".parse().unwrap()],
                name,
            }
        }
    }
    impl Recognizer for MockPerson {
        fn name(&self) -> &str {
            "mock-person"
        }
        fn supported_entities(&self) -> &[EntityType] {
            &self.entities
        }
        fn supported_languages(&self) -> &[&str] {
            &["en"]
        }
        fn analyze(
            &self,
            text: &str,
            _e: Option<&[EntityType]>,
            _n: Option<&NlpArtifacts>,
        ) -> Vec<RecognizerResult> {
            match text.find(self.name) {
                Some(pos) => vec![
                    RecognizerResult::new(
                        "PERSON".parse().unwrap(),
                        pos,
                        pos + self.name.len(),
                        0.99,
                    )
                    .with_recognizer("mock-person"),
                ],
                None => Vec::new(),
            }
        }
    }

    fn engine_personal_on() -> MaskEngine {
        let mut cfg = EngineConfig::default();
        cfg.enabled_categories.insert(Category::Personal);
        MaskEngine::new(cfg).unwrap()
    }

    // A Ready recognizer masks its entity (when the category is on) and round-trips;
    // disabling it live makes the same text pass through unmasked.
    #[test]
    fn ml_recognizer_masks_when_ready_then_off() {
        let e = engine_personal_on();
        let generation = e.ml_begin_load(MlConfig {
            enabled: true,
            ..Default::default()
        });
        e.ml_set_ready(generation, Arc::new(MockPerson::new("Alice Johnson")));
        assert!(e.ml_active());

        let original = "please call Alice Johnson today";
        let out = e.mask(original, Surface::UserMessage).unwrap();
        assert!(
            out.masked_text.contains("[PERSON_"),
            "ml PERSON not masked: {}",
            out.masked_text
        );
        assert!(!out.masked_text.contains("Alice Johnson"));
        assert_eq!(e.unmask(&out.masked_text, &out.manifest).unwrap(), original);

        // Live off: recognizer dropped, name flows through.
        e.ml_disable();
        assert!(!e.ml_active());
        let off = e.mask(original, Surface::UserMessage).unwrap();
        assert!(
            off.masked_text.contains("Alice Johnson"),
            "ml off should not mask: {}",
            off.masked_text
        );
    }

    // Loading state (not Ready) ⇒ recognizer is NOT consulted yet (regex-only).
    #[test]
    fn ml_loading_does_not_mask_yet() {
        let e = engine_personal_on();
        e.ml_begin_load(MlConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(!e.ml_active(), "Loading is not active");
        let out = e.mask("call Alice Johnson", Surface::UserMessage).unwrap();
        assert!(
            out.masked_text.contains("Alice Johnson"),
            "must be regex-only while loading: {}",
            out.masked_text
        );
    }

    // Generation guard: a load that completes AFTER an off / model change must not
    // resurrect a recognizer (the critical race from the adversarial review).
    #[test]
    fn ml_stale_load_completion_is_discarded() {
        let e = engine_personal_on();
        let stale_gen = e.ml_begin_load(MlConfig {
            enabled: true,
            ..Default::default()
        });
        // User turns it off (or changes the model) while the first load is in flight.
        e.ml_disable();
        // The stale load now finishes and tries to install its recognizer.
        e.ml_set_ready(stale_gen, Arc::new(MockPerson::new("Alice Johnson")));
        assert!(
            !e.ml_active(),
            "stale load must not become active after disable"
        );
        let out = e.mask("call Alice Johnson", Surface::UserMessage).unwrap();
        assert!(out.masked_text.contains("Alice Johnson"), "stale load leaked");
    }

    // DATE_TIME (the ML model's `private_date`) is intentionally unmapped to any
    // category — dates are noisy — so it's dropped by default but opt-in via an
    // explicit per-type operator. Lock that decision (review follow-up).
    #[test]
    fn date_time_unmapped_by_default_but_opt_in() {
        let cfg = EngineConfig::default();
        assert!(
            !cfg.entity_enabled("DATE_TIME"),
            "DATE_TIME must be off by default"
        );
        for c in [
            Category::Secrets,
            Category::Financial,
            Category::Identity,
            Category::Contact,
            Category::Personal,
        ] {
            assert!(
                !c.entity_types().contains(&"DATE_TIME"),
                "{c:?} unexpectedly lists DATE_TIME"
            );
        }
        // Opt-in escape hatch: an explicit per-type operator enables it.
        let mut cfg = EngineConfig::default();
        cfg.entity_operators
            .insert("DATE_TIME".into(), Operator::Token);
        assert!(
            cfg.entity_enabled("DATE_TIME"),
            "an entity_operator should enable DATE_TIME"
        );
    }

    // Lock the ML status wire strings — the status line and the hooks CLI match on
    // exactly these (a rename here would silently break the indicator).
    #[test]
    fn ml_status_serializes_to_stable_strings() {
        use serde_json::json;
        assert_eq!(serde_json::to_value(MlStatus::Disabled).unwrap(), json!("disabled"));
        assert_eq!(serde_json::to_value(MlStatus::Loading).unwrap(), json!("loading"));
        assert_eq!(serde_json::to_value(MlStatus::Ready).unwrap(), json!("ready"));
        assert_eq!(serde_json::to_value(MlStatus::Failed).unwrap(), json!("failed"));
    }

    // Lock the catalog mapping target strings: the ML model maps its labels to
    // `EntityType`s whose `Display` MUST equal the category entity strings, else ML
    // detections would be silently dropped by the category gate.
    #[test]
    fn entity_type_display_matches_category_strings() {
        for (parsed, expected, cat) in [
            ("PERSON", "PERSON", Category::Personal),
            ("LOCATION", "LOCATION", Category::Personal),
            ("EMAIL_ADDRESS", "EMAIL_ADDRESS", Category::Contact),
            ("PHONE_NUMBER", "PHONE_NUMBER", Category::Contact),
            ("US_BANK_ACCOUNT", "US_BANK_NUMBER", Category::Financial),
            ("API_KEY", "API_KEY", Category::Secrets),
            // Regression guard for the alias-vs-Display silent-drop bug: each LHS is a
            // parse alias; the category must list the canonical Display (RHS).
            ("IBAN", "IBAN_CODE", Category::Financial),
            ("CRYPTO_WALLET", "CRYPTO", Category::Financial),
            ("US_ROUTING_NUMBER", "ABA_ROUTING_NUMBER", Category::Financial),
            ("US_MEDICAL_LICENSE", "MEDICAL_LICENSE", Category::Identity),
        ] {
            let et: EntityType = parsed.parse().unwrap();
            assert_eq!(et.to_string(), expected, "Display drift for {parsed}");
            assert!(
                cat.entity_types().contains(&expected),
                "{expected} missing from its category"
            );
        }
    }

    // ----- Reveal marker (display-time decoration of un-masked assistant text) ---

    fn engine_with_marker(prefix: &str, suffix: &str) -> MaskEngine {
        let mut cfg = EngineConfig::default();
        cfg.reveal_marker = RevealMarker {
            enabled: true,
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
        };
        MaskEngine::new(cfg).unwrap()
    }

    // `unmask_assistant` wraps every value it RESOLVES; plain `unmask` never does.
    #[test]
    fn reveal_marker_wraps_assistant_unmask_only() {
        let e = engine_with_marker("<", ">");
        let m = e.mask("mail bob@example.com", Surface::UserMessage).unwrap();
        let tok = m.manifest.entries[0].token_handle.clone();
        let line = format!("write to {tok} now");

        let decorated = e.unmask_assistant(&line, &m.manifest).unwrap();
        assert_eq!(decorated, "write to <bob@example.com> now");

        // Plain unmask (tool input / compaction path) is undecorated.
        let plain = e.unmask(&line, &m.manifest).unwrap();
        assert_eq!(plain, "write to bob@example.com now");
    }

    // An UNKNOWN token (not in the manifest or store) is left verbatim — never
    // wrapped, so we never decorate a value we didn't actually reveal.
    #[test]
    fn reveal_marker_leaves_unknown_token_verbatim() {
        let e = engine_with_marker("<", ">");
        let m = UnmaskManifest::new();
        let line = "ghost [EMAIL_ADDRESS_deadbeef0000] here";
        assert_eq!(e.unmask_assistant(line, &m).unwrap(), line);
    }

    // Disabled marker ⇒ `unmask_assistant` == `unmask` (no behavior change; this is
    // why every pre-existing default-config test stays green).
    #[test]
    fn reveal_marker_disabled_is_plain_unmask() {
        let e = engine(); // default: marker off
        let m = e.mask("mail bob@example.com", Surface::UserMessage).unwrap();
        let tok = m.manifest.entries[0].token_handle.clone();
        let line = format!("to {tok}");
        assert_eq!(
            e.unmask_assistant(&line, &m.manifest).unwrap(),
            e.unmask(&line, &m.manifest).unwrap()
        );
    }

    // THE transparency invariant: a wrapped reply re-sent as assistant history masks
    // to BYTE-IDENTICAL bytes as masking the bare token — the decoration adds zero
    // noise upstream. Proven with an ANSI marker whose prefix ends in a word char
    // (`m`), the worst case for naive token-adjacent stripping.
    #[test]
    fn reveal_marker_strips_on_resend_byte_identical() {
        let e = engine_with_marker("\u{1b}[97;44m", "\u{1b}[0m");

        // Turn 1: a value is minted, then revealed+wrapped for display.
        let t1 = e
            .mask("contact alice@example.com", Surface::UserMessage)
            .unwrap();
        let tok = t1.manifest.entries[0].token_handle.clone();
        let reply_tokenized = format!("I'll email {tok} today");
        let shown = e.unmask_assistant(&reply_tokenized, &t1.manifest).unwrap();
        assert!(shown.contains("\u{1b}[97;44malice@example.com\u{1b}[0m"));

        // Turn 2: Claude Code re-sends that shown reply as assistant history.
        let resent = e.mask(&shown, Surface::AssistantText).unwrap();
        // Baseline: what the bare token would have masked to with no marker at all.
        let baseline = e.mask(&reply_tokenized, Surface::AssistantText).unwrap();
        assert_eq!(
            resent.masked_text, baseline.masked_text,
            "re-sent assistant history must be byte-identical to the un-decorated token: {:?}",
            resent.masked_text
        );
        // And concretely: the email is a clean token, no stray ANSI bytes survive.
        assert!(resent.masked_text.contains(&tok));
        assert!(!resent.masked_text.contains('\u{1b}'));
        assert!(!resent.masked_text.contains("alice@example.com"));
    }

    // The reveal marker is display/apply-time: a live change must NOT move the
    // detection fingerprint (the cache must survive toggling the decoration).
    #[test]
    fn reveal_marker_not_in_detection_fingerprint() {
        let base = EngineConfig::default().detection_fingerprint();
        let mut cfg = EngineConfig::default();
        cfg.reveal_marker = RevealMarker {
            enabled: true,
            prefix: "<<".into(),
            suffix: ">>".into(),
        };
        assert_eq!(
            base,
            cfg.detection_fingerprint(),
            "reveal_marker must not affect the detection fingerprint"
        );
    }

    // The strip is assistant-surface-only and token-faithful: it must NOT mangle a
    // user message that legitimately contains the marker bytes around non-PII.
    #[test]
    fn reveal_marker_strip_is_assistant_surface_only() {
        let e = engine_with_marker("$", "$");
        // A user types literal `$`; that surface is never stripped, so the `$` survive
        // (the strip is AssistantText-only — we only peel decoration WE added).
        let user = e.mask("the price is $5 to $10", Surface::UserMessage).unwrap();
        assert!(
            user.masked_text.contains("$5") && user.masked_text.contains("$10"),
            "user-surface `$` must not be stripped: {:?}",
            user.masked_text
        );
    }

    // Any surface label can be masked (no direction gate); unmask round-trips.
    #[test]
    fn assistant_surface_masks_and_round_trips() {
        let e = engine();
        let original = "I emailed dave@example.com for you";
        let out = e.mask(original, Surface::AssistantText).unwrap();
        assert!(out.masked_text.contains("[EMAIL_ADDRESS_"));
        assert_eq!(e.unmask(&out.masked_text, &out.manifest).unwrap(), original);
    }

    // ----- Detection cache (Component 1) — committed-scope verification --------

    // A repeated identical leaf hits the cache, reproduces the masked text, and
    // REPLAYS the manifest (not a cached-empty) so it still unmasks.
    #[test]
    fn cache_hit_is_deterministic_and_replays_manifest() {
        let e = engine();
        let text = "email alice@example.com and bob@example.com";
        let a = e.mask(text, Surface::UserMessage).unwrap();
        assert_eq!(a.stats.fresh_miss, 1, "first mask is a miss");
        assert_eq!(a.stats.hit, 0);
        let b = e.mask(text, Surface::UserMessage).unwrap();
        assert_eq!(b.stats.hit, 1, "second identical mask is a cache hit");
        assert_eq!(b.stats.fresh_miss, 0);
        assert_eq!(a.masked_text, b.masked_text, "hit reproduces the masked text");
        assert!(
            !b.manifest.is_empty(),
            "manifest is REPLAYED on a hit, not cached empty"
        );
        assert_eq!(a.manifest.len(), b.manifest.len());
        assert_eq!(e.unmask(&b.masked_text, &b.manifest).unwrap(), text);
    }

    // Manifest-replay regression: a custom literal token (which does NOT match
    // `token_regex`) unmasks ONLY via the replayed per-call manifest, so it must
    // survive a cache hit.
    #[test]
    fn literal_token_round_trips_through_a_cache_hit() {
        let mut cfg = EngineConfig::default();
        cfg.custom_replacements.push(CustomReplacement {
            pattern: "ACME-CODENAME".into(),
            entity_type: "CODENAME".into(),
            is_regex: false,
            case_sensitive: true,
            priority: 0,
            literal_token: true,
            token: Some("[CODENAME_acme]".into()),
            apply_to_surfaces: None,
        });
        let e = MaskEngine::new(cfg).unwrap();
        let text = "deploy ACME-CODENAME now";
        let first = e.mask(text, Surface::UserMessage).unwrap();
        assert_eq!(first.stats.fresh_miss, 1);
        let second = e.mask(text, Surface::UserMessage).unwrap();
        assert_eq!(second.stats.hit, 1, "second mask is a hit");
        assert!(second.masked_text.contains("[CODENAME_acme]"));
        assert_eq!(e.unmask(&second.masked_text, &second.manifest).unwrap(), text);
    }

    // Operators are resolved at APPLY time: swapping an operator VALUE (same key)
    // takes effect on the same text WITHOUT a detection re-run (cache hit).
    #[test]
    fn operator_value_swap_applies_without_redetection() {
        let mut cfg = EngineConfig::default();
        // Pre-establish the EMAIL operator KEY so a later value swap leaves the
        // detection fingerprint intact.
        cfg.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Token);
        let e = MaskEngine::new(cfg).unwrap();
        let text = "mail carol@example.com";
        let first = e.mask(text, Surface::UserMessage).unwrap();
        assert_eq!(first.stats.fresh_miss, 1);
        assert!(first.masked_text.contains("[EMAIL_ADDRESS_"));

        let mut cfg2 = e.config_snapshot();
        cfg2.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Redact);
        e.set_config(cfg2).unwrap();

        let second = e.mask(text, Surface::UserMessage).unwrap();
        assert_eq!(
            second.stats.hit, 1,
            "an operator VALUE change must NOT bust the cache"
        );
        assert_eq!(second.stats.fresh_miss, 0);
        assert!(
            second.masked_text.contains("[REDACTED]"),
            "the new operator resolves at apply-time: {}",
            second.masked_text
        );
    }

    // A detection-affecting change (category off) moves `policy_fp` → fresh
    // detection, and the previously-masked EMAIL is no longer masked.
    #[test]
    fn category_change_invalidates_via_fingerprint() {
        let e = engine();
        let text = "mail dave@example.com";
        let on = e.mask(text, Surface::UserMessage).unwrap();
        assert!(on.masked_text.contains("[EMAIL_ADDRESS_"));
        assert_eq!(on.stats.fresh_miss, 1);
        assert_eq!(e.mask(text, Surface::UserMessage).unwrap().stats.hit, 1);

        let mut cfg = e.config_snapshot();
        cfg.enabled_categories.remove(&Category::Contact);
        e.set_config(cfg).unwrap();

        let off = e.mask(text, Surface::UserMessage).unwrap();
        assert_eq!(
            off.stats.fresh_miss, 1,
            "category change must bust the cache (fresh detection)"
        );
        assert_eq!(off.stats.hit, 0);
        assert!(
            off.masked_text.contains("dave@example.com"),
            "EMAIL no longer masked once Contact is off: {}",
            off.masked_text
        );
    }

    // LRU (not FIFO) eviction, and a live `cap = 0` that clears + disables.
    #[test]
    fn lru_evicts_least_recently_used_and_live_cap_zero_disables() {
        let cfg = EngineConfig {
            detection_cache_cap: 2,
            ..Default::default()
        };
        let e = MaskEngine::new(cfg).unwrap();
        let (t1, t2, t3) = (
            "one alice@example.com",
            "two bob@example.com",
            "three carol@example.com",
        );
        e.mask(t1, Surface::UserMessage).unwrap();
        e.mask(t2, Surface::UserMessage).unwrap();
        assert_eq!(e.cache.len(), 2);
        // Touch t1 → t2 becomes the least-recently-used.
        assert_eq!(e.mask(t1, Surface::UserMessage).unwrap().stats.hit, 1);
        // Insert t3 → evicts the LRU (t2), NOT t1 (which FIFO would have dropped).
        e.mask(t3, Surface::UserMessage).unwrap();
        assert_eq!(e.cache.len(), 2);
        assert_eq!(
            e.mask(t1, Surface::UserMessage).unwrap().stats.hit,
            1,
            "t1 stayed resident (recently used)"
        );
        assert_eq!(
            e.mask(t2, Surface::UserMessage).unwrap().stats.fresh_miss,
            1,
            "t2 was evicted as the LRU → miss"
        );

        // Live disable.
        let mut cfg0 = e.config_snapshot();
        cfg0.detection_cache_cap = 0;
        e.set_config(cfg0).unwrap();
        assert_eq!(e.cache.len(), 0, "cap 0 clears the cache");
        assert_eq!(
            e.mask(t1, Surface::UserMessage).unwrap().stats.fresh_miss,
            1,
            "disabled cache always misses"
        );
        assert_eq!(e.cache.len(), 0, "disabled cache never inserts");
    }

    // Two (here four) concurrent misses on the SAME new leaf run detection exactly
    // once — the ML gate's re-check gives single-flight (audit #6).
    #[test]
    fn concurrent_misses_single_flight_through_ml_gate() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        struct CountingPerson {
            calls: Arc<AtomicUsize>,
            entities: Vec<EntityType>,
        }
        impl Recognizer for CountingPerson {
            fn name(&self) -> &str {
                "counting-person"
            }
            fn supported_entities(&self) -> &[EntityType] {
                &self.entities
            }
            fn supported_languages(&self) -> &[&str] {
                &["en"]
            }
            fn analyze(
                &self,
                text: &str,
                _e: Option<&[EntityType]>,
                _n: Option<&NlpArtifacts>,
            ) -> Vec<RecognizerResult> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                // Hold the gate long enough that all racers reach the first (gateless)
                // cache probe and miss before this insert lands.
                std::thread::sleep(Duration::from_millis(80));
                match text.find("Dana Scully") {
                    Some(pos) => vec![
                        RecognizerResult::new("PERSON".parse().unwrap(), pos, pos + 11, 0.99)
                            .with_recognizer("counting-person"),
                    ],
                    None => Vec::new(),
                }
            }
        }

        let e = Arc::new(engine_personal_on());
        let calls = Arc::new(AtomicUsize::new(0));
        let generation = e.ml_begin_load(MlConfig {
            enabled: true,
            ..Default::default()
        });
        e.ml_set_ready(
            generation,
            Arc::new(CountingPerson {
                calls: calls.clone(),
                entities: vec!["PERSON".parse().unwrap()],
            }),
        );

        let text = "call Dana Scully";
        std::thread::scope(|s| {
            for _ in 0..4 {
                let e = e.clone();
                s.spawn(move || {
                    let out = e.mask(text, Surface::UserMessage).unwrap();
                    assert!(out.masked_text.contains("[PERSON_"));
                });
            }
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight: 4 concurrent identical misses run detection once"
        );
    }

    // Detection is deterministic and carries a stable per-source tag (the field the
    // deferred Component-3 burn keys off; also exercises the literal marker).
    #[test]
    fn detection_is_deterministic_and_source_tagged() {
        use crate::cache::Source;
        let analyzer = presidio_analyzer::default_analyzer("en");
        let cfg = EngineConfig::default();
        let customs = detect::compile_customs(&cfg.custom_replacements).unwrap();
        let text = "ping bob@example.com";
        let a = run_detection(&analyzer, &cfg, &customs, None, text, Surface::UserMessage).unwrap();
        let b = run_detection(&analyzer, &cfg, &customs, None, text, Surface::UserMessage).unwrap();
        assert_eq!(a.len(), 1, "one EMAIL detection");
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0].start, b[0].start);
        assert_eq!(a[0].end, b[0].end);
        assert_eq!(a[0].entity_type, b[0].entity_type);
        assert_eq!(a[0].source, Source::Regex, "presidio email is regex-sourced");
        assert!(!a[0].literal);
    }
}
