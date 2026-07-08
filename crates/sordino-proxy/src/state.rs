//! Shared proxy state.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sordino_engine::MaskEngine;

use crate::config::ConfigLayers;
use crate::monitor::{Ledger, Monitor};
use crate::secrets::SecretsStatus;
use crate::zdr::{ZdrSelection, ZdrTarget};

/// Upper bound on persisted per-conversation selections, so a runaway/abusive caller
/// cannot grow the selections file without limit. (UNCERTAIN value — 1000 is a generous
/// ceiling for concurrent conversations in one project; a real workload is far smaller.)
const MAX_PERSISTED_SELECTIONS: usize = 1000;

/// Process-global monotonic nonce making each selections-file temp path unique, so two
/// concurrent writers to the SAME `<project_key>.json` never collide on the same temp file
/// (one truncating the temp the other is renaming ⇒ spurious `NotFound` rename ⇒ spurious
/// `PersistError`/5xx). See [`atomic_write_0600`].
static WRITE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Process-global lock serializing ALL selection-file writes (one proxy per project, so a
/// single mutex suffices). Held across the whole {snapshot + write + rollback} critical
/// section in `set_zdr_selection`/`clear_zdr_selection` so a STALER snapshot can never win
/// the rename and durably drop an engaged conversation (silent Normal revert on recycle).
/// **Lock order:** acquired ONLY in set/clear and ALWAYS strictly before `zdr_sessions` —
/// never the reverse — so it can deadlock with neither `zdr_sessions` nor `config_control`.
static SELECTIONS_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Best-effort retention for the per-conversation report dir: prune report files older
/// than this so a long-lived state dir does not accumulate stale revert/restore reports.
const REPORT_MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60; // two weeks

/// A persisted ZDR selection — **conversation → target NAME only**, NEVER a credential,
/// a [`ZdrTarget`], or a `ZdrKey`. The absence of any key-bearing field is the durable
/// invariant: the on-disk selections file can be world-read (it is `0600`, but defense in
/// depth) and still carry nothing that decrypts or authenticates anything. Asserted by
/// construction — this struct has exactly two `String` fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSelection {
    pub conversation: String,
    pub target: String,
}

/// A failed durable write of the selections file. Carries the io/serde reason string so
/// the admin handler can surface *why* the engage/disengage could not be made durable.
#[derive(Debug)]
pub struct PersistError(pub String);

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PersistError {}

/// Three-way result of loading the selections file. Distinguishes "no file" (first boot,
/// legitimately zero) from "unreadable / malformed file" (the exact fail-OPEN this finding
/// forbids) — unlike `read_rendezvous`, which collapses NotFound/perm-denied/malformed all
/// into `None`.
#[derive(Debug)]
pub enum PersistedLoad {
    /// File does not exist — first boot. Empty map, no synthetic revert, silent.
    Absent,
    /// File parsed cleanly (a present-but-empty array is `Loaded(vec![])`, NOT corrupt).
    Loaded(Vec<PersistedSelection>),
    /// File exists but is unreadable (permission denied / I/O error) OR malformed
    /// (torn write / partial JSON). NEVER silently treated as empty — fail-closed-and-visible.
    Corrupt(String),
}

/// A failed boot — the proxy must NOT bind the listener. Emitted in exactly one place: a
/// failed *global-revert WRITE* on the Corrupt branch, where the degrade cannot be made
/// visible any other way.
#[derive(Debug)]
pub struct ReloadFatal(pub String);

impl std::fmt::Display for ReloadFatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ReloadFatal {}

/// One per-conversation outcome of revalidating the persisted selections at boot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReloadOutcome {
    /// The target still resolves and is user_verified — ZDR restored into the map.
    Restored { conversation: String, target: String },
    /// The selection was DROPPED (fails closed to Normal) — the user must be told.
    Reverted { conversation: String, reason: String },
}

/// The set of per-conversation outcomes A6 narrates. Empty on a true first boot.
#[derive(Clone, Debug, Default)]
pub struct ZdrReloadReport {
    pub outcomes: Vec<ReloadOutcome>,
}

/// The epoch-bearing global Corrupt sentinel written to `<project_key>.global.json`. The
/// `epoch` (unix nanos) is a strictly-monotonic instance id so A6 can distinguish "already
/// narrated THIS corrupt instance" from "a NEW corrupt instance".
#[derive(Clone, Debug, Serialize, Deserialize)]
struct GlobalRevert {
    epoch: u64,
    conversation: String,
    reason: String,
}

/// Default bounded off-window: an absent-ttl `mask off` self-reverts after this. Enforced
/// **server-side** (in [`AppState::set_masking_disabled`]), NOT client-side — so the legacy
/// `disable` alias, which POSTs no body, can never produce an UNBOUNDED off (the J2 backstop).
/// Short-and-bounded is the safe surprise direction (fails toward masking-ON).
pub const DEFAULT_MASKING_OFF_TTL: Duration = Duration::from_secs(30 * 60);

/// Hard ceiling on ANY off-window (F3 `--for <dur>` / `--sticky`). A caller-supplied ttl is
/// CLAMPED to this before the deadline is computed, so (a) a huge `--for 9999h` (or `--sticky`,
/// which requests this ceiling explicitly) can never overflow the monotonic `Instant + ttl` add,
/// and (b) "indefinite" is really "up to 24h, then auto-re-arm" — there is no unbounded off.
pub const MAX_MASKING_OFF_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cap on the recently-auto-reverted ring. Write-mostly here (feeds later re-arm narration);
/// bounded so a long-lived proxy that churns many offs never grows it without limit.
const RECENTLY_REVERTED_CAP: usize = 16;

/// Why a per-conversation masking-off was cleared (recorded on the [`MaskingDisabled`] ring).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevertReason {
    /// The bounded off-window's TTL elapsed; enforcement lazily re-masked the conversation.
    Expired,
}

/// A per-conversation masking-off window's bounded deadline.
#[derive(Clone, Debug)]
pub struct Deadline {
    /// **Monotonic** instant at/after which enforcement re-masks. Compared against the injected
    /// [`Clock`], NEVER wall-clock — so setting `SystemTime` backward can't extend the window.
    pub enforce: Instant,
    /// Wall-clock deadline for DISPLAY only (statusline "until HH:MM"); never drives enforcement.
    pub display: SystemTime,
    /// How the off was set (informational — currently the ttl basis).
    pub reason: String,
}

/// Injectable monotonic clock behind the off-window TTL. Production uses [`Clock::system`];
/// a unit test uses [`Clock::manual`] and ADVANCES it — a hardcoded `Instant::now()` cannot be
/// moved forward, which would make the load-bearing TTL gate un-runnable.
#[derive(Clone)]
pub enum Clock {
    /// Real monotonic time.
    System,
    /// Test clock: a shared, advanceable `Instant` (cloneable — an `Arc` handle can advance it).
    Manual(Arc<std::sync::Mutex<Instant>>),
}

impl Clock {
    /// The production clock (real monotonic time).
    pub fn system() -> Self {
        Clock::System
    }

    /// A test clock starting at `base`; advance it with [`Clock::advance`].
    pub fn manual(base: Instant) -> Self {
        Clock::Manual(Arc::new(std::sync::Mutex::new(base)))
    }

    /// Now, on the monotonic timeline this clock represents.
    pub fn now(&self) -> Instant {
        match self {
            Clock::System => Instant::now(),
            Clock::Manual(t) => *t.lock().expect("manual clock mutex poisoned"),
        }
    }

    /// Advance a manual clock by `by` (a no-op on the system clock — test affordance only).
    pub fn advance(&self, by: Duration) {
        if let Clock::Manual(t) = self {
            let mut g = t.lock().expect("manual clock mutex poisoned");
            *g += by;
        }
    }
}

/// The per-conversation masking-off state, held behind a single mutex: the bounded off-windows,
/// the [`Clock`] their TTL is enforced against, and a small ring of recently auto-reverted
/// windows. Colocating the three under ONE lock lets [`AppState::is_masking_disabled`] read the
/// clock, evict an expired entry, and record the revert atomically — WITHOUT adding a clock/ring
/// parameter to that method (its `(&self, &str) -> bool` signature is pinned by egress callers).
pub struct MaskingDisabled {
    /// conv id -> its bounded off-window. Presence (after lazy expiry) = masking OFF for that
    /// conversation. This is the `HashMap<String, Deadline>` the F2 spec names.
    pub entries: HashMap<String, Deadline>,
    /// The clock the `enforce` deadlines are compared against.
    pub clock: Clock,
    /// Ring of recently TTL-expired offs (newest at the back), bounded by [`RECENTLY_REVERTED_CAP`].
    pub recently_reverted: VecDeque<(String, SystemTime, RevertReason)>,
}

impl MaskingDisabled {
    /// Empty state driven by `clock`.
    pub fn new(clock: Clock) -> Self {
        Self {
            entries: HashMap::new(),
            clock,
            recently_reverted: VecDeque::new(),
        }
    }
}

impl Default for MaskingDisabled {
    /// Empty state on the production (system) clock — the default for every non-test init site.
    fn default() -> Self {
        Self::new(Clock::system())
    }
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<MaskEngine>,
    pub http: reqwest::Client,
    pub upstream_base: Arc<String>,
    /// Hex of the session key; required (via `x-sordino-key`) to call the audit
    /// reveal and `/privacy` control endpoints, so they are not a trivial oracle
    /// for a tool-driven `curl`.
    pub admin_key: Arc<String>,
    /// Per-scope config file paths, so `POST /sordino/reload` can recompute the
    /// effective engine config after the CLI edits a file.
    pub layers: Arc<ConfigLayers>,
    /// Absolute project root this (per-project) proxy serves.
    pub project_root: Arc<String>,
    /// The port this proxy is bound to (reported by the config endpoint).
    pub port: u16,
    /// In-memory local request monitor and optional approval gate.
    pub monitor: Monitor,
    /// Opt-in append-only policy-event ledger. `None` on the default (privacy-first)
    /// path — a registered-secret wire-refusal appends one class-only JSONL line only
    /// when the operator sets `[proxy] ledger = true`. Best-effort: a ledger write error
    /// never alters the 409 refusal (the refusal is the enforcement; the ledger is the
    /// receipt). Its own `Mutex` lives inside [`Ledger`], never the monitor store's lock.
    pub ledger: Option<Arc<Ledger>>,
    /// Serializes ML state transitions (`/sordino/ml/{enable,disable}`, and the ML
    /// reconcile in `put`/`reload`). Without it, two concurrent `model on`/`off`
    /// requests can interleave their config-write and runtime-toggle so a stale
    /// reconcile resurrects a load after the last intent was *off*. Held only across
    /// the sync critical section (never across an `.await`).
    pub ml_control: Arc<std::sync::Mutex<()>>,
    /// Serializes the config read-modify-write shared by EVERY control-plane writer
    /// (`config_snapshot` → mutate → `set_config`, plus the synchronous local-TOML
    /// persist). Without it two concurrent writers (reveal + profile, custom-mask +
    /// PUT, …) lost-update each other, and a persist could be reordered against the
    /// live swap. Held across the snapshot→set_config→persist critical section, never
    /// across an `.await`. Lock order is fixed **`config_control` then `ml_control`**
    /// everywhere a writer needs both, to avoid deadlock.
    pub config_control: Arc<std::sync::Mutex<()>>,
    /// Readiness gate for the secrets channel. `false` holds LLM intake at `503`
    /// until all REQUIRED secrets have resolved from their backends (fail-closed: a
    /// required secret that never resolves keeps intake closed). Starts `true` when
    /// no secret is `required` (or none configured), so a no-secret project pays zero
    /// overhead. `/healthz` is NOT gated (liveness answers immediately).
    pub secrets_ready: Arc<AtomicBool>,
    /// Per-secret resolution status for the admin snapshot (names/operators/scheme/
    /// resolved/required + any error). NEVER contains a secret value.
    pub secrets_status: Arc<std::sync::RwLock<SecretsStatus>>,
    /// ZDR trust-routing registry, resolved ONCE at startup from the `[zdr]` config.
    /// Immutable for the proxy's life (targets don't reload live), so an in-flight
    /// request that captured an `Arc<ZdrTarget>` is never stranded by a config change.
    /// Holds the in-process credential and is therefore NEVER serialized.
    pub zdr_targets: Arc<HashMap<String, Arc<ZdrTarget>>>,
    /// The target `/sordino:zdr` engages when given no explicit config name (already
    /// validated to name a resolved target, else `None`).
    pub zdr_default: Arc<Option<String>>,
    /// Per-conversation ZDR posture (the **Trust** switch state). Keyed by the same
    /// conversation id the session route carries (`/sordino/session/{id}`). A missing
    /// entry = no ZDR (the default). Mutated only by the key-gated control endpoint.
    pub zdr_sessions: Arc<std::sync::Mutex<HashMap<String, ZdrSelection>>>,
    /// Conversations whose masking is temporarily turned OFF (the per-conversation
    /// counterpart of the project-wide master switch). Keyed by the same conversation id
    /// the session route carries (`/sordino/session/{id}`); membership = masking disabled
    /// for that conversation. Mutated only by the key-gated control endpoint.
    ///
    /// **In-memory ONLY, by design** — unlike ZDR selections this is never persisted. It
    /// mirrors the master switch (`config.enabled`, also runtime-only) and, crucially,
    /// fails toward masking-ON: a proxy recycle drops the set, so a forgotten disable can
    /// never silently keep a conversation unmasked across restarts. A registered secret is
    /// still masked for a disabled conversation (the engine's A9 carve-out via
    /// [`MaskEngine::mask_when_disabled`]).
    ///
    /// **Bounded lifecycle (F2):** each off is a `HashMap<String, Deadline>` entry, not a bare
    /// set member — it self-reverts once its TTL elapses (default [`DEFAULT_MASKING_OFF_TTL`]),
    /// enforced on a monotonic [`Clock`] via lazy expiry in [`Self::is_masking_disabled`] plus a
    /// key-gated expired-only GC sweep at SessionStart. The recycle-fails-ON guarantee still
    /// holds; the TTL adds a backstop for a forgotten off within a single proxy life.
    pub masking_disabled: Arc<std::sync::Mutex<MaskingDisabled>>,
}

impl AppState {
    /// Host portion of the upstream base URL (for the rewritten `Host` header).
    pub fn upstream_host(&self) -> &str {
        self.upstream_base
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("api.anthropic.com")
    }

    /// Whether the secrets readiness gate is open (required secrets resolved).
    pub fn secrets_ready(&self) -> bool {
        self.secrets_ready.load(Ordering::Relaxed)
    }

    /// Look up a resolved ZDR target by name (cloning the `Arc`, not the target).
    pub fn zdr_target(&self, name: &str) -> Option<Arc<ZdrTarget>> {
        self.zdr_targets.get(name).cloned()
    }

    /// Whether masking is currently turned OFF for this conversation — with **lazy expiry**:
    /// if the entry's bounded TTL has elapsed on the injected [`Clock`], it is evicted, recorded
    /// on the recently-reverted ring, and this returns `false` (masked). Because every egress
    /// chokepoint (`routes.rs`, `openai_chat.rs`, `openai_responses.rs`) funnels through this one
    /// method, the whole request path inherits auto-revert from here. The guard is dropped before
    /// the caller does any `.await`.
    pub fn is_masking_disabled(&self, conversation: &str) -> bool {
        // Read the clock BEFORE taking the lock so no lock is held across the (trivial) clock read.
        let now = self.clock_now();
        let mut md = self
            .masking_disabled
            .lock()
            .expect("masking_disabled mutex poisoned");
        match md.entries.get(conversation) {
            Some(d) if now >= d.enforce => {
                // TTL elapsed on the MONOTONIC timeline: evict and record the auto-revert. Record
                // the scheduled wall-clock deadline (`display`) as the revert `when` (display-only).
                let display = d.display;
                md.entries.remove(conversation);
                md.recently_reverted.push_back((
                    conversation.to_string(),
                    display,
                    RevertReason::Expired,
                ));
                while md.recently_reverted.len() > RECENTLY_REVERTED_CAP {
                    md.recently_reverted.pop_front();
                }
                false
            }
            Some(_) => true,
            None => false,
        }
    }

    /// Turn masking OFF for this conversation for a bounded window. `ttl` `None` applies the
    /// SERVER-SIDE default [`DEFAULT_MASKING_OFF_TTL`] — so an absent-ttl caller (the legacy
    /// `disable` alias POSTs no body) can never produce an unbounded off. Returns `true` if this
    /// was a NEW disable, `false` if it re-armed an existing one (mirroring the old set-insert
    /// contract `admin.rs` consumes). In-memory only — no fail-closed rollback path.
    pub fn set_masking_disabled(&self, conversation: &str, ttl: Option<Duration>) -> bool {
        // Clamp to the 24h ceiling FIRST: a huge caller ttl (`--for 9999h`, or `--sticky` which
        // asks for the ceiling) is bounded before it ever reaches the `Instant`/`SystemTime` add,
        // so it can neither overflow nor produce a truly unbounded off.
        let ttl = ttl.unwrap_or(DEFAULT_MASKING_OFF_TTL).min(MAX_MASKING_OFF_TTL);
        let now = self.clock_now();
        // Belt-and-suspenders even after the clamp: `checked_add` can't panic, and a (practically
        // impossible, post-clamp) overflow falls back to `now` — an already-elapsed deadline, i.e.
        // fail-toward-masking-ON.
        let deadline = Deadline {
            enforce: now.checked_add(ttl).unwrap_or(now),
            display: SystemTime::now()
                .checked_add(ttl)
                .unwrap_or_else(SystemTime::now),
            reason: format!("ttl={}s", ttl.as_secs()),
        };
        self.masking_disabled
            .lock()
            .expect("masking_disabled mutex poisoned")
            .entries
            .insert(conversation.to_string(), deadline)
            .is_none()
    }

    /// Turn masking back ON for this conversation — **unconditionally** (removes the override at
    /// any scope; kills J3). Returns whether the conversation was disabled, so the caller can
    /// report a no-op honestly.
    pub fn clear_masking_disabled(&self, conversation: &str) -> bool {
        self.masking_disabled
            .lock()
            .expect("masking_disabled mutex poisoned")
            .entries
            .remove(conversation)
            .is_some()
    }

    /// The conversations currently masking-disabled, for the admin snapshot / statusline (feeds
    /// the F0 snapshot array). Sorted so the snapshot is stable across reads.
    pub fn masking_disabled_active(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .masking_disabled
            .lock()
            .expect("masking_disabled mutex poisoned")
            .entries
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Now, on the [`Clock`] behind the masking-off TTL. Reads the clock out from under the
    /// `masking_disabled` lock (system clock in production; a manual, advanceable one in tests).
    fn clock_now(&self) -> Instant {
        self.masking_disabled
            .lock()
            .expect("masking_disabled mutex poisoned")
            .clock
            .now()
    }

    /// Expired-only GC sweep of the per-conversation off map: evict EVERY entry whose TTL has
    /// elapsed on the injected [`Clock`], recording each on the recently-reverted ring, and
    /// return how many were swept. Called (key-gated) at SessionStart. It sweeps ONLY expired
    /// entries — never a still-live SIBLING window's deliberate off — so a restart of one window
    /// can't strand another's off (the TTL alone covers forgotten offs).
    pub fn sweep_expired_masking_disabled(&self) -> usize {
        let mut md = self
            .masking_disabled
            .lock()
            .expect("masking_disabled mutex poisoned");
        let now = md.clock.now();
        let expired: Vec<String> = md
            .entries
            .iter()
            .filter(|(_, d)| now >= d.enforce)
            .map(|(c, _)| c.clone())
            .collect();
        for conv in &expired {
            if let Some(d) = md.entries.remove(conv) {
                md.recently_reverted
                    .push_back((conv.clone(), d.display, RevertReason::Expired));
                while md.recently_reverted.len() > RECENTLY_REVERTED_CAP {
                    md.recently_reverted.pop_front();
                }
            }
        }
        expired.len()
    }

    /// The ZDR posture a conversation is pinned to, if any. Clones out from under the
    /// lock so the guard is never held across an `.await`.
    pub fn zdr_selection(&self, conversation: &str) -> Option<ZdrSelection> {
        self.zdr_sessions
            .lock()
            .expect("zdr_sessions mutex poisoned")
            .get(conversation)
            .cloned()
    }

    /// Engage ZDR for a conversation (set its pinned target name), persisting the new
    /// selection set to disk AFTER the in-memory mutation. **Fail-closed (S1):** if the
    /// durable write fails the in-memory insert is ROLLED BACK (removed) and `Err` is
    /// returned — so a successful in-memory engage whose disk write failed (the silent-loss
    /// footgun: routes ZDR this proxy life, silently reverts on the next recycle) can never
    /// happen. The in-memory map and the on-disk file never diverge in the fail-open
    /// direction.
    ///
    /// Lock order: insert, DROP the `zdr_sessions` lock, clone the entries out, THEN write —
    /// never hold the lock across the file write, and never touch `config_control` here.
    pub fn set_zdr_selection(
        &self,
        conversation: &str,
        target: &str,
    ) -> Result<(), PersistError> {
        // Serialize selection-file writes process-wide and HOLD the guard across the whole
        // {cap-check + insert + snapshot + write + rollback} section so a staler snapshot can
        // never win the rename. Acquired FIRST, strictly before `zdr_sessions` (lock order).
        let _wguard = SELECTIONS_WRITE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (entries, prior) = {
            let mut map = self.zdr_sessions.lock().expect("zdr_sessions mutex poisoned");
            // Cap fail-closed-and-VISIBLE: a NEW conversation that would grow the map past the
            // bound is refused HERE (surfaces a 5xx via the admin handler), never silently
            // dropped at snapshot time. A switch/re-engage of an EXISTING conversation does not
            // grow the map and is always allowed.
            if !map.contains_key(conversation) && map.len() >= MAX_PERSISTED_SELECTIONS {
                return Err(PersistError(format!(
                    "ZDR selection cap ({MAX_PERSISTED_SELECTIONS}) reached — disengage another conversation first"
                )));
            }
            // Capture the prior value so a failed write can restore the EXACT pre-engage state
            // (a switch X->Y that fails to persist must leave X, not None — else X is dropped
            // unannounced and resurrects on the next recycle).
            let prior = map.insert(
                conversation.to_string(),
                ZdrSelection {
                    target: target.to_string(),
                },
            );
            (Self::snapshot_persisted(&map), prior)
        }; // zdr_sessions lock dropped here; write lock still held
        if let Err(e) = self.write_selections(&entries) {
            // Faithful rollback: restore the prior value (Some) or remove (None) so memory
            // matches the disk's pre-mutation state — never a third diverged state.
            let mut map = self.zdr_sessions.lock().expect("zdr_sessions mutex poisoned");
            match prior {
                Some(old) => {
                    map.insert(conversation.to_string(), old);
                }
                None => {
                    map.remove(conversation);
                }
            }
            return Err(e);
        }
        Ok(())
    }

    /// Disengage ZDR for a conversation **write-first**: the pruned selection set is made
    /// durable BEFORE the in-memory entry is removed. Returns whether a selection was present.
    /// **Fail-closed (S1, D1):** unlike ENGAGE — whose transient state is ZDR (the STRONGER
    /// posture, so map-first is safe) — a map-first DISENGAGE would make its transient state
    /// `Normal` (the WEAKER posture): during the write I/O the entry would already be gone, so a
    /// concurrent request (which takes only `zdr_sessions`, never `SELECTIONS_WRITE_LOCK`) would
    /// resolve `PinnedMode::Normal` and route to the DEFAULT endpoint for a conversation that is
    /// still DURABLY ZDR-pinned. To close that fail-open window the order is reversed: (1)
    /// snapshot the pruned set WITHOUT mutating the live map and record whether the entry was
    /// present, dropping the lock with the entry STILL in the map; (2) `write_selections` FIRST —
    /// on `Err` the map is untouched (still engaged), so just return `Err` (memory == disk ==
    /// engaged, nothing to roll back); (3) only AFTER the write is durable, briefly re-lock and
    /// remove the entry. A clear of a not-present conversation still rewrites the unchanged file
    /// and returns `Ok(false)` on success / `Err` on failure. There is NO window where a
    /// still-durably-pinned conversation routes `Normal`; the only transient is "disk says
    /// disengaged, map still ZDR" for the microsecond before the remove — which routes ZDR
    /// (fail-closed, safe).
    pub fn clear_zdr_selection(&self, conversation: &str) -> Result<bool, PersistError> {
        // Same process-wide write serialization as `set_zdr_selection`, acquired FIRST and
        // strictly before `zdr_sessions`, held across {snapshot + write + remove}.
        let _wguard = SELECTIONS_WRITE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // (1) Compute the pruned snapshot WITHOUT mutating the live map; capture presence.
        // The lock is released with the entry STILL in the map — concurrent routing keeps
        // resolving ZDR until the durable write below succeeds.
        let (entries, was_present) = {
            let map = self.zdr_sessions.lock().expect("zdr_sessions mutex poisoned");
            let was_present = map.contains_key(conversation);
            (Self::snapshot_persisted_excluding(&map, conversation), was_present)
        }; // lock dropped here — entry still present in the map
        // (2) Write-FIRST. On failure the map is untouched (still engaged): memory == disk ==
        // engaged, so there is nothing to roll back — just surface the Err (admin → 5xx).
        self.write_selections(&entries)?;
        // (3) Disengage is now DURABLE — only NOW remove the in-memory entry.
        self.zdr_sessions
            .lock()
            .expect("zdr_sessions mutex poisoned")
            .remove(conversation);
        Ok(was_present)
    }

    /// Snapshot of currently-active ZDR sessions as `(conversation, target)` pairs,
    /// for the admin snapshot / statusline. Conversation ids are local session ids.
    pub fn zdr_active(&self) -> Vec<(String, String)> {
        self.zdr_sessions
            .lock()
            .expect("zdr_sessions mutex poisoned")
            .iter()
            .map(|(c, s)| (c.clone(), s.target.clone()))
            .collect()
    }

    // -- ZDR selection persistence (A4/H1/D1) --------------------------------------

    /// The project-identity key main's rendezvous uses, derived from THIS proxy's
    /// canonical project root.
    fn zdr_project_key(&self) -> String {
        sordino_state::project_key(&self.project_root)
    }

    /// `<state_dir>/zdr-sessions/` — created `0700`. The selections file lives here.
    fn zdr_sessions_dir() -> std::io::Result<PathBuf> {
        let dir = sordino_state::state_dir()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .join("zdr-sessions");
        std::fs::create_dir_all(&dir)?;
        set_dir_mode(&dir, 0o700);
        Ok(dir)
    }

    /// `<state_dir>/zdr-sessions/<project_key>.json` — the persisted selection set.
    fn selections_path(&self) -> std::io::Result<PathBuf> {
        Ok(Self::zdr_sessions_dir()?.join(format!("{}.json", self.zdr_project_key())))
    }

    /// `<state_dir>/zdr-reports/` — created `0700`. One file PER conversation, plus the
    /// single project-scoped `<project_key>.global.json` Corrupt sentinel.
    fn zdr_reports_dir() -> std::io::Result<PathBuf> {
        let dir = sordino_state::state_dir()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .join("zdr-reports");
        std::fs::create_dir_all(&dir)?;
        set_dir_mode(&dir, 0o700);
        Ok(dir)
    }

    /// `<state_dir>/zdr-reports/<conversation>.json` — a per-conversation report file.
    /// The conversation id is sanitized so it is always a single safe filename component
    /// (a hostile/path-bearing id can never escape the report dir).
    fn report_path(conversation: &str) -> std::io::Result<PathBuf> {
        Ok(Self::zdr_reports_dir()?.join(format!("{}.json", sanitize_component(conversation))))
    }

    /// `<state_dir>/zdr-reports/<project_key>.global.json` — the project-scoped Corrupt
    /// sentinel (the ONE shared report file).
    fn global_report_path(&self) -> std::io::Result<PathBuf> {
        Ok(Self::zdr_reports_dir()?.join(format!("{}.global.json", self.zdr_project_key())))
    }

    /// Snapshot the live map as a deterministically-ordered `Vec<PersistedSelection>`
    /// (name only — NO key). The persisted set ALWAYS equals the in-memory set: the
    /// [`MAX_PERSISTED_SELECTIONS`] cap is enforced fail-closed at ENGAGE time in
    /// `set_zdr_selection`, NOT by truncating here — a post-insert truncate would silently drop
    /// the lexicographically-last conversation from disk while it still routes ZDR in memory
    /// (silent Normal revert on the next recycle, the exact loss the cap exists to bound).
    fn snapshot_persisted(map: &HashMap<String, ZdrSelection>) -> Vec<PersistedSelection> {
        let mut v: Vec<PersistedSelection> = map
            .iter()
            .map(|(c, s)| PersistedSelection {
                conversation: c.clone(),
                target: s.target.clone(),
            })
            .collect();
        v.sort_by(|a, b| a.conversation.cmp(&b.conversation));
        v
    }

    /// Snapshot the live map as a deterministically-ordered `Vec<PersistedSelection>`,
    /// EXCLUDING `conversation`, WITHOUT mutating the map. This is the write-first disengage
    /// primitive (D1): `clear_zdr_selection` persists this pruned set BEFORE it removes the
    /// in-memory entry, so a still-durably-pinned conversation never routes `Normal` during the
    /// write window. Identical ordering/contract to [`snapshot_persisted`] minus the one key.
    fn snapshot_persisted_excluding(
        map: &HashMap<String, ZdrSelection>,
        conversation: &str,
    ) -> Vec<PersistedSelection> {
        let mut v: Vec<PersistedSelection> = map
            .iter()
            .filter(|(c, _)| c.as_str() != conversation)
            .map(|(c, s)| PersistedSelection {
                conversation: c.clone(),
                target: s.target.clone(),
            })
            .collect();
        v.sort_by(|a, b| a.conversation.cmp(&b.conversation));
        v
    }

    /// Atomically write the selections file (`0600`, temp+rename). Maps any io/serde error
    /// to [`PersistError`].
    fn write_selections(&self, entries: &[PersistedSelection]) -> Result<(), PersistError> {
        let path = self
            .selections_path()
            .map_err(|e| PersistError(e.to_string()))?;
        let bytes = serde_json::to_vec_pretty(entries).map_err(|e| PersistError(e.to_string()))?;
        atomic_write_0600(&path, &bytes).map_err(|e| PersistError(e.to_string()))
    }

    /// Read + classify the selections file three ways (Absent / Loaded / Corrupt). Does NOT
    /// mirror `read_rendezvous` (which collapses every failure into `None` = fail-OPEN):
    /// `NotFound` ⇒ Absent; ANY other read error OR a JSON parse error ⇒ Corrupt(reason).
    pub fn load_persisted_selections(&self) -> PersistedLoad {
        let path = match self.selections_path() {
            Ok(p) => p,
            // Could not even build the path (state_dir failed) — fail-closed, treat as
            // corrupt so the boot makes the degrade visible rather than silently empty.
            Err(e) => return PersistedLoad::Corrupt(e.to_string()),
        };
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Vec<PersistedSelection>>(&bytes) {
                Ok(entries) => PersistedLoad::Loaded(entries),
                Err(e) => PersistedLoad::Corrupt(e.to_string()),
            },
            Err(e) if e.kind() == ErrorKind::NotFound => PersistedLoad::Absent,
            Err(e) => PersistedLoad::Corrupt(e.to_string()),
        }
    }

    /// Collapse duplicate-conversation entries to ONE entry per conversation, LAST occurrence
    /// wins, PRESERVING first-seen order of the survivors (deterministic). Matches how a
    /// `HashMap`-serialized selections file would collapse duplicates, so this is a no-op on a
    /// normally-written file and only disciplines a hand-tampered one. Guarantees the
    /// restore/revert loop processes each conversation exactly once → in-memory map and
    /// `<conv>.json` report always agree.
    fn dedupe_persisted_last_wins(entries: Vec<PersistedSelection>) -> Vec<PersistedSelection> {
        // Last-wins: keep the latest target for each conversation.
        let mut winner: HashMap<String, String> = HashMap::new();
        // Stable first-seen ordering of the surviving conversations (deterministic output).
        let mut order: Vec<String> = Vec::new();
        for entry in entries {
            if !winner.contains_key(&entry.conversation) {
                order.push(entry.conversation.clone());
            }
            winner.insert(entry.conversation, entry.target);
        }
        order
            .into_iter()
            .map(|conversation| {
                let target = winner
                    .remove(&conversation)
                    .expect("winner map populated for every ordered conversation");
                PersistedSelection {
                    conversation,
                    target,
                }
            })
            .collect()
    }

    /// Re-validate the persisted selections at boot and install the surviving ones into the
    /// in-memory map. Fallible in EXACTLY ONE branch — a failed global-revert WRITE on
    /// Corrupt — which propagates so the proxy does NOT bind the listener. Every other path
    /// returns `Ok(report)`; every other side-effect failure logs-and-continues because the
    /// routing decision is already safe (Restored in memory, or Reverted = dropped = Normal).
    pub fn reload_zdr_sessions(
        &self,
        load: PersistedLoad,
    ) -> Result<ZdrReloadReport, ReloadFatal> {
        // Best-effort prune of stale report files; never fatal.
        let _ = Self::prune_old_reports();
        match load {
            // First boot — empty map, empty report, silent. NO synthetic revert.
            // This boot's selection state was readable (no file ⇒ nothing corrupt), so clear
            // any stale Corrupt sentinel a PAST corrupt boot left behind (signal hygiene).
            PersistedLoad::Absent => {
                self.clear_global_revert();
                Ok(ZdrReloadReport::default())
            }

            PersistedLoad::Corrupt(reason) => {
                // Fail-CLOSED-and-visible. The proxy cannot enumerate which conversations the
                // corrupt file held, so it emits a SINGLE global "*" revert. Ordering is
                // non-negotiable: (i) write the global revert FIRST, then (ii) quarantine the
                // corrupt file, then (iii) leave the map empty.
                let reason_msg = format!(
                    "selection state corrupt ({reason}) — all ZDR selections lost across \
                     recycle; re-engage with /sordino:zdr per conversation"
                );
                // (i) The ONE boot-fatal write.
                if let Err(e) = self.write_global_revert(&reason_msg) {
                    return Err(ReloadFatal(format!(
                        "could not write the global ZDR revert sentinel ({e}); refusing to \
                         serve with a silently-empty ZDR map"
                    )));
                }
                // (ii) Quarantine — a rename failure is NOT fatal (the degrade is already
                // visible via the written global file); log and continue.
                if let Err(e) = self.quarantine_selections() {
                    tracing::warn!(
                        "sordino ZDR: could not quarantine the corrupt selections file ({e}); \
                         the global revert was written, continuing with an empty map"
                    );
                }
                // (iii) Leave the in-memory map empty.
                let report = ZdrReloadReport {
                    outcomes: vec![ReloadOutcome::Reverted {
                        conversation: "*".into(),
                        reason: reason_msg,
                    }],
                };
                Ok(report)
            }

            PersistedLoad::Loaded(entries) => {
                // The selections file parsed cleanly — THIS boot is not corrupt — so clear any
                // stale Corrupt sentinel a past corrupt boot left behind. The per-entry outcomes
                // below (Restored/Reverted) are about INDIVIDUAL selections; the global sentinel
                // is a whole-instance "ALL selections were lost" signal and does not belong to a
                // clean boot regardless of how individual entries resolve. Signal hygiene only.
                self.clear_global_revert();
                // Dedupe by conversation BEFORE the restore/revert loop so each conversation
                // is processed EXACTLY ONCE. The selections file is normally serialized from a
                // `HashMap`, so it never contains duplicate conversations — but it is a `0600`
                // file the user could hand-edit, and a duplicated conversation (e.g. one valid
                // and one missing target) would otherwise process the conversation twice:
                // last-write-wins on the `<conv>.json` report, but the in-memory map could still
                // carry the earlier restore — a map/report contradiction (the map routes ZDR
                // while A6 reads the report as Reverted/Normal). Collapsing duplicates here makes
                // the map and the report ALWAYS agree per conversation.
                //
                // Winner = LAST occurrence (deterministic), matching how a `HashMap`-serialized
                // file would collapse duplicates (the last `insert` for a key wins) — so the
                // dedupe is a no-op on a normally-written file and only disciplines a tampered one.
                let entries = Self::dedupe_persisted_last_wins(entries);
                let mut report = ZdrReloadReport::default();
                let mut survivors: Vec<PersistedSelection> = Vec::new();
                for entry in entries {
                    let outcome = match self.zdr_target(&entry.target) {
                        Some(t) if t.user_verified => {
                            // Restore the in-memory map entry FIRST, then write its report.
                            self.zdr_sessions
                                .lock()
                                .expect("zdr_sessions mutex poisoned")
                                .insert(
                                    entry.conversation.clone(),
                                    ZdrSelection {
                                        target: entry.target.clone(),
                                    },
                                );
                            survivors.push(entry.clone());
                            ReloadOutcome::Restored {
                                conversation: entry.conversation.clone(),
                                target: entry.target.clone(),
                            }
                        }
                        Some(_) => ReloadOutcome::Reverted {
                            conversation: entry.conversation.clone(),
                            reason: "target no longer user_verified".into(),
                        },
                        None => ReloadOutcome::Reverted {
                            conversation: entry.conversation.clone(),
                            reason: "target no longer configured".into(),
                        },
                    };
                    // A per-conversation report write failure is NOT boot-fatal — the routing
                    // decision is already safe in memory (Restored routes ZDR; Reverted was
                    // DROPPED from the map so it fails closed to Normal). Log and continue.
                    //
                    // BUT for a REVERTED outcome the report is the ONLY signal A6 has to tell the
                    // user "ZDR could NOT be restored" (D1). If that write fails AND we also drop
                    // the entry from `survivors`, the entry is gone from map+disk with NO report —
                    // a SILENT Normal egress, the exact kill-condition. So on a failed Reverted
                    // report write, KEEP the entry on disk: the next boot re-loads it, re-validates
                    // (still invalid → re-reverts), and RETRIES the report — the revert becomes
                    // eventually-visible instead of permanently-silent. The in-memory map still
                    // does NOT restore it (it routes masked-Normal, data-safe). A SUCCESSFUL
                    // Reverted report → dropped as before (reported + cleaned up). A Restored
                    // report-write failure is non-degrading (the entry is already in map+survivors
                    // and routes ZDR correctly) → keep today's behavior.
                    if let Err(e) = self.write_report(&outcome) {
                        tracing::warn!(
                            "sordino ZDR: could not write reload report for a conversation ({e}); \
                             the in-memory decision still holds"
                        );
                        if let ReloadOutcome::Reverted { conversation, .. } = &outcome {
                            tracing::warn!(
                                "sordino ZDR: retaining reverted selection for {conversation} on \
                                 disk so the next boot retries the revert report (avoids a silent \
                                 Normal egress with no recorded revert)"
                            );
                            survivors.push(PersistedSelection {
                                conversation: conversation.clone(),
                                target: entry.target.clone(),
                            });
                        }
                    }
                    report.outcomes.push(outcome);
                }
                // Rewrite the validated map so dropped entries don't linger on disk. A failed
                // rewrite is NOT fatal — the in-memory map is already correct; the stale
                // entries are simply re-validated (and re-dropped) on the next boot.
                if let Err(e) = self.write_selections(&survivors) {
                    tracing::warn!(
                        "sordino ZDR: could not rewrite the validated selections file ({e}); \
                         stale entries will be re-validated next boot"
                    );
                }
                Ok(report)
            }
        }
    }

    /// Atomically write the epoch-bearing global Corrupt sentinel (`0600`, temp+rename).
    /// OVERWRITES on each corrupt boot so the file always reflects the latest instance; the
    /// `epoch` (unix nanos) is strictly-monotonic across distinct corrupt boots.
    fn write_global_revert(&self, reason: &str) -> std::io::Result<()> {
        let path = self.global_report_path()?;
        let body = GlobalRevert {
            epoch: now_nanos(),
            conversation: "*".into(),
            reason: reason.to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&body)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        atomic_write_0600(&path, &bytes)
    }

    /// Best-effort removal of the global Corrupt sentinel on a CLEAN boot (Absent/Loaded).
    /// The sentinel must reflect ONLY the current boot instance: if THIS boot's selection
    /// state was readable (not corrupt), any sentinel still on disk was written by a PAST
    /// corrupt boot and is now stale. Leaving it would make A6's `consume_zdr_transitions`
    /// narrate the global "ALL ZDR selections lost" line to every conversation first seen on
    /// this (clean) boot — including brand-new ones that never had a ZDR selection — turning a
    /// real corrupt-revert signal into perpetual noise. Removing it means a future corrupt boot
    /// writes a NEW-epoch sentinel, and the `.global-seen` markers' stale epoch correctly
    /// re-triggers a fresh emit then. Signal hygiene ONLY: a `NotFound` (no sentinel) or ANY
    /// other error is non-fatal — it must never fail the boot or change routing.
    fn clear_global_revert(&self) {
        match self.global_report_path() {
            Ok(path) => {
                if let Err(e) = std::fs::remove_file(&path) {
                    if e.kind() != ErrorKind::NotFound {
                        tracing::warn!(
                            "sordino ZDR: could not clear the stale global Corrupt sentinel on a \
                             clean boot ({e}); a past-corrupt signal may re-narrate (non-fatal)"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "sordino ZDR: could not resolve the global Corrupt sentinel path on a clean \
                     boot ({e}); skipping stale-sentinel cleanup (non-fatal)"
                );
            }
        }
    }

    /// Quarantine the unparseable selections file by renaming it to
    /// `<project_key>.json.corrupt-<unix_ts>` so the next boot is Absent, not a permanent
    /// re-corrupt loop.
    fn quarantine_selections(&self) -> std::io::Result<()> {
        let path = self.selections_path()?;
        let quarantined = path.with_file_name(format!(
            "{}.json.corrupt-{}",
            self.zdr_project_key(),
            now_unix()
        ));
        std::fs::rename(&path, &quarantined)
    }

    /// Write one per-conversation report file (`0600`, temp+rename).
    fn write_report(&self, outcome: &ReloadOutcome) -> std::io::Result<()> {
        let conversation = match outcome {
            ReloadOutcome::Restored { conversation, .. }
            | ReloadOutcome::Reverted { conversation, .. } => conversation,
        };
        let path = Self::report_path(conversation)?;
        let bytes =
            serde_json::to_vec_pretty(outcome).map_err(|e| std::io::Error::other(e.to_string()))?;
        atomic_write_0600(&path, &bytes)
    }

    /// Best-effort prune of GENUINELY-AGEABLE report-dir artifacts older than
    /// [`REPORT_MAX_AGE_SECS`]. Never fatal. **D1:** the prune must NEVER delete a pending
    /// per-conversation `<conv>.json` report — those are UNCONSUMED transition signals (A6
    /// consumes a report ONLY by `remove_file` on the user's next UserPromptSubmit in that
    /// conversation), so an existing report = a pending signal. Pruning one would mean a user
    /// dormant in a reverted conversation for > 14 days returns to a SILENT Normal routing
    /// change (the kill-condition). So the prune is restricted to the two artifacts that are NOT
    /// pending signals and DO accumulate: the hooks-internal `<conv>.global-seen` consumed-epoch
    /// markers (a pruned marker just means a future NEW corrupt epoch re-emits — safe) and the
    /// `<project_key>.json.corrupt-<ts>` quarantine files (dead). Everything else — all
    /// `<conv>.json` reports AND the `<project_key>.global.json` sentinel — is PRESERVED.
    fn prune_old_reports() -> std::io::Result<()> {
        let dir = Self::zdr_reports_dir()?;
        let now = now_unix();
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_file() {
                continue;
            }
            // Only the genuinely-ageable, NON-pending-signal artifacts are prunable. A
            // `<conv>.json` report is an unconsumed transition signal and the
            // `<project_key>.global.json` sentinel is a pending signal too — both end in `.json`,
            // so both are SKIPPED here. The `.json`-ending guard is LOAD-BEARING, not redundant:
            // `sanitize_component` preserves `.`/`-`/`_`, so a conversation id literally containing
            // `.json.corrupt-` sanitizes unchanged into a report file `<...>.json.corrupt-<...>.json`
            // that would otherwise match `contains(".json.corrupt-")` and be wrongly pruned —
            // deleting an unconsumed transition signal (the exact silent-revert kill-condition this
            // prune exists to avoid). The genuine quarantine file is `<project_key>.json.corrupt-<ts>`
            // (a numeric ts suffix — it never ends in `.json`), so excluding ALL `.json`-ending
            // names keeps every report/sentinel and still prunes the real quarantine + markers.
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let prunable = !name.ends_with(".json")
                && (name.ends_with(".global-seen") || name.contains(".json.corrupt-"));
            if !prunable {
                continue;
            }
            let age_ok = md
                .modified()
                .ok()
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| now.saturating_sub(d.as_secs()) > REPORT_MAX_AGE_SECS)
                .unwrap_or(false);
            if age_ok {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    /// Constant-time-ish check of the `x-sordino-key` header against the admin key.
    pub fn authed(&self, hdrs: &http::HeaderMap) -> bool {
        let provided = hdrs
            .get("x-sordino-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Length-prefixed equality is fine here: the key is local-only and the
        // endpoint is loopback-bound; this gate exists to stop a blind tool `curl`,
        // not a co-located timing attacker (who can already read the 0600 file).
        !provided.is_empty() && provided == self.admin_key.as_str()
    }

    /// This proxy instance's project-identity hash (a pure `blake3` of the canonical
    /// project root — no I/O). Callers on the SAME project compute the identical value,
    /// so requiring it is a no-op for honest same-project clients while rejecting a
    /// caller that resolved a valid `(port,key)` pair for the WRONG live instance
    /// (a collided/recycled-port race).
    pub fn project_key(&self) -> String {
        sordino_state::project_key(&self.project_root)
    }

    /// True iff `provided` is present AND equals this proxy's project key.
    pub fn project_header_matches(&self, provided: Option<&str>) -> bool {
        provided.is_some_and(|p| p == self.project_key())
    }

    /// Control-plane authorization: the bearer admin key AND this instance's project
    /// identity (`x-sordino-project`). Closes the residual where a valid-shaped
    /// `(port,key)` pair accepted for a collided/recycled-port live instance.
    pub fn authed_for_project(&self, hdrs: &http::HeaderMap) -> bool {
        self.authed(hdrs)
            && self.project_header_matches(hdrs.get("x-sordino-project").and_then(|v| v.to_str().ok()))
    }
}

// -- file helpers for ZDR selection persistence (A4/H1/D1) ----------------------

/// Atomically write `bytes` to `path` (`0600`), mirroring `sordino_state::write_rendezvous`:
/// write a process-unique temp sibling, chmod `0600`, then `rename` onto `path` (atomic on
/// the same filesystem). A failed write or rename leaves NO temp behind, and the PREVIOUS
/// valid file (or none) intact — a torn/partial file on disk is impossible by construction.
fn atomic_write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("state");
    // Unique per write: pid alone collides when two threads write the SAME target file
    // concurrently; a process-global monotonic nonce makes each temp path distinct so one
    // writer can never truncate/remove the temp another is renaming.
    let seq = WRITE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.tmp.{}.{seq}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    set_file_mode(&tmp, 0o600);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Max bytes for a sanitized filename COMPONENT. The final filename is
/// `<component>.json` / `<component>.global-seen` (≤ ~14 extra bytes), so a 200-byte component
/// keeps the whole name well under the 255-byte limit common to ext4/APFS/NTFS — an overlong
/// conversation id can never make the report/marker write fail with `ENAMETOOLONG`.
const SANITIZE_COMPONENT_MAX: usize = 200;

/// Reduce a conversation id to a single safe filename component so a hostile/path-bearing id
/// (`../../etc/foo`) can never escape the report dir. Keeps `[A-Za-z0-9._-]`, replaces the
/// rest with `_`, never yields an empty or dot-only name, and is length-bounded to
/// [`SANITIZE_COMPONENT_MAX`] bytes (an overlong id is deterministically truncated to a prefix
/// plus a stable blake3 hash of the FULL sanitized string, keeping distinct long ids distinct).
///
/// MUST stay BYTE-IDENTICAL to the hooks-side replica (`sordino-hooks` `sanitize_component`): the
/// report-file key A6 reads has to match the key A4 writes, or the transition signal never fires.
fn sanitize_component(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.chars().all(|c| c == '.') {
        out = format!("_{out}");
    }
    // Bound the length. `out` is ASCII by construction (only `[A-Za-z0-9._-]`), so byte- and
    // char-length coincide and slicing on a byte index is always on a char boundary. Hash the
    // FULL sanitized string so distinct long ids stay distinct and both sides derive the same name.
    if out.len() > SANITIZE_COMPONENT_MAX {
        const HASH_HEX: usize = 16;
        const PREFIX: usize = SANITIZE_COMPONENT_MAX - HASH_HEX - 1; // prefix + '-' + 16 hex
        let mut h = blake3::Hasher::new();
        h.update(out.as_bytes());
        out = format!("{}-{}", &out[..PREFIX], &h.finalize().to_hex()[..HASH_HEX]);
    }
    out
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) {}

#[cfg(unix)]
fn set_dir_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn set_dir_mode(_path: &Path, _mode: u32) {}

/// Wall-clock seconds since the unix epoch (0 if the clock is before the epoch).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Wall-clock NANOS since the unix epoch — the strictly-monotonic-across-distinct-boots
/// epoch id the global Corrupt sentinel carries so A6 can tell two corrupt instances apart.
fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod project_binding_tests {
    //! A5-server (GAP-CLOSURE G19): control-plane authorization binds THIS proxy's
    //! project identity (`x-sordino-project`) on top of the bearer admin key.
    use super::*;
    use sordino_engine::{EngineConfig, MaskEngine};
    use std::sync::atomic::AtomicBool;

    const ROOT: &str = "/tmp/sordino-state-test-project";
    const KEY: &str = "unit-admin-key";

    /// Minimal `AppState` bound to a fixed `project_root`/`admin_key` (mirrors the
    /// integration `mk_state` fixture; only the auth-relevant fields matter here).
    fn mk_state() -> AppState {
        AppState {
            engine: Arc::new(MaskEngine::new(EngineConfig::default()).unwrap()),
            http: reqwest::Client::new(),
            upstream_base: Arc::new("http://127.0.0.1:1".into()),
            admin_key: Arc::new(KEY.into()),
            layers: Arc::new(ConfigLayers {
                user: PathBuf::from("/nonexistent/sordino/config.toml"),
                project: None,
                local: None,
            }),
            project_root: Arc::new(ROOT.into()),
            port: 0,
            monitor: Monitor::new(),
            ledger: None,
            ml_control: Arc::new(std::sync::Mutex::new(())),
            config_control: Arc::new(std::sync::Mutex::new(())),
            secrets_ready: Arc::new(AtomicBool::new(true)),
            secrets_status: Arc::new(std::sync::RwLock::new(SecretsStatus::default())),
            zdr_targets: Arc::new(HashMap::new()),
            zdr_default: Arc::new(None),
            zdr_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            masking_disabled: Arc::new(std::sync::Mutex::new(MaskingDisabled::default())),
        }
    }

    /// Build a header map with the given admin key and optional project header.
    fn hdrs(key: Option<&str>, project: Option<&str>) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        if let Some(k) = key {
            h.insert("x-sordino-key", k.parse().unwrap());
        }
        if let Some(p) = project {
            h.insert("x-sordino-project", p.parse().unwrap());
        }
        h
    }

    #[test]
    fn project_header_matches_truth_table() {
        let st = mk_state();
        let correct = st.project_key();
        // correct project -> true
        assert!(st.project_header_matches(Some(correct.as_str())));
        // wrong project -> false
        assert!(!st.project_header_matches(Some("not-this-projects-hash")));
        // missing project -> false
        assert!(!st.project_header_matches(None));
    }

    #[test]
    fn authed_for_project_truth_table() {
        let st = mk_state();
        let correct = st.project_key();
        // correct key + correct project -> true
        assert!(st.authed_for_project(&hdrs(Some(KEY), Some(correct.as_str()))));
        // correct key + wrong project -> false
        assert!(!st.authed_for_project(&hdrs(Some(KEY), Some("wrong-project"))));
        // correct key + missing project -> false
        assert!(!st.authed_for_project(&hdrs(Some(KEY), None)));
        // wrong key + correct project -> false (bearer key still required)
        assert!(!st.authed_for_project(&hdrs(Some("wrong-key"), Some(correct.as_str()))));
    }
}

#[cfg(test)]
mod masking_ttl_tests {
    //! F2 bounded per-conversation masking lifecycle — the load-bearing gate, run against an
    //! INJECTED, advanceable [`Clock`] (a hardcoded `Instant::now()` could not be moved forward,
    //! making the TTL un-testable). Covers the atomic's five kill-conditions at the state layer,
    //! which is where enforcement (`is_masking_disabled`) and the sweep actually live.
    use super::*;
    use sordino_engine::{EngineConfig, MaskEngine};
    use std::sync::atomic::AtomicBool;

    /// Minimal `AppState` whose masking-off map is driven by the supplied (manual) clock, so the
    /// test can advance time past a deadline.
    fn mk_state_with_clock(clock: Clock) -> AppState {
        AppState {
            engine: Arc::new(MaskEngine::new(EngineConfig::default()).unwrap()),
            http: reqwest::Client::new(),
            upstream_base: Arc::new("http://127.0.0.1:1".into()),
            admin_key: Arc::new("k".into()),
            layers: Arc::new(ConfigLayers {
                user: PathBuf::from("/nonexistent/sordino/config.toml"),
                project: None,
                local: None,
            }),
            project_root: Arc::new("/tmp/sordino-ttl-test".into()),
            port: 0,
            monitor: Monitor::new(),
            ledger: None,
            ml_control: Arc::new(std::sync::Mutex::new(())),
            config_control: Arc::new(std::sync::Mutex::new(())),
            secrets_ready: Arc::new(AtomicBool::new(true)),
            secrets_status: Arc::new(std::sync::RwLock::new(SecretsStatus::default())),
            zdr_targets: Arc::new(HashMap::new()),
            zdr_default: Arc::new(None),
            zdr_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            masking_disabled: Arc::new(std::sync::Mutex::new(MaskingDisabled::new(clock))),
        }
    }

    /// Kill-conditions (1) + (5): an absent-ttl off is BOUNDED (server-side 30m default, not
    /// `None`), and once the injected clock passes that deadline the next check is MASKED and the
    /// entry is evicted (recorded on the revert ring).
    #[test]
    fn absent_ttl_off_is_bounded_and_auto_reverts() {
        let base = Instant::now();
        let clock = Clock::manual(base);
        let st = mk_state_with_clock(clock.clone());

        // `mask off` with NO ttl → the SERVER-SIDE default window, so it is bounded (not None).
        assert!(st.set_masking_disabled("A", None));
        assert!(st.is_masking_disabled("A"));
        {
            let md = st.masking_disabled.lock().unwrap();
            let d = md.entries.get("A").expect("entry present");
            assert_eq!(
                d.enforce,
                base + DEFAULT_MASKING_OFF_TTL,
                "absent ttl ⇒ the 30m default deadline, never an unbounded off"
            );
        }

        // Just before the deadline → still off.
        clock.advance(DEFAULT_MASKING_OFF_TTL - Duration::from_secs(1));
        assert!(st.is_masking_disabled("A"));

        // Past the deadline → the next request is MASKED and the entry is evicted.
        clock.advance(Duration::from_secs(2));
        assert!(!st.is_masking_disabled("A"));
        let md = st.masking_disabled.lock().unwrap();
        assert!(md.entries.is_empty(), "expired entry evicted");
        assert_eq!(
            md.recently_reverted
                .back()
                .map(|(c, _, r)| (c.as_str(), *r)),
            Some(("A", RevertReason::Expired)),
            "the auto-revert is recorded on the ring"
        );
    }

    /// Kill-condition (2): enforcement is on the MONOTONIC `Instant`, never the display
    /// `SystemTime`. An entry whose display wall-clock is far in the past stays off until its
    /// monotonic deadline — a backward wall clock can neither revert it early nor extend it.
    #[test]
    fn enforcement_uses_monotonic_instant_not_wall_clock() {
        let base = Instant::now();
        let clock = Clock::manual(base);
        let st = mk_state_with_clock(clock.clone());

        {
            let mut md = st.masking_disabled.lock().unwrap();
            md.entries.insert(
                "A".into(),
                Deadline {
                    enforce: base + Duration::from_secs(600),
                    // Wall-clock deadline already an hour in the PAST — must not drive enforcement.
                    display: SystemTime::now() - Duration::from_secs(3600),
                    reason: "test".into(),
                },
            );
        }
        // Display is in the past, but the monotonic deadline has not passed → still OFF.
        assert!(st.is_masking_disabled("A"));
        // Only advancing the MONOTONIC clock past `enforce` reverts it.
        clock.advance(Duration::from_secs(601));
        assert!(!st.is_masking_disabled("A"));
    }

    /// Kill-condition (3): `mask on` clears the per-conversation off UNCONDITIONALLY (the server
    /// clear is a scope-free map removal), and reports a no-op honestly when nothing was off.
    #[test]
    fn clear_is_unconditional() {
        let st = mk_state_with_clock(Clock::manual(Instant::now()));
        assert!(st.set_masking_disabled("A", None));
        assert!(st.is_masking_disabled("A"));
        assert!(st.clear_masking_disabled("A"), "was disabled");
        assert!(!st.is_masking_disabled("A"));
        assert!(!st.clear_masking_disabled("A"), "second clear is a no-op");
    }

    /// Kill-condition (4): the SessionStart sweep is EXPIRED-ONLY — it evicts a lapsed window but
    /// never a still-live SIBLING window's deliberate off, so restarting one window can't strand
    /// another's off.
    #[test]
    fn sweep_evicts_only_expired_not_live_siblings() {
        let base = Instant::now();
        let clock = Clock::manual(base);
        let st = mk_state_with_clock(clock.clone());

        st.set_masking_disabled("A", Some(Duration::from_secs(60)));
        st.set_masking_disabled("B", Some(Duration::from_secs(36_000)));
        // Advance past A's deadline but well within B's.
        clock.advance(Duration::from_secs(120));

        let swept = st.sweep_expired_masking_disabled();
        assert_eq!(swept, 1, "only the expired sibling is swept");
        assert!(!st.is_masking_disabled("A"));
        assert!(
            st.is_masking_disabled("B"),
            "a live sibling's off SURVIVES another window's SessionStart sweep"
        );
    }

    /// The snapshot array (feeds the F0 predicate) is the sorted set of off conversation keys.
    #[test]
    fn active_lists_sorted_keys() {
        let st = mk_state_with_clock(Clock::manual(Instant::now()));
        st.set_masking_disabled("beta", None);
        st.set_masking_disabled("alpha", None);
        assert_eq!(
            st.masking_disabled_active(),
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }

    /// Re-disabling an already-off conversation re-arms the deadline and reports `false` (not a
    /// NEW disable), preserving the old set-insert bool contract `admin.rs` consumes.
    #[test]
    fn redisable_rearms_and_reports_not_new() {
        let base = Instant::now();
        let clock = Clock::manual(base);
        let st = mk_state_with_clock(clock.clone());
        assert!(st.set_masking_disabled("A", Some(Duration::from_secs(60))));
        clock.advance(Duration::from_secs(30));
        // Re-arm with a fresh window → reports `false` (already off) but the deadline moves out.
        assert!(!st.set_masking_disabled("A", Some(Duration::from_secs(600))));
        let md = st.masking_disabled.lock().unwrap();
        assert_eq!(
            md.entries.get("A").unwrap().enforce,
            base + Duration::from_secs(30) + Duration::from_secs(600),
            "re-arm resets the deadline off the current clock"
        );
    }
}
