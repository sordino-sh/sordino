//! Shared proxy state.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zlauder_engine::MaskEngine;

use crate::config::ConfigLayers;
use crate::monitor::Monitor;
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

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<MaskEngine>,
    pub http: reqwest::Client,
    pub upstream_base: Arc<String>,
    /// Hex of the session key; required (via `x-zlauder-key`) to call the audit
    /// reveal and `/privacy` control endpoints, so they are not a trivial oracle
    /// for a tool-driven `curl`.
    pub admin_key: Arc<String>,
    /// Per-scope config file paths, so `POST /zlauder/reload` can recompute the
    /// effective engine config after the CLI edits a file.
    pub layers: Arc<ConfigLayers>,
    /// Absolute project root this (per-project) proxy serves.
    pub project_root: Arc<String>,
    /// The port this proxy is bound to (reported by the config endpoint).
    pub port: u16,
    /// In-memory local request monitor and optional approval gate.
    pub monitor: Monitor,
    /// Serializes ML state transitions (`/zlauder/ml/{enable,disable}`, and the ML
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
    /// The target `/zlauder:zdr` engages when given no explicit config name (already
    /// validated to name a resolved target, else `None`).
    pub zdr_default: Arc<Option<String>>,
    /// Per-conversation ZDR posture (the **Trust** switch state). Keyed by the same
    /// conversation id the session route carries (`/zlauder/session/{id}`). A missing
    /// entry = no ZDR (the default). Mutated only by the key-gated control endpoint.
    pub zdr_sessions: Arc<std::sync::Mutex<HashMap<String, ZdrSelection>>>,
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

    /// Disengage ZDR for a conversation, persisting the pruned selection set AFTER the
    /// in-memory mutation. Returns whether a selection was present. **Fail-closed (S1):** if
    /// the durable write fails, the just-removed entry is RE-INSERTED (rollback) and `Err` is
    /// returned — so a successful in-memory disengage whose disk write failed (which would
    /// leave the OLD selection on disk and RESURRECT ZDR on the next recycle) can never
    /// happen. A clear of a conversation that was NOT present still rewrites the unchanged
    /// file; if that write errs there is nothing to roll back — return `Err`.
    pub fn clear_zdr_selection(&self, conversation: &str) -> Result<bool, PersistError> {
        // Same process-wide write serialization as `set_zdr_selection`, acquired FIRST and
        // strictly before `zdr_sessions`, held across {snapshot + write + rollback}.
        let _wguard = SELECTIONS_WRITE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (entries, removed) = {
            let mut map = self.zdr_sessions.lock().expect("zdr_sessions mutex poisoned");
            let removed = map.remove(conversation);
            (Self::snapshot_persisted(&map), removed)
        }; // lock dropped here
        if let Err(e) = self.write_selections(&entries) {
            // Rollback only if we actually removed something.
            if let Some(sel) = removed {
                self.zdr_sessions
                    .lock()
                    .expect("zdr_sessions mutex poisoned")
                    .insert(conversation.to_string(), sel);
            }
            return Err(e);
        }
        Ok(removed.is_some())
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
        zlauder_state::project_key(&self.project_root)
    }

    /// `<state_dir>/zdr-sessions/` — created `0700`. The selections file lives here.
    fn zdr_sessions_dir() -> std::io::Result<PathBuf> {
        let dir = zlauder_state::state_dir()
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
        let dir = zlauder_state::state_dir()
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
            PersistedLoad::Absent => Ok(ZdrReloadReport::default()),

            PersistedLoad::Corrupt(reason) => {
                // Fail-CLOSED-and-visible. The proxy cannot enumerate which conversations the
                // corrupt file held, so it emits a SINGLE global "*" revert. Ordering is
                // non-negotiable: (i) write the global revert FIRST, then (ii) quarantine the
                // corrupt file, then (iii) leave the map empty.
                let reason_msg = format!(
                    "selection state corrupt ({reason}) — all ZDR selections lost across \
                     recycle; re-engage with /zlauder:zdr per conversation"
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
                        "zlauder ZDR: could not quarantine the corrupt selections file ({e}); \
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
                    // DROPPED so it fails closed to Normal). Log and continue.
                    if let Err(e) = self.write_report(&outcome) {
                        tracing::warn!(
                            "zlauder ZDR: could not write reload report for a conversation ({e}); \
                             the in-memory decision still holds"
                        );
                    }
                    report.outcomes.push(outcome);
                }
                // Rewrite the validated map so dropped entries don't linger on disk. A failed
                // rewrite is NOT fatal — the in-memory map is already correct; the stale
                // entries are simply re-validated (and re-dropped) on the next boot.
                if let Err(e) = self.write_selections(&survivors) {
                    tracing::warn!(
                        "zlauder ZDR: could not rewrite the validated selections file ({e}); \
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

    /// Best-effort prune of report files older than [`REPORT_MAX_AGE_SECS`]. Never fatal.
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

    /// Constant-time-ish check of the `x-zlauder-key` header against the admin key.
    pub fn authed(&self, hdrs: &http::HeaderMap) -> bool {
        let provided = hdrs
            .get("x-zlauder-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Length-prefixed equality is fine here: the key is local-only and the
        // endpoint is loopback-bound; this gate exists to stop a blind tool `curl`,
        // not a co-located timing attacker (who can already read the 0600 file).
        !provided.is_empty() && provided == self.admin_key.as_str()
    }
}

// -- file helpers for ZDR selection persistence (A4/H1/D1) ----------------------

/// Atomically write `bytes` to `path` (`0600`), mirroring `zlauder_state::write_rendezvous`:
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

/// Reduce a conversation id to a single safe filename component so a hostile/path-bearing id
/// (`../../etc/foo`) can never escape the report dir. Keeps `[A-Za-z0-9._-]`, replaces the
/// rest with `_`, and never yields an empty or dot-only name.
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
