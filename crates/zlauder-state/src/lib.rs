//! Shared on-disk session state for zlauder.
//!
//! `zlauder-proxy` and `zlauder-hooks` both need to agree on, per project, the
//! proxy's port, its admin key (the `x-zlauder-key` for the audit/control
//! endpoints), the token salt, and its pid. This crate is the single owner of
//! that file format and its location so the two binaries can't drift.
//!
//! ## Per-project isolation
//!
//! Each project gets its own proxy, hence its own key, salt, store, and config. The
//! proxy binds an OS-assigned ephemeral port (`127.0.0.1:0`) and PUBLISHES a
//! rendezvous record keyed by PROJECT IDENTITY (`blake3(canonical_root)`), so two
//! `claude` windows in the same project share one record (and one proxy), while
//! different projects can never collide — a consumer only ever reads its OWN record.
//!
//! ## Who writes it
//!
//! The **bound proxy** is the sole authority: after it binds, it writes the live
//! rendezvous record (real control token, salt, pid, the port it actually got). A
//! per-launch `nonce` lets the launcher trust only the instance it spawned, so a
//! stale/crashed record is never mistaken for the live proxy (authoritative liveness
//! is a `/healthz` build-id round-trip layered in the hook).
//!
//! The hooks reuse the *salt* across a restart (keeps tokens — and the prompt-cache
//! prefix — stable) but only when the record is owned by the same project.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Per-build identity baked in by `build.rs` (git short SHA, `-dirty` if the tree
/// had uncommitted changes, or `"unknown"` without git). Both binaries embed it;
/// the proxy reports it on `/healthz` and the SessionStart hook compares it against
/// its own to detect — and recycle — a long-lived proxy left over from an older
/// build (e.g. after a plugin update).
pub const BUILD_ID: &str = match option_env!("ZLAUDER_BUILD") {
    Some(s) => s,
    None => "unknown",
};

/// The user-scope config path: `$ZLAUDER_USER_CONFIG`, else
/// `$XDG_CONFIG_HOME/zlauder/config.toml`, else `$HOME/.config/zlauder/config.toml`.
/// Shared by the proxy (layer loading) and the hooks CLI (`--scope user` edits) so
/// they agree on the location.
pub fn user_config_path() -> PathBuf {
    if let Some(p) = std::env::var_os("ZLAUDER_USER_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        // Windows fallback when HOME is unset (Claude Code launched from cmd/PowerShell
        // may not export HOME to Git Bash): %APPDATA% is the roaming config root, so the
        // path becomes %APPDATA%\zlauder\config.toml.
        .or_else(windows_appdata)
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("zlauder").join("config.toml")
}

/// Root directory for zlauder state files (created `0700` on Unix).
///
/// `ZLAUDER_STATE_DIR` wins; else `$XDG_RUNTIME_DIR/zlauder`; else (Windows)
/// `%LOCALAPPDATA%\zlauder`; else a temp dir.
///
/// NOTE: `set_mode` is a no-op on Windows (see below), so the `0700` is not enforced
/// there — the state file holds the proxy's admin key + salt. We therefore prefer a
/// per-user dir (`%LOCALAPPDATA%`) over the shared, cleanup-prone temp dir on Windows;
/// hardening file ACLs further is out of scope.
pub fn state_dir() -> Result<PathBuf> {
    let base = std::env::var_os("ZLAUDER_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("zlauder")))
        .or_else(windows_localappdata_zlauder)
        .unwrap_or_else(|| std::env::temp_dir().join("zlauder"));
    std::fs::create_dir_all(&base).with_context(|| format!("creating state dir {base:?}"))?;
    set_mode(&base, 0o700);
    Ok(base)
}

/// `%LOCALAPPDATA%\zlauder` on Windows (a per-user, non-volatile dir), else `None`.
#[cfg(windows)]
fn windows_localappdata_zlauder() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("zlauder"))
}
#[cfg(not(windows))]
fn windows_localappdata_zlauder() -> Option<PathBuf> {
    None
}

/// `%APPDATA%` (the roaming config root) on Windows, else `None`. Used as a config-path
/// fallback when neither `XDG_CONFIG_HOME` nor `HOME` is set.
#[cfg(windows)]
fn windows_appdata() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}
#[cfg(not(windows))]
fn windows_appdata() -> Option<PathBuf> {
    None
}

/// Is `pid` (probably) a live process? Unix (Linux AND macOS) uses POSIX `kill(pid, 0)`;
/// Windows asks the OS process table; any other platform conservatively assumes alive
/// (never steal a port we can't prove is dead).
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // kill(pid, 0) sends no signal but runs the kernel's existence + permission
        // checks: 0 => the process is alive; errno EPERM => it exists but isn't ours
        // (still alive); ESRCH => it's gone. Portable across Linux and macOS, unlike a
        // `/proc` probe — without this, macOS hit the conservative "always alive" arm,
        // so a crashed proxy's stale record was never reclaimable and pinned its port.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        let pid_s = pid.to_string();
        let Ok(out) = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
        else {
            return true;
        };
        if !out.status.success() {
            return true;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .any(|line| {
                line.split(',')
                    .nth(1)
                    .map(|field| field.trim_matches('"') == pid_s)
                    .unwrap_or(false)
            })
    }
    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}

/// A process-unique temp path next to `path` (same directory → same filesystem, so
/// `rename`/`hard_link` onto `path` are atomic).
fn temp_sibling(path: &Path) -> PathBuf {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("state");
    dir.join(format!(".{name}.tmp.{}", std::process::id()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

// No-op on non-Unix (Windows): there is no portable `chmod`, so state files are not
// permission-restricted there. The proxy state file holds the admin key + salt, so on
// Windows we instead place the state dir under a per-user location (`%LOCALAPPDATA%`,
// see `state_dir`) rather than a world-readable temp dir; tightening NTFS ACLs is out of
// scope.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

// ---------------------------------------------------------------------------
// Plumbed-projects registry (persistent — per-project auto-enable state)
// ---------------------------------------------------------------------------

/// Per-project auto-enable state, persisted in the user-config dir (NOT the volatile runtime
/// state dir), so it survives reboots. SessionStart consults it to avoid re-plumbing a
/// project the user opted out of, and `/zlauder:uninstall --all` uses it to sweep every
/// plumbed project's routing before removing the plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlumbState {
    /// zlauder auto-plumbed (or the user enabled) routing for this project.
    Plumbed,
    /// The user ran `/zlauder:uninstall` here — never auto-plumb it again.
    Optout,
}

/// One project's registry record. Stored ONE FILE PER PROJECT (named by a hash of the root)
/// rather than a single shared map: concurrent updates to DIFFERENT projects then never
/// contend — each writes its own file via the atomic temp+rename — so there is no
/// lost-update race (e.g. one session's auto-plumb clobbering another's opt-out), with no
/// interprocess lock. A same-project race is idempotent (both write the same value). The
/// `root` is stored so the sweep can recover the path from the hashed filename and so a
/// (astronomically unlikely) hash collision is detectable.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryEntry {
    root: String,
    state: PlumbState,
}

/// Directory holding the plumbed-projects registry (one JSON file per project):
/// `<user-config-dir>/plumbed/`.
pub fn registry_dir() -> PathBuf {
    user_config_path().with_file_name("plumbed")
}

fn registry_entry_path(project_root: &str) -> PathBuf {
    registry_dir().join(format!(
        "{}.json",
        blake3::hash(project_root.as_bytes()).to_hex()
    ))
}

/// The recorded auto-enable state for `project_root` (a canonical path), or `None` if
/// zlauder has never plumbed or seen it.
pub fn registry_get(project_root: &str) -> Option<PlumbState> {
    let entry: RegistryEntry = std::fs::read(registry_entry_path(project_root))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())?;
    // Trust the entry only if its stored root matches (guards a hash collision).
    (entry.root == project_root).then_some(entry.state)
}

/// Record `state` for `project_root`, replacing any prior entry (atomic temp+rename). Enable
/// => `Plumbed` (clears a prior opt-out); disable => `Optout`.
pub fn registry_set(project_root: &str, state: PlumbState) -> Result<()> {
    let dir = registry_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {dir:?}"))?;
    let path = registry_entry_path(project_root);
    let entry = RegistryEntry {
        root: project_root.to_string(),
        state,
    };
    let tmp = temp_sibling(&path);
    std::fs::write(&tmp, serde_json::to_vec_pretty(&entry)?)
        .with_context(|| format!("writing {tmp:?}"))?;
    set_mode(&tmp, 0o600);
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming {tmp:?} -> {path:?}"))?;
    Ok(())
}

/// Remove `project_root` from the registry entirely (the disable sweep calls this once a
/// project's routing has been stripped). A missing entry is not an error.
pub fn registry_remove(project_root: &str) -> Result<()> {
    match std::fs::remove_file(registry_entry_path(project_root)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing registry entry"),
    }
}

/// Every project root currently in the `Plumbed` state (used by `/zlauder:uninstall --all`).
pub fn registry_plumbed_roots() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(registry_dir()) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        // Only the final per-project files (`<hash>.json`); skip an in-flight or crash-left
        // temp sibling (`.<hash>.json.tmp.<pid>`, whose extension is the pid, not "json"),
        // which could otherwise be parsed as a duplicate/stale entry by the disable sweep.
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .filter_map(|p| {
            let entry: RegistryEntry = serde_json::from_slice(&std::fs::read(&p).ok()?).ok()?;
            // Same collision/tamper guard `registry_get` applies on the read path: trust the
            // entry only if its filename is `blake3(root).json`, so the sweep never acts on a
            // mismatched or wrong-named (duplicated/hand-copied) record — it disables exactly the
            // projects that were legitimately recorded here, not whatever a stray file claims.
            let expected = format!("{}.json", blake3::hash(entry.root.as_bytes()).to_hex());
            (p.file_name().and_then(|n| n.to_str()) == Some(expected.as_str())).then_some(entry)
        })
        .filter(|e| e.state == PlumbState::Plumbed)
        .map(|e| e.root)
        .collect()
}

// ---------------------------------------------------------------------------
// Per-project rendezvous (OS-assigned ephemeral ports)
// ---------------------------------------------------------------------------
//
// This record is keyed by PROJECT IDENTITY (`blake3(canonical_root)`): the proxy binds
// an OS-assigned ephemeral port (`127.0.0.1:0`) and PUBLISHES the port it actually got,
// while consumers look it up by their OWN project root — never by a shared port. That
// keying has no hash-collision surface AND structurally prevents a cross-project
// ownership bug (a consumer can only ever read its own record).
//
// The proxy is the sole authority on its port; the hook LEARNS the bound port
// from the rendezvous after launch (it never passes one). A per-launch `nonce`
// (hook→proxy via `ZLAUDER_LAUNCH_NONCE`, echoed on `/healthz`) lets the launcher
// trust only the instance IT spawned, so a stale/crashed/static-conflict record
// can't be mistaken for the live proxy. Authoritative liveness is a `/healthz`
// build-id round-trip layered in the hook (this crate has no HTTP client); the
// `pid` here is only a cheap negative pre-filter.

/// Project-identity key: `blake3(canonical_root).hex`. The single hashing
/// contract — only Rust computes it (shell scripts never hash a path), and the
/// hook passes the already-canonical root to the proxy, which uses it verbatim,
/// so both sides name the same file.
pub fn project_key(canonical_root: &str) -> String {
    blake3::hash(canonical_root.as_bytes()).to_hex().to_string()
}

/// Project-identity-keyed live-proxy rendezvous record. The bound port lives
/// INSIDE the record (filled by the proxy after it binds). Path:
/// `<state_dir>/proxy/<project_key>.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rendezvous {
    /// Absolute canonical project root this proxy serves. Verified on read
    /// (collision/tamper guard, like [`RegistryEntry::root`]).
    pub project_root: String,
    /// The bound port. `0` ⇒ launching, not bound yet.
    pub port: u16,
    /// Hex of the proxy's control token (`x-zlauder-key`). FRESHLY MINTED by the
    /// proxy each launch — never read back from disk into a new proxy — so a
    /// tampered file can't inject attacker-controlled auth material.
    pub admin_key: String,
    /// Hex of the token salt; reused across restarts (prompt-cache stability)
    /// ONLY when the prior record passed [`read_rendezvous`] validation, else fresh.
    #[serde(default)]
    pub salt: String,
    pub base_url: String,
    /// PID of the live proxy, or `0` for a not-yet-bound record.
    pub pid: u32,
    /// Bind address (recorded so consumers/doctor know it; `127.0.0.1` by default).
    #[serde(default)]
    pub bind: String,
    /// The last port this project bound — the sticky seed a relaunch tries first
    /// (falling back to `:0` if taken), so the port stays stable across restarts.
    #[serde(default)]
    pub last_port: u16,
    /// The proxy's [`BUILD_ID`] — lets a later session recycle a stale-build proxy.
    #[serde(default)]
    pub build_id: String,
    /// Proxy start time (unix secs). Freshness signal independent of PID reuse.
    #[serde(default)]
    pub started_unix: u64,
    /// Per-launch random token. The launcher trusts a record only when this
    /// matches the nonce it handed the proxy via `ZLAUDER_LAUNCH_NONCE`.
    #[serde(default)]
    pub nonce: String,
}

/// Directory holding per-project rendezvous records: `<state_dir>/proxy/`.
pub fn rendezvous_dir() -> Result<PathBuf> {
    let dir = state_dir()?.join("proxy");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating rendezvous dir {dir:?}"))?;
    set_mode(&dir, 0o700);
    Ok(dir)
}

/// Path to `project_root`'s rendezvous record (`<state_dir>/proxy/<project_key>.json`).
pub fn rendezvous_path(project_root: &str) -> Result<PathBuf> {
    Ok(rendezvous_dir()?.join(format!("{}.json", project_key(project_root))))
}

/// On Unix, is `path` owner-only (no group/other access) AND owned by us? The
/// rendezvous holds the admin key, so a record that anyone else could have
/// written/read is not trustworthy. No-op `true` off Unix (where confidentiality
/// rests on the per-user `%LOCALAPPDATA%` dir, same posture as the legacy state file).
///
/// This `metadata` and the subsequent `read` in [`read_rendezvous`] are two syscalls
/// that both follow symlinks, so there is a small TOCTOU window. It is bounded: the
/// enclosing `proxy/` and `state_dir` are `0700`/per-user, so only the SAME euid could
/// swap the file — and a same-euid actor already wins by writing a valid record (and the
/// `admin_key` is freshly minted per launch regardless). Acceptable for the local-only
/// threat model; noted for candor.
#[cfg(unix)]
fn owner_only_readable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::metadata(path) else {
        return false;
    };
    (md.mode() & 0o077) == 0 && md.uid() == unsafe { libc::geteuid() }
}
#[cfg(not(unix))]
fn owner_only_readable(_path: &Path) -> bool {
    true
}

/// Read + VALIDATE `project_root`'s rendezvous record. Returns `None` (treat as
/// absent) unless the file parses cleanly, is owner-only on Unix, and stores the
/// matching `project_root`. A failed validation means the proxy mints fresh
/// salt/key rather than trusting a possibly-tampered record.
pub fn read_rendezvous(project_root: &str) -> Option<Rendezvous> {
    let path = rendezvous_path(project_root).ok()?;
    if !owner_only_readable(&path) {
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    let r: Rendezvous = serde_json::from_slice(&bytes).ok()?;
    (r.project_root == project_root).then_some(r)
}

/// Write `r` to its project's rendezvous file (`0600`, atomic temp+rename — a failed
/// write or rename leaves no temp file behind).
pub fn write_rendezvous(r: &Rendezvous) -> Result<()> {
    let path = rendezvous_path(&r.project_root)?;
    let tmp = temp_sibling(&path);
    if let Err(e) = std::fs::write(&tmp, serde_json::to_vec_pretty(r)?) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::from(e).context(format!("writing {tmp:?}")));
    }
    set_mode(&tmp, 0o600);
    if let Err(e) = std::fs::rename(&tmp, &path) {
        // A failed rename leaves the temp behind otherwise (the "no temp leak" invariant).
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::from(e).context(format!("renaming {tmp:?} -> {path:?}")));
    }
    Ok(())
}

/// Remove `project_root`'s rendezvous record (a missing file is not an error).
/// The hook calls this to clear a dead record it owns (by nonce) after a failed
/// launch, so a never-served record can't poison a later adoption attempt.
pub fn rendezvous_remove(project_root: &str) -> Result<()> {
    let path = rendezvous_path(project_root)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing rendezvous record"),
    }
}

/// Remove `project_root`'s rendezvous record ONLY if it is still OURS — both the on-disk
/// `nonce` and `pid` match. A successor proxy that already republished (new nonce/pid)
/// keeps its record; any record we no longer own is left untouched. The proxy calls this
/// on graceful shutdown so a clean stop leaves no stale record behind without ever
/// clobbering a live successor. A missing or foreign record is not an error.
///
/// The check-then-remove is not atomic: a successor that republishes in the sub-millisecond
/// gap between the read and the unlink could have its fresh record removed (we already saw
/// our own record under the guard). The window is bounded by the same single-euid local
/// threat model as [`read_rendezvous`] (only our uid writes here), and the effect is
/// self-healing — a missing record merely triggers the next consumer's normal launch/adopt
/// path, never a security or data loss. Not worth a cross-process lock pre-v1.0.
pub fn rendezvous_remove_if_owned(project_root: &str, nonce: &str, pid: u32) -> Result<()> {
    match read_rendezvous(project_root) {
        Some(r) if r.nonce == nonce && r.pid == pid => rendezvous_remove(project_root),
        _ => Ok(()),
    }
}

/// The project's bound port + record, IF the record names a bound port whose pid
/// is (cheaply) alive. The caller still confirms authoritative liveness with a
/// `/healthz` build-id round-trip — a reused PID that isn't answering our health
/// on that port is then treated as dead, closing the PID-reuse hole cross-platform.
pub fn live_port(project_root: &str) -> Option<(u16, Rendezvous)> {
    let r = read_rendezvous(project_root)?;
    (r.port != 0 && pid_alive(r.pid)).then_some((r.port, r))
}

// --- launch lock (single-launcher-per-project) ---------------------------------

/// How long a launch lock may be held before it's considered abandoned (a launcher
/// that died without removing it, or one wedged past any reasonable cold start).
pub const LAUNCH_LOCK_TTL_SECS: u64 = 30;

#[derive(Serialize, Deserialize)]
struct LockBody {
    pid: u32,
    nonce: String,
    started_unix: u64,
}

/// RAII guard for the per-project launch lock. Dropping it removes the lock file,
/// so the winner must hold it until the proxy has published a healthy, nonce-matching
/// record (or the launch has failed) — otherwise a sibling could win and double-launch.
pub struct LaunchLock {
    path: PathBuf,
    /// This guard's identity. Drop removes the file ONLY if it still carries this
    /// nonce — so a guard whose lock was already reclaimed by another launcher (a
    /// stale-TTL takeover while we ran long) never deletes the *successor's* lock.
    nonce: String,
}
impl Drop for LaunchLock {
    fn drop(&mut self) {
        // Identity-checked: only unlink a lock that is STILL ours. Without this,
        // a long-running-then-reclaimed holder would, on exit, delete the lock the
        // reclaiming launcher now owns — letting a third launcher acquire concurrently.
        if read_lock(&self.path).map(|b| b.nonce == self.nonce).unwrap_or(false) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn lock_path(project_root: &str) -> Result<PathBuf> {
    Ok(rendezvous_dir()?.join(format!("{}.lock", project_key(project_root))))
}

fn read_lock(path: &Path) -> Option<LockBody> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Atomically create the lock file via `O_CREAT|O_EXCL` (emulated with `hard_link`,
/// which fails with `AlreadyExists` if the target is present). Returns `false` then.
fn try_create_lock(path: &Path, body: &LockBody) -> Result<bool> {
    let tmp = temp_sibling(path);
    if let Err(e) = std::fs::write(&tmp, serde_json::to_vec(body)?) {
        // Clean up a partially-written temp so a failed create never leaks one.
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::from(e).context(format!("writing {tmp:?}")));
    }
    set_mode(&tmp, 0o600);
    let result = match std::fs::hard_link(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(anyhow::Error::from(e).context(format!("locking {path:?}"))),
    };
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Mint a `LaunchLock` guard for a path we just won.
fn lock_guard(path: &Path, nonce: &str) -> LaunchLock {
    LaunchLock {
        path: path.to_path_buf(),
        nonce: nonce.to_string(),
    }
}

/// Try to become the single launcher for `project_root`. Returns `Some(LaunchLock)`
/// to exactly one caller; `None` if another live launcher holds it. A lock whose
/// holder pid is dead, OR whose age exceeds [`LAUNCH_LOCK_TTL_SECS`] (so a reused
/// holder PID can't pin it forever), is reclaimed.
pub fn try_launch_lock(project_root: &str, pid: u32, nonce: &str) -> Result<Option<LaunchLock>> {
    let path = lock_path(project_root)?;
    let body = LockBody {
        pid,
        nonce: nonce.to_string(),
        started_unix: now_unix(),
    };
    // Fast, uncontended path: no lock file yet.
    if try_create_lock(&path, &body)? {
        return Ok(Some(lock_guard(&path, nonce)));
    }
    // A lock exists. Reclaim only if its holder is dead, or it is past the TTL (so a
    // dead holder's *reused* PID can't pin it forever).
    let Some(existing) = read_lock(&path) else {
        // It vanished between our create attempt and the read — race for it once more.
        return Ok(try_create_lock(&path, &body)?.then(|| lock_guard(&path, nonce)));
    };
    let reclaimable = !pid_alive(existing.pid)
        || now_unix().saturating_sub(existing.started_unix) > LAUNCH_LOCK_TTL_SECS;
    if !reclaimable {
        return Ok(None);
    }
    // Claim the RIGHT to replace the stale lock atomically: rename the exact current
    // file aside. `rename` of a given source path succeeds for exactly ONE racer; any
    // concurrent reclaimer gets `NotFound` and yields. This replaces a racy
    // remove-then-create (under which two reclaimers, or a reclaimer and a fresh
    // acquirer, could each believe they hold the lock).
    let claimed = path.with_file_name(format!(
        "{}.reclaim.{nonce}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("lock")
    ));
    match std::fs::rename(&path, &claimed) {
        Ok(()) => {
            // Best-effort: a crash between the rename and this remove orphans a
            // `<lock>.reclaim.<nonce>` sidecar. Harmless — it is never the lock path,
            // so it can't block acquisition; it is at worst disk clutter in the 0700 dir.
            let _ = std::fs::remove_file(&claimed);
            // We won the reclaim; create our lock exclusively. If a fresh acquirer
            // slipped a create in between, we lose the O_EXCL and yield (no stomp).
            Ok(try_create_lock(&path, &body)?.then(|| lock_guard(&path, nonce)))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None), // another reclaimer won the claim
        Err(e) => Err(anyhow::Error::from(e).context("reclaiming stale launch lock")),
    }
}

/// Current unix time in whole seconds (0 if the clock is before the epoch).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- loopback / bind-error classifiers (pure; unit-tested on any OS) ------------

/// Is `bind` a loopback address (or the name `localhost`)? Non-loopback binds
/// expose the control plane to the network and are refused by the proxy unless
/// explicitly acknowledged.
pub fn is_loopback_bind(bind: &str) -> bool {
    let b = bind.trim();
    if b.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // Tolerate a bracketed IPv6 literal (`[::1]`).
    let b = b
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(b);
    b.parse::<std::net::IpAddr>()
        // `to_canonical` folds an IPv4-mapped IPv6 (`::ffff:127.0.0.1`) back to its v4
        // form so it is recognized as loopback. Errs safe in any case — an unrecognized
        // loopback form is merely *refused* (ack required), never wrongly exposed.
        .map(|ip| ip.to_canonical().is_loopback())
        .unwrap_or(false)
}

/// A classified bind failure, mapped from an OS errno / `io::ErrorKind` so both the
/// proxy (at bind) and the hook (diagnosing a launch failure) render the same
/// actionable cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindFault {
    /// Port already in use (`EADDRINUSE` / `WSAEADDRINUSE`).
    InUse,
    /// Privileged (<1024) or OS-reserved/excluded port (`EACCES` / `WSAEACCES`).
    Permission,
    /// The bind address isn't local to this host (`EADDRNOTAVAIL` / `WSAEADDRNOTAVAIL`).
    AddrNotAvail,
    /// Anything else.
    Other,
}

/// Classify a `TcpListener::bind` error. Matches `io::ErrorKind` first, then falls
/// back to the raw Windows Winsock codes (which surface as `Uncategorized`).
pub fn classify_bind_error(raw_os: Option<i32>, kind: ErrorKind) -> BindFault {
    match kind {
        ErrorKind::AddrInUse => BindFault::InUse,
        ErrorKind::PermissionDenied => BindFault::Permission,
        ErrorKind::AddrNotAvailable => BindFault::AddrNotAvail,
        _ => match raw_os {
            Some(10048) => BindFault::InUse,        // WSAEADDRINUSE
            Some(10013) => BindFault::Permission,   // WSAEACCES
            Some(10049) => BindFault::AddrNotAvail, // WSAEADDRNOTAVAIL
            _ => BindFault::Other,
        },
    }
}

impl BindFault {
    /// A human, actionable message for a failed bind of `port` on `bind`.
    pub fn message(self, port: u16, bind: &str) -> String {
        match self {
            BindFault::InUse => format!(
                "port {port} is already in use — another process (or a stale zlauder proxy) holds it. \
                 Pick a different `[proxy] port` in zlauder.toml, or remove it to use an OS-assigned \
                 ephemeral port (recommended)."
            ),
            BindFault::Permission => format!(
                "binding {bind}:{port} was denied — the port is privileged (<1024) or OS-reserved. \
                 On Windows, Hyper-V/WSL/Docker reserve ranges (`netsh interface ipv4 show \
                 excludedportrange protocol=tcp`); choose a port outside them, or remove `[proxy] \
                 port` to use an ephemeral port (recommended)."
            ),
            BindFault::AddrNotAvail => format!(
                "{bind} is not an address on this machine — use 127.0.0.1 (the default) or a local \
                 interface IP."
            ),
            BindFault::Other => format!("could not bind {bind}:{port}."),
        }
    }
}

/// A SINGLE process-global lock serializing every test that mutates the process-wide
/// `ZLAUDER_STATE_DIR` / `ZLAUDER_USER_CONFIG` env vars. Shared across BOTH test
/// modules below — separate per-module locks would not mutually exclude, so a
/// `rendezvous_tests` case and a `tests` case could race on the env under
/// `--test-threads` and read each other's state dir.
#[cfg(test)]
static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod rendezvous_tests {
    use super::*;

    // The shared env lock (see TEST_ENV_LOCK) — ZLAUDER_STATE_DIR is process-global.
    use super::TEST_ENV_LOCK as ENV_LOCK;

    fn with_state_dir(tag: &str, f: impl FnOnce(&std::path::Path)) {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test guarded by ENV_LOCK.
        unsafe { std::env::set_var("ZLAUDER_STATE_DIR", &dir) };
        f(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("ZLAUDER_STATE_DIR") };
    }

    fn rec(root: &str, port: u16, pid: u32) -> Rendezvous {
        Rendezvous {
            project_root: root.into(),
            port,
            admin_key: "ab".repeat(32),
            salt: "cd".repeat(16),
            base_url: format!("http://127.0.0.1:{port}"),
            pid,
            bind: "127.0.0.1".into(),
            last_port: port,
            build_id: "testbuild".into(),
            started_unix: now_unix(),
            nonce: "nonce-x".into(),
        }
    }

    /// A definitely-dead pid: spawn a trivial child and reap it.
    fn dead_pid() -> u32 {
        let mut c = std::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
            .args(if cfg!(windows) {
                ["/C", "exit 0"]
            } else {
                ["-c", "exit 0"]
            })
            .spawn()
            .expect("spawn throwaway child");
        let pid = c.id();
        let _ = c.wait();
        pid
    }

    #[test]
    fn rendezvous_round_trips_and_guards_root() {
        with_state_dir("rv-rt", |_| {
            assert!(read_rendezvous("/proj/a").is_none());
            write_rendezvous(&rec("/proj/a", 41234, std::process::id())).unwrap();
            let back = read_rendezvous("/proj/a").expect("present");
            assert_eq!(back.port, 41234);
            assert_eq!(back.admin_key, "ab".repeat(32));
            // A different project never reads /proj/a's record (project-keyed lookup).
            assert!(read_rendezvous("/proj/b").is_none());
        });
    }

    #[test]
    fn live_port_requires_bound_and_alive() {
        with_state_dir("rv-live", |_| {
            // Not bound yet (port 0).
            write_rendezvous(&rec("/proj/a", 0, std::process::id())).unwrap();
            assert!(live_port("/proj/a").is_none(), "port 0 is not live");
            // Bound + alive (our own pid).
            write_rendezvous(&rec("/proj/a", 41001, std::process::id())).unwrap();
            assert_eq!(live_port("/proj/a").map(|(p, _)| p), Some(41001));
            // Bound but dead pid → reclaimable.
            write_rendezvous(&rec("/proj/a", 41001, dead_pid())).unwrap();
            assert!(live_port("/proj/a").is_none(), "dead pid is not live");
        });
    }

    #[cfg(unix)]
    #[test]
    fn read_rendezvous_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        with_state_dir("rv-perm", |_| {
            write_rendezvous(&rec("/proj/a", 41002, std::process::id())).unwrap();
            assert!(read_rendezvous("/proj/a").is_some());
            // Loosen perms as a tamper proxy → record is no longer trusted.
            let p = rendezvous_path("/proj/a").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                read_rendezvous("/proj/a").is_none(),
                "a non-owner-only record must be rejected"
            );
        });
    }

    #[test]
    fn launch_lock_admits_one_then_reclaims_dead() {
        with_state_dir("rv-lock", |_| {
            let g = try_launch_lock("/proj/a", std::process::id(), "n1").unwrap();
            assert!(g.is_some(), "first caller wins the lock");
            // A live holder blocks a second caller.
            assert!(
                try_launch_lock("/proj/a", std::process::id(), "n2")
                    .unwrap()
                    .is_none(),
                "live holder blocks a second launcher"
            );
            drop(g); // releases the lock
            // After release, a fresh caller wins again.
            assert!(try_launch_lock("/proj/a", std::process::id(), "n3").unwrap().is_some());
        });
    }

    #[test]
    fn launch_lock_reclaims_dead_holder() {
        with_state_dir("rv-lock-dead", |_| {
            // Hand-write a lock owned by a dead pid; a new caller must reclaim it.
            let path = lock_path("/proj/a").unwrap();
            let body = LockBody {
                pid: dead_pid(),
                nonce: "old".into(),
                started_unix: now_unix(),
            };
            std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
            assert!(
                try_launch_lock("/proj/a", std::process::id(), "new")
                    .unwrap()
                    .is_some(),
                "a dead holder's lock is reclaimable"
            );
        });
    }

    #[test]
    fn launch_lock_reclaims_stale_holder() {
        with_state_dir("rv-lock-stale", |_| {
            // Live holder (our pid) but ancient started_unix → stale, reclaimable.
            let path = lock_path("/proj/a").unwrap();
            let body = LockBody {
                pid: std::process::id(),
                nonce: "old".into(),
                started_unix: 0,
            };
            std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
            assert!(
                try_launch_lock("/proj/a", std::process::id(), "new")
                    .unwrap()
                    .is_some(),
                "a lock older than the TTL is reclaimable even if the pid is alive"
            );
        });
    }

    // The HIGH from the Phase-1 paired review: a long-running holder that got
    // reclaimed (its lock taken over via the stale-TTL path) must NOT, on its own
    // eventual drop, delete the SUCCESSOR's lock — else a third launcher could acquire
    // while the successor still holds. Identity-checked Drop prevents the stomp.
    #[test]
    fn reclaimed_holder_drop_does_not_stomp_successor() {
        with_state_dir("rv-lock-stomp", |_| {
            // A stale lock recorded with a LIVE pid (ours) but an ancient start → the
            // exact reclaimable-while-alive condition that makes the drop race possible.
            let path = lock_path("/proj/a").unwrap();
            std::fs::write(
                &path,
                serde_json::to_vec(&LockBody {
                    pid: std::process::id(),
                    nonce: "A".into(),
                    started_unix: 0,
                })
                .unwrap(),
            )
            .unwrap();

            // B reclaims and now owns the on-disk lock.
            let b = try_launch_lock("/proj/a", std::process::id(), "B").unwrap();
            assert!(b.is_some(), "B reclaims the stale lock");
            assert_eq!(read_lock(&path).unwrap().nonce, "B");
            // The happy-path reclaim leaves no `.reclaim.*` sidecar behind (guards the
            // leak-test blind spot the paired review flagged).
            let sidecars: Vec<_> = std::fs::read_dir(rendezvous_dir().unwrap())
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".reclaim."))
                .collect();
            assert!(sidecars.is_empty(), "reclaim sidecar leaked: {sidecars:?}");

            // Simulate the original holder A's guard dropping AFTER the reclaim.
            drop(lock_guard(&path, "A"));

            // B's lock survives — A's identity-checked drop is a no-op on B's file.
            assert_eq!(
                read_lock(&path).map(|l| l.nonce),
                Some("B".to_string()),
                "A's drop must not stomp B's reclaimed lock"
            );
            // And a fresh launcher still cannot acquire while B holds (alive + fresh).
            assert!(
                try_launch_lock("/proj/a", std::process::id(), "C")
                    .unwrap()
                    .is_none(),
                "C must not acquire while B holds"
            );
            drop(b);
            // After B releases, the lock file is gone and C can win.
            assert!(read_lock(&path).is_none(), "B's release removed its own lock");
        });
    }

    #[test]
    fn is_loopback_bind_table() {
        for s in [
            "127.0.0.1",
            "::1",
            "[::1]",
            "localhost",
            "LOCALHOST",
            "127.5.5.5",
            "::ffff:127.0.0.1", // IPv4-mapped loopback (folded via to_canonical)
        ] {
            assert!(is_loopback_bind(s), "{s} should be loopback");
        }
        for s in ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "example.com"] {
            assert!(!is_loopback_bind(s), "{s} should NOT be loopback");
        }
    }

    #[test]
    fn classify_bind_error_table() {
        assert_eq!(
            classify_bind_error(None, ErrorKind::AddrInUse),
            BindFault::InUse
        );
        assert_eq!(
            classify_bind_error(None, ErrorKind::PermissionDenied),
            BindFault::Permission
        );
        assert_eq!(
            classify_bind_error(None, ErrorKind::AddrNotAvailable),
            BindFault::AddrNotAvail
        );
        // Windows Winsock codes arrive as an "other" kind with a raw os error.
        assert_eq!(
            classify_bind_error(Some(10048), ErrorKind::Other),
            BindFault::InUse
        );
        assert_eq!(
            classify_bind_error(Some(10013), ErrorKind::Other),
            BindFault::Permission
        );
        assert_eq!(classify_bind_error(Some(0), ErrorKind::Other), BindFault::Other);
    }

    #[test]
    fn write_rendezvous_leaves_no_temp() {
        with_state_dir("rv-noleak", |_| {
            write_rendezvous(&rec("/proj/a", 41003, std::process::id())).unwrap();
            write_rendezvous(&rec("/proj/a", 41003, std::process::id())).unwrap();
            let dir = rendezvous_dir().unwrap();
            let leaked: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".tmp."))
                .collect();
            assert!(leaked.is_empty(), "temp files leaked: {leaked:?}");
        });
    }

    #[test]
    fn rendezvous_remove_if_owned_respects_identity() {
        with_state_dir("rv-rmown", |_| {
            // A record we own (matching nonce + pid) is removed.
            let mut r = rec("/proj/a", 41010, std::process::id());
            r.nonce = "mine".into();
            write_rendezvous(&r).unwrap();
            rendezvous_remove_if_owned("/proj/a", "mine", std::process::id()).unwrap();
            assert!(read_rendezvous("/proj/a").is_none(), "our own record is cleared");

            // A successor's record (different nonce) is left untouched.
            let mut s = rec("/proj/a", 41011, std::process::id());
            s.nonce = "successor".into();
            write_rendezvous(&s).unwrap();
            rendezvous_remove_if_owned("/proj/a", "mine", std::process::id()).unwrap();
            assert!(
                read_rendezvous("/proj/a").is_some(),
                "a record owned by a successor (different nonce) must survive"
            );

            // A pid mismatch (right nonce, foreign pid) is also left untouched.
            rendezvous_remove_if_owned("/proj/a", "successor", 0x7FFF_FFFE).unwrap();
            assert!(
                read_rendezvous("/proj/a").is_some(),
                "a pid mismatch must not remove the record"
            );

            // Removing a non-existent record is not an error.
            rendezvous_remove_if_owned("/proj/none", "x", std::process::id()).unwrap();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shared env lock (see TEST_ENV_LOCK): ZLAUDER_STATE_DIR/ZLAUDER_USER_CONFIG are
    // process-global, so ALL env-mutating tests across both modules serialize on ONE lock.
    use super::TEST_ENV_LOCK as ENV_LOCK;

    // The plumbed-projects registry round-trips state, filters Plumbed for the sweep, and
    // honors an opt-out so a disabled project is never auto-re-plumbed.
    #[test]
    fn registry_round_trips_and_filters_plumbed() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test; points the registry at a temp config dir.
        unsafe { std::env::set_var("ZLAUDER_USER_CONFIG", dir.join("config.toml")) };

        assert_eq!(registry_get("/proj/a"), None);
        registry_set("/proj/a", PlumbState::Plumbed).unwrap();
        registry_set("/proj/b", PlumbState::Optout).unwrap();
        assert_eq!(registry_get("/proj/a"), Some(PlumbState::Plumbed));
        assert_eq!(registry_get("/proj/b"), Some(PlumbState::Optout));

        // Only Plumbed roots are swept; an opted-out project is excluded.
        assert_eq!(registry_plumbed_roots(), vec!["/proj/a".to_string()]);

        // Re-enabling clears a prior opt-out.
        registry_set("/proj/b", PlumbState::Plumbed).unwrap();
        let mut roots = registry_plumbed_roots();
        roots.sort();
        assert_eq!(roots, vec!["/proj/a".to_string(), "/proj/b".to_string()]);

        registry_remove("/proj/a").unwrap();
        assert_eq!(registry_get("/proj/a"), None);

        // A wrong-named (`<hash>` != blake3(root)) registry file is NOT swept: registry_get's
        // filename guard also applies to registry_plumbed_roots, so a mismatched/hand-copied
        // record can't inject a foreign root into the disable sweep.
        let stray = registry_dir().join("deadbeef.json");
        std::fs::write(&stray, br#"{"root":"/proj/stray","state":"plumbed"}"#).unwrap();
        assert!(
            !registry_plumbed_roots().contains(&"/proj/stray".to_string()),
            "a record whose filename != blake3(root) must be ignored by the sweep"
        );

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("ZLAUDER_USER_CONFIG") };
    }
}
