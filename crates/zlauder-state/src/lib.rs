//! Shared on-disk session state for zlauder.
//!
//! `zlauder-proxy` and `zlauder-hooks` both need to agree on, per project, the
//! proxy's port, its admin key (the `x-zlauder-key` for the audit/control
//! endpoints), the token salt, and its pid. This crate is the single owner of
//! that file format and its location so the two binaries can't drift.
//!
//! ## Per-project isolation
//!
//! Each project gets its own proxy on a project-derived port ([`derive_port`]),
//! hence its own key, salt, store, and config. State files are keyed by port
//! (`proxy-<port>.json`), so two `claude` windows in the same project share one
//! file (and one proxy), while different projects never collide.
//!
//! ## Who writes it
//!
//! The **bound proxy** is the authoritative writer: it writes its real key after
//! it successfully binds the port, so the file always matches the live proxy even
//! if two sessions race to launch (the loser fails to bind and never writes).
//! The hooks only *read* it (to reuse the key+salt across a proxy restart, which
//! keeps tokens — and Anthropic's prompt-cache prefix — stable).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Lowest port used by the per-project derivation.
pub const PORT_BASE: u16 = 18000;
/// Number of ports in the derivation window (`PORT_BASE..PORT_BASE+PORT_SPAN`).
pub const PORT_SPAN: u16 = 2000;

/// On-disk record describing one running (or last-known) per-project proxy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyState {
    pub port: u16,
    /// Hex of the proxy's session key. Required (via `x-zlauder-key`) to call the
    /// reveal/config control endpoints, so they are not a trivial oracle for a
    /// tool-driven `curl`.
    pub admin_key: String,
    /// Hex of the token salt; reused across proxy restarts on this port so tokens
    /// (and the prompt-cache prefix) stay stable mid-session.
    #[serde(default)]
    pub salt: String,
    pub base_url: String,
    pub pid: u32,
    /// Absolute project root this proxy serves (so a port collision between two
    /// different projects is detectable).
    #[serde(default)]
    pub project_root: String,
}

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
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("zlauder").join("config.toml")
}

/// Deterministically map a (canonical) project root to a port in the derivation
/// window. Same path → same port (so repeat sessions and sibling windows share a
/// proxy); different paths → almost-always different ports. Collisions are rare
/// and resolved at `init` time by probing upward.
pub fn derive_port(project_root: &str) -> u16 {
    let h = blake3::hash(project_root.as_bytes());
    let b = h.as_bytes();
    let n = u16::from_le_bytes([b[0], b[1]]);
    PORT_BASE + (n % PORT_SPAN)
}

/// Root directory for zlauder state files (created `0700`).
///
/// `ZLAUDER_STATE_DIR` wins; else `$XDG_RUNTIME_DIR/zlauder`; else a temp dir.
pub fn state_dir() -> Result<PathBuf> {
    let base = std::env::var_os("ZLAUDER_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("zlauder")))
        .unwrap_or_else(|| std::env::temp_dir().join("zlauder"));
    std::fs::create_dir_all(&base).with_context(|| format!("creating state dir {base:?}"))?;
    set_mode(&base, 0o700);
    Ok(base)
}

/// Path to the state file for `port` (`<state_dir>/proxy-<port>.json`).
pub fn state_path(port: u16) -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("proxy-{port}.json")))
}

/// Read the state file for `port`.
pub fn read_state(port: u16) -> Result<ProxyState> {
    let path = state_path(port)?;
    let bytes = std::fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Read the state file for `port`, returning `None` if it doesn't exist or is
/// unparseable (rather than erroring).
pub fn read_state_opt(port: u16) -> Option<ProxyState> {
    read_state(port).ok()
}

/// Resolve the port a project should use: its [`derive_port`] value, probed upward
/// past any port currently recorded as owned by a *different* project. Stable for a
/// given project. This is the single source of truth for "what port does project X
/// get" — both `init` (which persists the result into `settings.json`) and the
/// `session-start` fallback call it, so they can't diverge into a split-brain port.
pub fn pick_port(project_root: &str) -> u16 {
    let start = derive_port(project_root);
    for off in 0..PORT_SPAN {
        let p = PORT_BASE + ((start - PORT_BASE + off) % PORT_SPAN);
        match read_state_opt(p) {
            // Owned by a *different* project → keep looking.
            Some(st) if !st.project_root.is_empty() && st.project_root != project_root => continue,
            _ => return p,
        }
    }
    start
}

/// Write `state` to its port's state file (`0600`).
pub fn write_state(state: &ProxyState) -> Result<()> {
    let path = state_path(state.port)?;
    std::fs::write(&path, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("writing {path:?}"))?;
    set_mode(&path, 0o600);
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_port_is_deterministic_and_in_range() {
        let a = derive_port("/home/me/projects/alpha");
        let b = derive_port("/home/me/projects/alpha");
        let c = derive_port("/home/me/projects/beta");
        assert_eq!(a, b, "same path => same port");
        assert!((PORT_BASE..PORT_BASE + PORT_SPAN).contains(&a));
        assert!((PORT_BASE..PORT_BASE + PORT_SPAN).contains(&c));
        // Not a hard guarantee, but these two distinct paths must not collide or
        // the isolation premise is silently broken for the test fixtures.
        assert_ne!(a, c, "distinct paths collided in-range");
    }

    #[test]
    fn state_round_trips() {
        let dir = std::env::temp_dir().join(format!("zlauder-test-{}", std::process::id()));
        // SAFETY: single-threaded test; sets a process-local override only.
        unsafe { std::env::set_var("ZLAUDER_STATE_DIR", &dir) };
        let st = ProxyState {
            port: 18042,
            admin_key: "ab".repeat(32),
            salt: "cd".repeat(16),
            base_url: "https://api.anthropic.com".into(),
            pid: 4242,
            project_root: "/home/me/projects/alpha".into(),
        };
        write_state(&st).unwrap();
        let back = read_state(18042).unwrap();
        assert_eq!(back.admin_key, st.admin_key);
        assert_eq!(back.salt, st.salt);
        assert_eq!(back.project_root, st.project_root);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
