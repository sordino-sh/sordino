//! Shared proxy state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zlauder_engine::MaskEngine;

use crate::config::ConfigLayers;
use crate::monitor::Monitor;
use crate::secrets::SecretsStatus;

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
