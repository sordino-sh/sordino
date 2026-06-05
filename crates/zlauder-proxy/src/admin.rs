//! `/privacy` control plane: key-gated endpoints that read and hot-swap the live
//! masking policy on *this* (per-project) proxy.
//!
//! Every endpoint requires the `x-zlauder-key` header — a control token derived
//! from (but not revealing) the AES session key, read from the 0600 state file;
//! the same gate as `reveal`. That stops a blind, tool-driven
//! `curl 127.0.0.1:PORT/zlauder/disable` (e.g. via prompt injection) from silently
//! turning masking off, while keeping the encryption key off disk (reading the
//! state file grants control, not offline decryption). It does NOT defend against
//! a model that already has full shell access and can run the trusted CLI — that's
//! the documented shell-access threat tier, out of scope.
//!
//! Because each project has its own proxy, a change here is scoped to this project
//! only; concurrent sessions in other projects are untouched.

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::Response;
use http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zlauder_engine::{AllowList, EngineConfig};

use crate::config;
use crate::state::AppState;

/// Allow-list in its raw, serializable form (the live [`AllowList`] holds compiled
/// `regex::Regex`, which isn't `Serialize`; we round-trip via the source strings).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WireAllowList {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub exact_ci: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl From<&AllowList> for WireAllowList {
    fn from(a: &AllowList) -> Self {
        let mut exact: Vec<String> = a.exact.iter().cloned().collect();
        let mut exact_ci: Vec<String> = a.exact_ci.iter().cloned().collect();
        exact.sort();
        exact_ci.sort();
        let patterns = a.patterns.iter().map(|r| r.as_str().to_string()).collect();
        Self {
            exact,
            exact_ci,
            patterns,
        }
    }
}

impl WireAllowList {
    fn build(self) -> Result<AllowList, String> {
        AllowList::from_specs(self.exact, self.exact_ci, self.patterns).map_err(|e| e.to_string())
    }
}

/// Wire form of [`EngineConfig`]: all of its serializable fields (flattened) plus
/// the allow-list as raw specs (which `EngineConfig` itself skips).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireConfig {
    #[serde(flatten)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub allow_list: WireAllowList,
}

impl WireConfig {
    pub fn from_engine(cfg: &EngineConfig) -> Self {
        let allow_list = WireAllowList::from(&cfg.allow_list);
        Self {
            engine: cfg.clone(),
            allow_list,
        }
    }

    pub fn into_engine(self) -> Result<EngineConfig, String> {
        let mut engine = self.engine;
        engine.allow_list = self.allow_list.build()?;
        Ok(engine)
    }
}

/// `{ enabled, project_root, port, token_count, config }` — the full live state.
fn snapshot(st: &AppState) -> serde_json::Value {
    let cfg = st.engine.config_snapshot();
    let wire = WireConfig::from_engine(&cfg);
    json!({
        "enabled": cfg.enabled,
        "project_root": st.project_root.as_str(),
        "port": st.port,
        "token_count": st.engine.token_count(),
        "config": wire,
    })
}

/// `GET /zlauder/config` — current effective config + live state.
pub async fn get_config(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    json_ok(&snapshot(&st))
}

/// `PUT /zlauder/config` — replace the live engine config with the posted one.
pub async fn put_config(State(st): State<AppState>, hdrs: HeaderMap, body: Bytes) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    let wire: WireConfig = match serde_json::from_slice(&body) {
        Ok(w) => w,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid config JSON: {e}"),
            );
        }
    };
    let engine_cfg = match wire.into_engine() {
        Ok(c) => c,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid allow_list regex: {e}"),
            );
        }
    };
    if !(0.0..=1.0).contains(&engine_cfg.score_threshold) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!(
                "score_threshold {} out of range 0.0..=1.0",
                engine_cfg.score_threshold
            ),
        );
    }
    if let Err(e) = st.engine.set_config(engine_cfg) {
        return text(StatusCode::BAD_REQUEST, &format!("config rejected: {e}"));
    }
    json_ok(&snapshot(&st))
}

/// `POST /zlauder/enable` — flip the master switch on.
pub async fn enable(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    set_enabled(&st, &hdrs, true)
}

/// `POST /zlauder/disable` — flip the master switch off (transparent passthrough).
pub async fn disable(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    set_enabled(&st, &hdrs, false)
}

fn set_enabled(st: &AppState, hdrs: &HeaderMap, on: bool) -> Response {
    if !st.authed(hdrs) {
        return forbidden();
    }
    st.engine.set_enabled(on);
    json_ok(&snapshot(st))
}

/// `POST /zlauder/reload` — re-read the per-scope config files and hot-swap.
pub async fn reload(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    let mut cfg = match config::reload_engine(&st.layers) {
        Ok(c) => c,
        Err(e) => {
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("reload failed: {e}"),
            );
        }
    };
    // The master switch is "live"-owned: a file reload (e.g. triggered by an
    // unrelated `profile`/`category` edit) must NOT silently flip masking on/off.
    // Only the explicit enable/disable endpoints change it; the file's `enabled`
    // value applies on a cold start (when the proxy reads the files fresh).
    cfg.enabled = st.engine.is_enabled();
    if let Err(e) = st.engine.set_config(cfg) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("reloaded config rejected: {e}"),
        );
    }
    json_ok(&snapshot(&st))
}

// --- small response helpers (mirrors routes.rs style) -----------------------

fn json_ok(v: &serde_json::Value) -> Response {
    let body = serde_json::to_vec(v).unwrap_or_default();
    let mut r = Response::new(Body::from(body));
    r.headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

fn forbidden() -> Response {
    text(StatusCode::FORBIDDEN, "missing or invalid x-zlauder-key")
}

fn text(status: StatusCode, msg: &str) -> Response {
    let mut r = Response::new(Body::from(msg.to_string()));
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    // The allow-list is carried as a sibling field (`EngineConfig.allow_list` is
    // `#[serde(skip)]`, so the flattened struct never emits/reads it). Pin that
    // invariant: a GET-then-PUT round-trip must preserve a custom allow-list value,
    // and PUT must take the allow-list from the sibling, not the (skipped) flatten.
    #[test]
    fn wireconfig_round_trips_allow_list_via_sibling() {
        let mut cfg = EngineConfig::default();
        cfg.allow_list.add_exact("keep-me@example.com");

        // Serialize as the GET endpoint does.
        let wire = WireConfig::from_engine(&cfg);
        let json = serde_json::to_value(&wire).unwrap();
        assert!(
            json["allow_list"]["exact"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "keep-me@example.com"),
            "custom allow-list entry must appear in the sibling, got {json}"
        );
        // The flattened EngineConfig must NOT carry an `allow_list` key (it's skipped).
        assert!(json.get("allow_list").is_some());
        assert!(
            json.as_object()
                .unwrap()
                .keys()
                .filter(|k| *k == "allow_list")
                .count()
                == 1,
            "exactly one allow_list key (the sibling)"
        );

        // Deserialize as PUT does, rebuild the engine config, and confirm the value
        // survived the compiled-Regex → specs → recompiled-Regex trip.
        let back: WireConfig = serde_json::from_value(json).unwrap();
        let rebuilt = back.into_engine().expect("valid allow-list");
        assert!(rebuilt.allow_list.is_allowed("keep-me@example.com"));
        // Common-word defaults are re-seeded by from_specs (idempotent).
        assert!(rebuilt.allow_list.is_allowed("Anthropic"));
    }
}
