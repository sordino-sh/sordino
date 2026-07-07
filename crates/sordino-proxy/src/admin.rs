//! `/privacy` control plane: key-gated endpoints that read and hot-swap the live
//! masking policy on *this* (per-project) proxy.
//!
//! Every endpoint requires the `x-sordino-key` header — a control token derived
//! from (but not revealing) the AES session key, read from the 0600 state file;
//! the same gate as `reveal`. That stops a blind, tool-driven
//! `curl 127.0.0.1:PORT/sordino/disable` (e.g. via prompt injection) from silently
//! turning masking off, while keeping the encryption key off disk (reading the
//! state file grants control, not offline decryption). It does NOT defend against
//! a model that already has full shell access and can run the trusted CLI — that's
//! the documented shell-access threat tier, out of scope.
//!
//! Because each project has its own proxy, a change here is scoped to this project
//! only; concurrent sessions in other projects are untouched.

use std::collections::HashMap;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::response::Response;
use http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sordino_engine::{AllowList, BrokerPolicy, EngineConfig, MlStatus, Profile};

use crate::config;
use crate::ml::reconcile_ml;
use crate::monitor;
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

/// `{ enabled, project_root, port, token_count, config, ml }` — the full live
/// state. `ml.enabled` is the desired flag; `ml.status` is the live runtime
/// lifecycle (`disabled`/`loading`/`ready`/`failed`) — the latter is what tells
/// the user whether their text is actually being filtered through the model yet.
pub(crate) fn snapshot(st: &AppState) -> serde_json::Value {
    let cfg = st.engine.config_snapshot();
    let wire = WireConfig::from_engine(&cfg);
    let ml = st.engine.ml_snapshot();
    // Registered-secret status: counts/names/operators/scheme/resolved/required +
    // any error — NEVER a value (SecretRuntimeEntry has no value field, and the
    // engine config WireConfig above carries no secret either).
    // Recover a poisoned read guard rather than panic the snapshot handler — the
    // status is value-free, so a degraded read is safe and keeps the endpoint up.
    let secrets = st
        .secrets_status
        .read()
        .unwrap_or_else(|p| p.into_inner());
    json!({
        "enabled": cfg.enabled,
        "project_root": st.project_root.as_str(),
        "port": st.port,
        "token_count": st.engine.token_count(),
        "config": wire,
        "ml": {
            "enabled": cfg.ml.enabled,
            // Effective policy (resolves the http default), so the status line and
            // any client see the TRUE refusal behavior, not the unset three-state.
            "required": cfg.ml.required_effective(),
            "backend": cfg.ml.backend,
            "model": cfg.ml.model,
            "endpoint": cfg.ml.endpoint,
            "status": ml.status,
            "error": ml.error,
            // Post-`Ready` recognizer failures: requests are refused while status
            // stays `ready`, so operators can see endpoint flaps.
            "last_runtime_error": ml.last_runtime_error,
            "runtime_failures": ml.runtime_failures,
        },
        "secrets": {
            "ready": st.secrets_ready(),
            "total": secrets.entries.len(),
            "resolved": secrets.resolved(),
            "required": secrets.required(),
            "entries": secrets.entries,
        },
        "zdr": zdr_block(st),
        // Conversations with masking turned OFF (the per-conversation switch). Local
        // session ids only — never any value. Empty on the common all-masked path.
        "masking_disabled_conversations": st.masking_disabled_active(),
    })
}

/// The `zdr` block of the snapshot: configured targets (value-free views — NEVER a
/// credential), the default target, and the currently-active sessions
/// `[{conversation, config}]`. The statusline reads `active` to decide whether to
/// show its (per-session) ZDR segment.
fn zdr_block(st: &AppState) -> serde_json::Value {
    let configured: Vec<_> = st.zdr_targets.values().map(|t| t.view()).collect();
    let active: Vec<serde_json::Value> = st
        .zdr_active()
        .into_iter()
        .map(|(conversation, config)| json!({ "conversation": conversation, "config": config }))
        .collect();
    json!({
        "configured": configured,
        "default": st.zdr_default.as_ref(),
        "active": active,
    })
}

/// Broadcast the live policy to monitor subscribers after a config mutation, tagging it
/// with the caller's `x-sordino-write-id` (if the request carried one). The ORIGINATING
/// browser tab recognizes its own echo by that id and suppresses its redundant
/// "policy changed" toast (it already toasted the specific change); OTHER tabs and the
/// CLI (no matching id) treat the frame as a genuine external change and DO toast. This
/// makes external-change notification precise even when it races a local write in flight.
pub(crate) fn push_policy(st: &AppState, hdrs: &HeaderMap, snap: &serde_json::Value) {
    let mut tagged = snap.clone();
    if let Some(wid) = hdrs.get("x-sordino-write-id").and_then(|v| v.to_str().ok()) {
        if let Some(obj) = tagged.as_object_mut() {
            obj.insert("write_id".into(), json!(wid));
        }
    }
    st.monitor.broadcast_policy(tagged);
}

/// `GET /sordino/config` — current effective config + live state.
pub async fn get_config(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    json_ok(&snapshot(&st))
}

/// Deep-merge `over` onto `base` (both `serde_json::Value`): objects recurse
/// key-by-key; every other value (including arrays) replaces wholesale. A `null` in
/// `over` overwrites with `null` (callers don't send nulls; this keeps the merge a
/// pure overlay). This is what turns `PUT /sordino/config` into a real partial
/// merge: only the keys the client actually sent overlay the current config, so an
/// omitted field is preserved instead of being reset to its serde default.
fn merge_json(base: &mut serde_json::Value, over: serde_json::Value) {
    match (base, over) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(bv) => merge_json(bv, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

/// `PUT /sordino/config` — MERGE the posted (partial) config onto the live config.
/// Only the keys present in the request body overlay the current effective config;
/// every omitted field is preserved (a real merge, not a whole-object replace that
/// resets omitted fields to serde defaults).
pub async fn put_config(State(st): State<AppState>, hdrs: HeaderMap, body: Bytes) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    // Parse the body as a raw JSON object so we can tell which keys were actually
    // sent. A non-object body is the only hard parse error here.
    let over: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        Ok(_) => {
            return text(StatusCode::BAD_REQUEST, "config body must be a JSON object");
        }
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid config JSON: {e}"),
            );
        }
    };
    // Serialize the whole config read-modify-write against every other control-plane
    // writer (custom-mask, reveal, profile, ml). Lock order is config_control THEN
    // ml_control (acquired below) — fixed everywhere to avoid deadlock.
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    // Start from the live config in its wire form, overlay only the sent keys, then
    // deserialize the merged whole.
    let current = WireConfig::from_engine(&st.engine.config_snapshot());
    let mut merged = match serde_json::to_value(&current) {
        Ok(v) => v,
        Err(e) => {
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("serializing current config: {e}"),
            );
        }
    };
    merge_json(&mut merged, over);

    let wire: WireConfig = match serde_json::from_value(merged) {
        Ok(w) => w,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid merged config: {e}"),
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
    // Reject typo'd / alias / unknown entity_operators keys so a misspelled key
    // stops being a silent no-op (item 2c). A custom_replacement.entity_type is its
    // own detector and is never a no-op, so it is intentionally not validated here.
    //
    // Validate ONLY the DELTA this PUT introduces, not the whole merged config: a
    // stale unknown key already in the live snapshot (the file loader only WARNS, it
    // doesn't strip) would otherwise brick EVERY future merge-PUT — including an
    // unrelated request that only lowers the threshold or enables a category — locking
    // the operator out of TIGHTENING policy through the UI/CLI. We flag a key only if
    // it is unknown AND it is genuinely new or changed relative to the current snapshot
    // (`current_engine.entity_operators`). Pre-existing typo'd keys carry forward
    // untouched (they were already warned about at file load), but they can no longer
    // poison an unrelated edit.
    let current_engine = st.engine.config_snapshot();
    let new_unknown = new_unknown_entity_keys(&current_engine, &engine_cfg);
    if !new_unknown.is_empty() {
        return text(
            StatusCode::BAD_REQUEST,
            &format!(
                "unknown entity type(s) {:?} — must be a canonical EntityType Display name \
                 (an alias or typo here masks nothing)",
                new_unknown
            ),
        );
    }
    // `ml.enabled` is live-owned by the dedicated enable/disable endpoints; PUT
    // may change only model params.
    let _ml_guard = st.ml_control.lock().expect("ml_control mutex poisoned");
    let mut engine_cfg = engine_cfg;
    engine_cfg.ml.enabled = st.engine.ml_snapshot().status != MlStatus::Disabled;
    let new_ml = engine_cfg.ml.clone();
    if let Err(e) = st.engine.set_config(engine_cfg) {
        return text(StatusCode::BAD_REQUEST, &format!("config rejected: {e}"));
    }
    reconcile_ml(&st, &new_ml, false);
    let snap = snapshot(&st);
    push_policy(&st, &hdrs, &snap);
    json_ok(&snap)
}

/// `POST /sordino/profile/{name}` — apply a detection profile (threshold +
/// categories + default operator TOGETHER, from [`EngineConfig::for_profile`]) and
/// persist per the `?scope=` query (default `session`). This is the SHARED path the
/// CLI's `apply_profile` also routes through, so the UI and CLI can never drift on
/// what a profile means or how it is persisted.
///
/// `{name}` is the snake_case profile id (`strict`/`balanced`/`minimal`/
/// `secrets_only`, plus the `development_safe` back-compat alias). `?scope` is one
/// of `session|project|user|local`. Live application always happens; a file scope
/// additionally writes the profile's fields to that scope's TOML.
pub async fn apply_profile(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    // Parse the profile id via serde so the `development_safe` alias is honored.
    let profile: Profile = match serde_json::from_value(json!(name)) {
        Ok(p) => p,
        Err(_) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!(
                    "unknown profile '{name}' (valid: strict, balanced, minimal, secrets_only)"
                ),
            );
        }
    };
    let scope = match q.get("scope").map(String::as_str) {
        None | Some("session") => Scope::Session,
        Some("project") => Scope::Project,
        Some("user") => Scope::User,
        Some("local") => Scope::Local,
        Some(other) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("unknown scope '{other}' (valid: session, project, user, local)"),
            );
        }
    };

    // Derive the profile's threshold/categories/operator from the single engine
    // source, then overlay them onto the LIVE config (keeping entity_operators,
    // allow_list, ml, custom rules, etc.). `enabled`/`ml.enabled` stay live-owned.
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let defaults = EngineConfig::for_profile(profile);
    let mut cfg = st.engine.config_snapshot();
    cfg.profile = profile;
    cfg.score_threshold = defaults.score_threshold;
    cfg.enabled_categories = defaults.enabled_categories.clone();
    cfg.default_operator = defaults.default_operator;
    if let Err(e) = st.engine.set_config(cfg) {
        return text(StatusCode::BAD_REQUEST, &format!("config rejected: {e}"));
    }

    // Persist per scope (file scopes only). Best-effort: a write failure leaves the
    // live change in effect and surfaces a session-only signal.
    let (persisted, persist_error) = if scope == Scope::Session {
        (None, None)
    } else {
        match config::persist_profile(&st.layers, &st.project_root, scope, profile) {
            Ok(path) => (Some(path.display().to_string()), None),
            Err(e) => (None, Some(e.to_string())),
        }
    };

    // Push the new live policy to open panels (plain config snapshot, before the
    // action-specific fields below — the panel only reads `config`/`ml`).
    let mut snap = snapshot(&st);
    push_policy(&st, &hdrs, &snap);

    if let Some(obj) = snap.as_object_mut() {
        obj.insert("profile_applied".into(), json!(name));
        obj.insert("scope".into(), json!(scope_label(scope)));
        obj.insert("persisted".into(), json!(persisted));
        obj.insert("session_only".into(), json!(scope == Scope::Session));
        if let Some(e) = persist_error {
            obj.insert("persist_error".into(), json!(e));
        }
    }
    json_ok(&snap)
}

/// The unknown `entity_operators` keys that `merged` INTRODUCES or CHANGES relative
/// to `current` — i.e. the validation delta a merge-PUT is responsible for. A key
/// that is unknown but already present (same value) in `current` is NOT returned: it
/// was carried forward from a previously-loaded file (which only warns on unknown
/// keys), so failing the PUT on it would lock the operator out of tightening policy.
/// Genuinely new or value-changed unknown keys ARE returned (still rejected).
fn new_unknown_entity_keys(current: &EngineConfig, merged: &EngineConfig) -> Vec<String> {
    let unknown: std::collections::HashSet<String> =
        merged.unknown_entity_types().into_iter().collect();
    merged
        .entity_operators
        .iter()
        .filter(|(k, v)| {
            unknown.contains(k.as_str()) && current.entity_operators.get(*k) != Some(*v)
        })
        .map(|(k, _)| k.clone())
        .collect()
}

/// Scope a profile/config write targets. Mirrors the hooks CLI's `Scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Session,
    Project,
    User,
    Local,
}

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::Session => "session",
        Scope::Project => "project",
        Scope::User => "user",
        Scope::Local => "local",
    }
}

/// `POST /sordino/ml/enable` — turn the ML recognizer on. The model loads in the
/// background; masking stays regex-only until it is `Ready`.
pub async fn ml_enable(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    // Serialize against a concurrent enable/disable AND any other config writer.
    // Lock order config_control → ml_control (held only across sync code).
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let _ml_guard = st.ml_control.lock().expect("ml_control mutex poisoned");
    let mut cfg = st.engine.config_snapshot();
    cfg.ml.enabled = true;
    let ml = cfg.ml.clone();
    if let Err(e) = st.engine.set_config(cfg) {
        return text(StatusCode::BAD_REQUEST, &format!("config rejected: {e}"));
    }
    // An explicit enable retries a previously-failed load.
    reconcile_ml(&st, &ml, true);
    let snap = snapshot(&st);
    push_policy(&st, &hdrs, &snap);
    json_ok(&snap)
}

/// `POST /sordino/ml/disable` — turn the ML recognizer off live (drops the model
/// from the detection path immediately; any in-flight load is invalidated).
pub async fn ml_disable(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let _ml_guard = st.ml_control.lock().expect("ml_control mutex poisoned");
    let mut cfg = st.engine.config_snapshot();
    cfg.ml.enabled = false;
    if let Err(e) = st.engine.set_config(cfg) {
        return text(StatusCode::BAD_REQUEST, &format!("config rejected: {e}"));
    }
    st.engine.ml_disable();
    let snap = snapshot(&st);
    push_policy(&st, &hdrs, &snap);
    json_ok(&snap)
}

/// `POST /sordino/enable` — flip the master switch on.
pub async fn enable(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    set_enabled(&st, &hdrs, true)
}

/// `POST /sordino/disable` — flip the master switch off (transparent passthrough).
pub async fn disable(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    set_enabled(&st, &hdrs, false)
}

fn set_enabled(st: &AppState, hdrs: &HeaderMap, on: bool) -> Response {
    if !st.authed_for_project(hdrs) {
        return forbidden();
    }
    // The master switch is config state, so it must compose under `config_control`
    // like every other control-plane writer. Without the lock, a concurrent
    // `reload`/`put`/`profile` (which snapshot `enabled`, then `set_config` the whole
    // config) can read the pre-toggle value and write it back AFTER this toggle —
    // silently losing the operator's intent (e.g. re-disabling masking right after an
    // explicit enable, leaking PII). Held only across the sync toggle + snapshot.
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    st.engine.set_enabled(on);
    json_ok(&snapshot(st))
}

/// `POST /sordino/reload` — re-read the per-scope config files and hot-swap.
pub async fn reload(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    // Serialize the file-reload RMW against live config writers. Lock order
    // config_control → ml_control (acquired below).
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let mut cfg = match config::reload_engine(&st.layers) {
        Ok(c) => c,
        Err(e) => {
            // A failed reload must not leave a stale (possibly permissive) broker
            // policy live — fail closed to default-deny before returning.
            st.engine.set_broker_policy(BrokerPolicy::default());
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
    // `ml.enabled` is live-owned for the same reason — only `/sordino/ml/{enable,
    // disable}` flip it. We still pick up model-param changes from the files below.
    // Serialized against the ml/enable|disable handlers.
    let _ml_guard = st.ml_control.lock().expect("ml_control mutex poisoned");
    cfg.ml.enabled = st.engine.ml_snapshot().status != MlStatus::Disabled;
    let new_ml = cfg.ml.clone();
    if let Err(e) = st.engine.set_config(cfg) {
        st.engine.set_broker_policy(BrokerPolicy::default());
        return text(
            StatusCode::BAD_REQUEST,
            &format!("reloaded config rejected: {e}"),
        );
    }
    // Apply any model/revision/min_score/prefer_gpu change from the files. With
    // `enabled` preserved above, this never flips ML on/off — and `retry_failed =
    // false` means an unrelated edit won't re-stall a previously-failed load.
    reconcile_ml(&st, &new_ml, false);
    // Rebuild the broker policy from the reloaded files so a removed/restricted rule
    // takes effect live; any error swaps to default-deny (fail-closed).
    let broker_policy = match config::reload_broker_allows(&st.layers) {
        Ok(allows) => crate::secrets::build_broker_policy(&allows).unwrap_or_else(|e| {
            tracing::error!(
                "sordino: reloaded [broker] policy invalid ({e}); broker DISABLED (default-deny)"
            );
            BrokerPolicy::default()
        }),
        Err(e) => {
            tracing::error!(
                "sordino: could not reload [broker] policy ({e}); broker DISABLED (default-deny)"
            );
            BrokerPolicy::default()
        }
    };
    st.engine.set_broker_policy(broker_policy);
    let snap = snapshot(&st);
    push_policy(&st, &hdrs, &snap);
    json_ok(&snap)
}

/// `POST /sordino/broker/resolve` (x-sordino-key) — the T2/T3 tool-boundary resolve.
/// Body: `{ "tool_name": "...", "tool_input": { ... } }`. Resolves ALLOW-LISTED broker
/// tokens in `tool_input` to their real values and returns the rewritten input. Local
/// + key-gated: the resolved values are for the LOCAL tool only — this is the one
/// place a broker value is spliced back in. Denied / unknown tokens stay tokenized.
pub async fn broker_resolve(State(st): State<AppState>, hdrs: HeaderMap, body: Bytes) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    #[derive(Deserialize)]
    struct Req {
        tool_name: String,
        #[serde(default)]
        tool_input: serde_json::Value,
    }
    let req: Req = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid broker resolve body: {e}"),
            );
        }
    };
    let mut input = req.tool_input;
    let report = st.engine.broker_resolve_pointers(&req.tool_name, &mut input);
    // Surface the per-pointer denials so the PreToolUse hook can tell the model WHY an
    // allow-listed broker token stayed masked (blocker #4). VALUE-FREE: only the RFC-6901
    // pointer (already in the tool input the model sent) and a reason CATEGORY — never the
    // resolved secret, and never the host parsed from it (HostNotAllowed drops the host).
    let denied: Vec<_> = report
        .denied
        .iter()
        .map(|(pointer, reason)| json!({ "pointer": pointer, "reason": deny_reason_label(reason) }))
        .collect();
    json_ok(&json!({
        "tool_input": input,
        "resolved": report.resolved,
        "denied": denied,
        "denied_count": report.denied.len(),
    }))
}

/// A stable, VALUE-FREE label for a broker denial — safe to surface to the model (so it can
/// guide the user to a fix) without ever revealing the resolved secret, or, for a host
/// denial, the host parsed out of it.
fn deny_reason_label(reason: &sordino_engine::DenyReason) -> &'static str {
    use sordino_engine::DenyReason::*;
    match reason {
        NoRule => "no matching [[broker.allow]] rule for this secret + tool + param",
        EgressBoundary => "tool is an egress boundary (MCP / sub-agent) — never brokered",
        OpaqueCommand => "tool runs a free-form shell command — use a structured tool instead",
        HostNotAllowed(_) => "the destination host is not on the rule's allow-list",
        HostUnparsed => "the rule requires a host allow-list but no host could be parsed",
    }
}

/// `POST /sordino/diag/mask` (key-gated): a masking canary for `/sordino:verify` Leg 1. Masks a
/// caller-supplied `{"text": ...}` through THIS project's live engine + merged config and
/// reports whether anything changed — proving the engine actually masks, a verdict distinct
/// from "this session is routed". Never forwards upstream. Key-gated so the model can't use it
/// as a masking oracle.
pub async fn diag_mask(State(st): State<AppState>, hdrs: HeaderMap, body: Bytes) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    #[derive(Deserialize)]
    struct Req {
        text: String,
    }
    let req: Req = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid diag/mask body: {e}")),
    };
    match st.engine.mask(&req.text, sordino_engine::Surface::UserMessage) {
        Ok(m) => {
            let changed = m.masked_text != req.text;
            json_ok(&json!({ "masked": m.masked_text, "changed": changed }))
        }
        Err(e) => text(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("mask failed: {e}"),
        ),
    }
}

/// `GET /sordino/session/{conversation_id}/routed` (key-gated): READ-ONLY per-session
/// inbound observability. Reports whether inbound for `conversation_id` reached THIS
/// proxy recently — the only signal that can detect a `-c`/`-p` provider override
/// (config says sordino but traffic went straight to the upstream), under which the
/// proxy sees ZERO inbound for the id.
///
/// Response 200 `{"routed_recently": bool, "last_seen_ms": u128|null}`. `routed_recently`
/// is true IFF the proxy has actually recorded inbound for this id within
/// [`monitor::ROUTED_RECENTLY_WINDOW_MS`]. It reflects ONLY recorded inbound — never
/// proxy liveness or config-on-disk — and never blocks a request or drives a masking
/// claim. Key-gated (same `x-sordino-key` as every other admin route): a public
/// per-session-inbound endpoint would be an information leak.
pub async fn session_routed(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(conversation_id): Path<String>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let (routed_recently, last_seen_ms) = st
        .monitor
        .routed_recently(&conversation_id, monitor::ROUTED_RECENTLY_WINDOW_MS);
    json_ok(&json!({
        "routed_recently": routed_recently,
        "last_seen_ms": last_seen_ms,
    }))
}

/// `GET /sordino/session/{conversation}/zdr` (x-sordino-key) — the **Trust** switch
/// status for this conversation: its active selection (if any), the default, and the
/// value-free list of configured targets.
pub async fn zdr_get(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(conversation): Path<String>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    json_ok(&zdr_status(&st, &conversation))
}

/// `POST /sordino/session/{conversation}/zdr` (x-sordino-key) — ENGAGE ZDR for this
/// conversation. Body: `{ "config": "name" }`, or `{}`/`{"config": null}` to use the
/// configured default. Deny-by-default: an unknown or non-`user_verified` config is
/// REFUSED (the system cannot verify ZDR — only the user can). Engaging breaks the
/// Anthropic prompt cache for this conversation, so this is never automatic and the
/// response front-loads that cost as a warning.
pub async fn zdr_set(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(conversation): Path<String>,
    body: Bytes,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    #[derive(Deserialize, Default)]
    struct Req {
        #[serde(default)]
        config: Option<String>,
    }
    // An empty body is allowed (⇒ use the default).
    let req: Req = if body.is_empty() {
        Req::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return text(StatusCode::BAD_REQUEST, &format!("invalid zdr body: {e}"));
            }
        }
    };
    let name = match req.config.or_else(|| st.zdr_default.as_ref().clone()) {
        Some(n) => n,
        None => {
            return text(
                StatusCode::BAD_REQUEST,
                "no ZDR config named and no [zdr] default configured",
            );
        }
    };
    let target = match st.zdr_target(&name) {
        Some(t) => t,
        None => {
            return text(
                StatusCode::NOT_FOUND,
                &format!("unknown ZDR config '{name}' (check `[zdr]` targets resolved at startup)"),
            );
        }
    };
    if !target.user_verified {
        return text(
            StatusCode::BAD_REQUEST,
            &format!(
                "ZDR config '{name}' is not user_verified — refusing to engage. sordino cannot \
                 verify a provider is zero-retention; set `user_verified = true` on this target \
                 only after you have independently confirmed it."
            ),
        );
    }
    // Fail-closed-and-VISIBLE (S1): the durable write may fail; a 5xx (not 200) is the
    // falsifiable contract that the failure is non-silent. Returns BEFORE building the
    // success snapshot so the body never claims "engaged" on a write failure.
    match st.set_zdr_selection(&conversation, &name) {
        Ok(()) => {}
        Err(e) => {
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "ZDR engage could NOT be made durable ({e}) — NOT engaged; the selection \
                     would be lost on the next proxy restart. Check the state dir is writable, \
                     then retry /sordino:zdr."
                ),
            );
        }
    };
    let mut snap = zdr_status(&st, &conversation);
    if let Some(obj) = snap.as_object_mut() {
        obj.insert("engaged".into(), json!(name));
        obj.insert(
            "warning".into(),
            json!(format!(
                "ZDR engaged: this conversation now routes to '{name}' ({}). Switching endpoints \
                 BREAKS the Anthropic prompt cache — the next turn re-pays full input cost. \
                 Masking still fully applies; values are NOT revealed (routing-only).",
                target.trust_basis.label()
            )),
        );
    }
    json_ok(&snap)
}

/// `DELETE /sordino/session/{conversation}/zdr` (x-sordino-key) — DISENGAGE ZDR
/// (back to the default masked Anthropic path). Also breaks the cache once.
pub async fn zdr_clear(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(conversation): Path<String>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    // Fail-closed-and-VISIBLE (S1): a failed durable write of the disengage must NOT report
    // success — the old selection would still be on disk and RESURRECT on the next restart.
    let was_active = match st.clear_zdr_selection(&conversation) {
        Ok(b) => b,
        Err(e) => {
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "ZDR disengage could NOT be made durable ({e}) — STILL engaged; it would \
                     resurrect on the next restart. Check the state dir is writable, then retry \
                     /sordino:zdr off."
                ),
            );
        }
    };
    let mut snap = zdr_status(&st, &conversation);
    if let Some(obj) = snap.as_object_mut() {
        obj.insert("disengaged".into(), json!(was_active));
    }
    json_ok(&snap)
}

/// Per-conversation ZDR status payload shared by the get/set/clear handlers.
fn zdr_status(st: &AppState, conversation: &str) -> serde_json::Value {
    let configured: Vec<_> = st.zdr_targets.values().map(|t| t.view()).collect();
    json!({
        "conversation": conversation,
        "active": st.zdr_selection(conversation).map(|s| s.target),
        "default": st.zdr_default.as_ref(),
        "configured": configured,
    })
}

/// `GET /sordino/session/{conversation}/masking` (x-sordino-key) — whether masking is
/// currently turned OFF for this conversation. Read-only.
pub async fn masking_get(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(conversation): Path<String>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    json_ok(&masking_status(&st, &conversation))
}

/// `POST /sordino/session/{conversation}/masking` (x-sordino-key) — turn masking OFF for
/// THIS conversation only (the per-conversation counterpart of the master switch). The
/// proxy-wide switch and every other conversation are untouched; registered secrets are
/// still masked (engine A9). In-memory only — a proxy restart clears it (fails toward
/// masking ON), so there is no durability contract to fail-close on.
pub async fn masking_disable(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(conversation): Path<String>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let newly = st.set_masking_disabled(&conversation);
    let mut snap = masking_status(&st, &conversation);
    if let Some(obj) = snap.as_object_mut() {
        obj.insert("changed".into(), json!(newly));
        obj.insert(
            "warning".into(),
            json!(
                "Masking is OFF for this conversation — its PII now egresses UNMASKED (registered \
                 secrets are still masked). Session-scoped and NOT persisted: it lifts on the next \
                 Claude Code restart, or turn it back on with `/sordino:privacy on`."
            ),
        );
    }
    json_ok(&snap)
}

/// `DELETE /sordino/session/{conversation}/masking` (x-sordino-key) — turn masking back
/// ON for this conversation (clear the override).
pub async fn masking_enable(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(conversation): Path<String>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let was_disabled = st.clear_masking_disabled(&conversation);
    let mut snap = masking_status(&st, &conversation);
    if let Some(obj) = snap.as_object_mut() {
        obj.insert("changed".into(), json!(was_disabled));
    }
    json_ok(&snap)
}

/// Per-conversation masking status payload shared by the masking get/disable/enable
/// handlers. `disabled` = masking is currently off for this conversation.
fn masking_status(st: &AppState, conversation: &str) -> serde_json::Value {
    json!({
        "conversation": conversation,
        "disabled": st.is_masking_disabled(conversation),
        // Whether the proxy-wide master switch is on, so a caller can tell a per-conversation
        // disable apart from a project-wide one.
        "master_enabled": st.engine.is_enabled(),
    })
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
    text(StatusCode::FORBIDDEN, "missing or invalid x-sordino-key")
}

fn text(status: StatusCode, msg: &str) -> Response {
    let mut r = Response::new(Body::from(msg.to_string()));
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordino_engine::{Category, Operator, Profile};

    // A partial PUT body must MERGE onto the live config: keys the client sent
    // overlay; every omitted field is preserved (not reset to its serde default).
    // This exercises the exact merge_json → WireConfig deserialize path put_config
    // uses, minus the live engine/HTTP plumbing.
    #[test]
    fn merge_put_preserves_omitted_fields() {
        // A non-default "live" config: strict-ish threshold + a custom entity op.
        let mut live = EngineConfig {
            score_threshold: 0.42,
            profile: Profile::Strict,
            enabled_categories: [Category::Secrets, Category::Personal]
                .into_iter()
                .collect(),
            ..EngineConfig::default()
        };
        live.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Redact);
        live.allow_list.add_exact("keep-me@example.com");

        let current = WireConfig::from_engine(&live);
        let mut merged = serde_json::to_value(&current).unwrap();
        // Client sends ONLY a new threshold.
        merge_json(&mut merged, serde_json::json!({ "score_threshold": 0.8 }));

        let wire: WireConfig = serde_json::from_value(merged).unwrap();
        let out = wire.into_engine().unwrap();
        assert_eq!(out.score_threshold, 0.8, "sent field overlaid");
        // Everything omitted survived:
        assert_eq!(out.profile, Profile::Strict);
        assert_eq!(
            out.enabled_categories,
            [Category::Secrets, Category::Personal]
                .into_iter()
                .collect()
        );
        assert_eq!(
            out.entity_operators.get("EMAIL_ADDRESS"),
            Some(&Operator::Redact)
        );
        assert!(out.allow_list.is_allowed("keep-me@example.com"));
    }

    #[test]
    fn merge_put_can_update_nested_and_arrays() {
        let live = EngineConfig::default();
        let current = WireConfig::from_engine(&live);
        let mut merged = serde_json::to_value(&current).unwrap();
        // Arrays replace wholesale; nested objects (ml) deep-merge.
        merge_json(
            &mut merged,
            serde_json::json!({
                "enabled_categories": ["secrets"],
                "ml": { "model": "acme/x" }
            }),
        );
        let out: WireConfig = serde_json::from_value(merged).unwrap();
        let cfg = out.into_engine().unwrap();
        assert_eq!(
            cfg.enabled_categories,
            [Category::Secrets].into_iter().collect()
        );
        assert_eq!(cfg.ml.model, "acme/x");
        // ml.enabled (omitted in the nested object) kept its prior value.
        assert!(!cfg.ml.enabled);
    }

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

    // A stale unknown entity_operators key already in the live config (the file loader
    // only warns, never strips) must NOT brick an unrelated merge-PUT. Only the keys
    // the PUT actually introduces or changes are validated.
    #[test]
    fn stale_unknown_key_does_not_brick_unrelated_put() {
        // Live config carries a typo'd key (survived file load with only a warning).
        let mut current = EngineConfig::default();
        current
            .entity_operators
            .insert("EMIAL".into(), Operator::Redact);

        // A merge-PUT that only lowers the threshold carries the stale key forward
        // unchanged. The delta is empty → no rejection.
        let mut merged = current.clone();
        merged.score_threshold = 0.3;
        assert!(
            new_unknown_entity_keys(&current, &merged).is_empty(),
            "carried-forward stale typo must not block an unrelated edit"
        );
    }

    #[test]
    fn newly_introduced_unknown_key_is_still_rejected() {
        let current = EngineConfig::default();
        // PUT introduces a fresh typo'd key.
        let mut merged = current.clone();
        merged
            .entity_operators
            .insert("EMIAL".into(), Operator::Redact);
        assert_eq!(
            new_unknown_entity_keys(&current, &merged),
            vec!["EMIAL".to_string()],
            "a brand-new typo'd key is still flagged"
        );
    }

    #[test]
    fn changed_value_on_stale_unknown_key_is_rejected() {
        // A stale typo'd key that the PUT also re-points to a different operator IS a
        // genuine new edit on that key → flag it (the operator is touching it now).
        let mut current = EngineConfig::default();
        current
            .entity_operators
            .insert("EMIAL".into(), Operator::Redact);
        let mut merged = current.clone();
        merged
            .entity_operators
            .insert("EMIAL".into(), Operator::Token);
        assert_eq!(
            new_unknown_entity_keys(&current, &merged),
            vec!["EMIAL".to_string()]
        );
    }

    #[test]
    fn valid_opt_in_keys_pass_delta_validation() {
        // DATE_TIME/DOMAIN are valid canonical Display names (opt-in levers) and must
        // pass even when freshly introduced.
        let current = EngineConfig::default();
        let mut merged = current.clone();
        merged
            .entity_operators
            .insert("DATE_TIME".into(), Operator::Redact);
        merged
            .entity_operators
            .insert("DOMAIN".into(), Operator::Redact);
        assert!(new_unknown_entity_keys(&current, &merged).is_empty());
    }
}
