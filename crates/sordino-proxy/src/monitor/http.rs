//! Axum handlers for the local, key-gated monitor surface.
//!
//! Every handler enforces [`AppState::authed`]; the SSE `events` handler also
//! accepts the admin key as a query param (EventSource cannot set headers).
//! Canonical plaintext is only ever exposed through these key-gated routes.

use std::collections::HashMap;
use std::convert::Infallible;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::response::Response;
use futures::{StreamExt, stream};
use http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use serde::Serialize;
use serde_json::json;
use tokio::sync::broadcast;
use sordino_engine::CustomReplacement;

use crate::admin::{WireConfig, push_policy, snapshot as policy_snapshot};
use crate::routes;
use crate::state::AppState;

use super::model::{
    ApprovalDecision, CustomMaskRequest, ModeRequest, MonitorEvent, RejectRequest, RemaskRequest,
    RevealRequest, TagsRequest,
};
use super::persist;
use super::store::ReviewTicket;

/// Wait for the operator's verdict on a held request, converting a rejection into
/// the wire error the proxy returns upstream-side. Lives here (not in the module
/// root) because it is web glue: it depends on [`AppState`] and builds a Response.
pub async fn maybe_approve(st: &AppState, ticket: ReviewTicket) -> Result<(), Response> {
    match st.monitor.wait_for_approval(ticket).await {
        ApprovalDecision::Approve => Ok(()),
        ApprovalDecision::Reject { reason } => Err(routes::err(
            StatusCode::FORBIDDEN,
            &format!("sordino monitor rejected request: {reason}"),
        )),
    }
}

pub async fn snapshot(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    json_response(&st.monitor.snapshot())
}

pub async fn set_mode(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    axum::Json(req): axum::Json<ModeRequest>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    json_response(&st.monitor.set_mode(req.mode, req.max_pending_approvals))
}

pub async fn approve(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    match st.monitor.decide(&id, ApprovalDecision::Approve) {
        Ok(r) => json_response(&r),
        Err(_) => text(StatusCode::NOT_FOUND, "unknown or non-pending request"),
    }
}

pub async fn reject(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<RejectRequest>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let reason = if req.reason.trim().is_empty() {
        "rejected by monitor".to_string()
    } else {
        req.reason
    };
    match st.monitor.decide(&id, ApprovalDecision::Reject { reason }) {
        Ok(r) => json_response(&r),
        Err(_) => text(StatusCode::NOT_FOUND, "unknown or non-pending request"),
    }
}

pub async fn tags(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<TagsRequest>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    match st.monitor.update_tags(&id, req.tags) {
        Ok(r) => json_response(&r),
        Err(_) => text(StatusCode::NOT_FOUND, "unknown request"),
    }
}

pub async fn custom_mask(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    axum::Json(req): axum::Json<CustomMaskRequest>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let pattern = req.pattern.trim();
    if pattern.is_empty() {
        return text(StatusCode::BAD_REQUEST, "pattern must not be empty");
    }
    let rule = CustomReplacement {
        pattern: pattern.to_string(),
        entity_type: req
            .entity_type
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "CUSTOM_KEYWORD".to_string()),
        is_regex: false,
        case_sensitive: req.case_sensitive,
        priority: 0,
        literal_token: false,
        token: None,
        apply_to_surfaces: None,
    };
    // Hold the config RMW lock across snapshot→set_config→persist so a concurrent
    // writer (reveal / profile / PUT) can't lost-update us or reorder the file write.
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let mut cfg = st.engine.config_snapshot();
    cfg.custom_replacements.push(rule.clone());
    if let Err(e) = st.engine.set_config(cfg) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("custom mask rejected: {e}"),
        );
    }
    // Persist to ./sordino.local.toml so a later `/sordino/reload` doesn't destroy
    // it. If we can't reach/write that path, the live change stays in effect but we
    // tell the UI it is session-only (lost on the next reload).
    let (persisted, session_only, persist_error) =
        match persist::persist_custom_replacement(&st.project_root, &rule) {
            Ok(path) => (Some(path.display().to_string()), false, None),
            Err(e) => (None, true, Some(e)),
        };
    let wire = WireConfig::from_engine(&st.engine.config_snapshot());
    // Live-sync open policy panels in every window (custom masks are shown there).
    push_policy(&st, &hdrs, &policy_snapshot(&st));
    json_response(&json!({
        "ok": true,
        "config": wire,
        "persisted": persisted,
        "session_only": session_only,
        "persist_error": persist_error,
    }))
}

/// `GET` listing of the live custom-mask rules (pattern + entity_type + flags), for
/// the UI's manage view. Reads the live config snapshot (the authoritative set,
/// including session-only additions not yet — or never — persisted).
pub async fn custom_masks_list(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let cfg = st.engine.config_snapshot();
    let rules: Vec<_> = cfg
        .custom_replacements
        .iter()
        .map(|c| {
            json!({
                "pattern": c.pattern,
                "entity_type": c.entity_type,
                "is_regex": c.is_regex,
                "case_sensitive": c.case_sensitive,
            })
        })
        .collect();
    json_response(&json!({ "custom_replacements": rules }))
}

/// Remove a custom-mask rule (matched by `pattern` + `entity_type`) from BOTH the
/// live config and the persisted `sordino.local.toml`. Removing the live rule is
/// authoritative; the file removal is best-effort (a session-only rule has nothing
/// persisted to remove).
pub async fn custom_masks_remove(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    axum::Json(req): axum::Json<super::model::CustomMaskRemoveRequest>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let pattern = req.pattern.trim().to_string();
    if pattern.is_empty() {
        return text(StatusCode::BAD_REQUEST, "pattern must not be empty");
    }
    let entity_type = req
        .entity_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "CUSTOM_KEYWORD".to_string());

    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let mut cfg = st.engine.config_snapshot();
    let before = cfg.custom_replacements.len();
    let mut removed_live = false;
    cfg.custom_replacements.retain(|c| {
        if !removed_live && c.pattern == pattern && c.entity_type == entity_type {
            removed_live = true;
            false
        } else {
            true
        }
    });
    if cfg.custom_replacements.len() != before
        && let Err(e) = st.engine.set_config(cfg)
    {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("custom mask removal rejected: {e}"),
        );
    }
    let removed_persisted =
        persist::remove_custom_replacement(&st.project_root, &pattern, &entity_type)
            .unwrap_or(false);
    let wire = WireConfig::from_engine(&st.engine.config_snapshot());
    if removed_live {
        push_policy(&st, &hdrs, &policy_snapshot(&st));
    }
    json_response(&json!({
        "ok": true,
        "removed_live": removed_live,
        "removed_persisted": removed_persisted,
        "config": wire,
    }))
}

/// The four common-word defaults `AllowList::with_common_words` always re-seeds.
/// Entries beyond these are operator-configured or reveal-created; only those are
/// persisted (the defaults are re-added by `from_specs` on every load).
const DEFAULT_ALLOW_EXACT: [&str; 3] = ["Anthropic", "Claude", "127.0.0.1"];
const DEFAULT_ALLOW_EXACT_CI: [&str; 1] = ["localhost"];

fn non_default_exact(al: &sordino_engine::AllowList) -> Vec<String> {
    al.exact
        .iter()
        .filter(|v| !DEFAULT_ALLOW_EXACT.contains(&v.as_str()))
        .cloned()
        .collect()
}

fn non_default_exact_ci(al: &sordino_engine::AllowList) -> Vec<String> {
    al.exact_ci
        .iter()
        .filter(|v| !DEFAULT_ALLOW_EXACT_CI.contains(&v.as_str()))
        .cloned()
        .collect()
}

/// Persist the live allow-list's full effective non-default sets to local TOML,
/// returning the `(persisted, session_only, persist_error)` triple the UI expects.
fn persist_allow_lists(st: &AppState, al: &sordino_engine::AllowList) -> (Option<String>, bool, Option<String>) {
    match persist::persist_local_allow_lists(
        &st.project_root,
        &non_default_exact(al),
        &non_default_exact_ci(al),
    ) {
        Ok(path) => (Some(path.display().to_string()), false, None),
        Err(e) => (None, true, Some(e)),
    }
}

/// `POST /sordino/monitor/reveal` — reveal a value TO THE MODEL: add it to the
/// allow-list (so future requests egress it plaintext) and, if it was backed by a
/// custom keyphrase rule, drop that rule too. Durable: re-persists the full effective
/// allow-list to `sordino.local.toml`. Privacy-reducing — the UI gates this behind a
/// confirm. All under `config_control` (snapshot→set_config→persist held together).
pub async fn reveal_keyphrase(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    axum::Json(req): axum::Json<RevealRequest>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let value = req.value.trim().to_string();
    if value.is_empty() {
        return text(StatusCode::BAD_REQUEST, "value must not be empty");
    }
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let mut cfg = st.engine.config_snapshot();

    // If this value is a custom keyphrase, remove its backing rule so it does not
    // immediately re-mask the value the allow-list now lets through. Mutate the LIVE
    // config here; only mirror the removal to the persisted file AFTER `set_config`
    // succeeds, so a rejected swap can't leave disk ahead of live.
    let mut removed_rule = false;
    let backing = req
        .pattern
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let backing_entity = req
        .entity_type
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "CUSTOM_KEYWORD".to_string());
    if let Some(pattern) = backing.as_deref() {
        let before = cfg.custom_replacements.len();
        let mut done = false;
        cfg.custom_replacements.retain(|c| {
            if !done && c.pattern == pattern && c.entity_type == backing_entity {
                done = true;
                false
            } else {
                true
            }
        });
        removed_rule = cfg.custom_replacements.len() != before;
    }

    cfg.allow_list.add_exact(&value);
    if let Err(e) = st.engine.set_config(cfg) {
        return text(StatusCode::BAD_REQUEST, &format!("reveal rejected: {e}"));
    }
    // Live swap succeeded — now mirror the custom-rule removal to disk (best-effort).
    if removed_rule && let Some(pattern) = backing.as_deref() {
        let _ = persist::remove_custom_replacement(&st.project_root, pattern, &backing_entity);
    }
    let live = st.engine.config_snapshot();
    let (persisted, session_only, persist_error) = persist_allow_lists(&st, &live.allow_list);
    let wire = WireConfig::from_engine(&live);
    // A reveal changes the live allow-list (what egresses plaintext) — sync open panels.
    push_policy(&st, &hdrs, &policy_snapshot(&st));
    json_response(&json!({
        "ok": true,
        "config": wire,
        "removed_rule": removed_rule,
        "persisted": persisted,
        "session_only": session_only,
        "persist_error": persist_error,
    }))
}

/// `DELETE /sordino/monitor/reveal` — re-mask a previously-revealed value: lift its
/// allow-list suppression (both `exact` and `exact_ci`) so detection resumes, and
/// re-persist the full effective allow-list. Does NOT recreate a removed custom rule,
/// and cannot re-mask a value egressing via a config `patterns` regex (only
/// `exact`/`exact_ci` are touched). Under `config_control`.
pub async fn remask_keyphrase(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    axum::Json(req): axum::Json<RemaskRequest>,
) -> Response {
    if !st.authed_for_project(&hdrs) {
        return forbidden();
    }
    let value = req.value.trim().to_string();
    if value.is_empty() {
        return text(StatusCode::BAD_REQUEST, "value must not be empty");
    }
    let _cfg_guard = st.config_control.lock().expect("config_control mutex poisoned");
    let mut cfg = st.engine.config_snapshot();
    let removed_exact = cfg.allow_list.exact.remove(&value);
    let removed_ci = cfg.allow_list.exact_ci.remove(&value.to_lowercase());
    let removed_live = removed_exact || removed_ci;
    if removed_live && let Err(e) = st.engine.set_config(cfg) {
        return text(StatusCode::BAD_REQUEST, &format!("remask rejected: {e}"));
    }
    let live = st.engine.config_snapshot();
    let (persisted, session_only, persist_error) = persist_allow_lists(&st, &live.allow_list);
    let wire = WireConfig::from_engine(&live);
    if removed_live {
        push_policy(&st, &hdrs, &policy_snapshot(&st));
    }
    json_response(&json!({
        "ok": true,
        "removed_live": removed_live,
        "config": wire,
        "persisted": persisted,
        "session_only": session_only,
        "persist_error": persist_error,
    }))
}

pub async fn events(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    // EventSource clients cannot set custom headers, so BOTH the admin key and the
    // project identity accept a query-param fallback (mirroring the header path).
    let key_ok = st.authed(&hdrs) || query.get("key") == Some(st.admin_key.as_ref());
    let project_ok = st
        .project_header_matches(hdrs.get("x-sordino-project").and_then(|v| v.to_str().ok()))
        || st.project_header_matches(query.get("project").map(String::as_str));
    if !key_ok || !project_ok {
        return forbidden();
    }
    let snapshot = st.monitor.snapshot();
    let rx = st.monitor.subscribe();
    let initial = stream::once(async move {
        Ok::<Bytes, Infallible>(Bytes::from(sse_frame(&MonitorEvent::Snapshot(Box::new(
            snapshot,
        )))))
    });
    let updates = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => return Some((Ok(Bytes::from(sse_frame(&ev))), rx)),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let mut r = Response::new(Body::from_stream(initial.chain(updates)));
    r.headers_mut()
        .insert(CONTENT_TYPE, "text/event-stream".parse().unwrap());
    r
}

fn sse_frame(ev: &MonitorEvent) -> String {
    let data = serde_json::to_string(ev).unwrap_or_else(|_| "{}".to_string());
    format!("data: {data}\n\n")
}

fn json_response(v: &impl Serialize) -> Response {
    let mut r = Response::new(Body::from(serde_json::to_vec(v).unwrap_or_default()));
    r.headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

pub(crate) fn forbidden() -> Response {
    text(StatusCode::FORBIDDEN, "missing or invalid x-sordino-key")
}

fn text(status: StatusCode, msg: &str) -> Response {
    let mut r = Response::new(Body::from(msg.to_string()));
    *r.status_mut() = status;
    r
}
