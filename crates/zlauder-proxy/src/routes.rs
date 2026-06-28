//! HTTP routing: mask requests, relay upstream, unmask responses.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::routing::{get, post};
use http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use zlauder_engine::{RevealAudit, UnmaskManifest};

use crate::wire_adapter::{AnthropicNative, WireAdapter};
use crate::zdr::PinnedMode;
use crate::{admin, headers, monitor, openai_chat, openai_responses, sse, state::AppState, walk};

const MAX_BODY: usize = 64 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        // Body is this proxy's build id — the SessionStart hook reads it to detect a
        // stale long-lived proxy (older build) and restart it. Health = HTTP 200. The
        // `x-zlauder-nonce` header echoes this launch's nonce so the launcher can confirm
        // the live proxy is the exact instance it just spawned (not a stale/foreign one).
        .route("/healthz", get(healthz))
        .route("/zlauder/reveal/{token}", get(reveal))
        // `/privacy` control plane (all key-gated; per-project proxy).
        .route(
            "/zlauder/config",
            get(admin::get_config).put(admin::put_config),
        )
        .route("/zlauder/profile/{name}", post(admin::apply_profile))
        .route("/zlauder/enable", post(admin::enable))
        .route("/zlauder/disable", post(admin::disable))
        .route("/zlauder/reload", post(admin::reload))
        .route("/zlauder/broker/resolve", post(admin::broker_resolve))
        .route("/zlauder/diag/mask", post(admin::diag_mask))
        .route("/zlauder/ml/enable", post(admin::ml_enable))
        .route("/zlauder/ml/disable", post(admin::ml_disable))
        .route("/zlauder/ui", get(monitor::ui))
        .route("/zlauder/monitor/snapshot", get(monitor::snapshot))
        .route("/zlauder/monitor/events", get(monitor::events))
        .route("/zlauder/monitor/mode", post(monitor::set_mode))
        .route(
            "/zlauder/monitor/requests/{id}/approve",
            post(monitor::approve),
        )
        .route(
            "/zlauder/monitor/requests/{id}/reject",
            post(monitor::reject),
        )
        .route("/zlauder/monitor/requests/{id}/tags", post(monitor::tags))
        .route(
            "/zlauder/monitor/custom-mask",
            get(monitor::custom_masks_list)
                .post(monitor::custom_mask)
                .delete(monitor::custom_masks_remove),
        )
        .route(
            "/zlauder/monitor/reveal",
            post(monitor::reveal_keyphrase).delete(monitor::remask_keyphrase),
        )
        // ZDR (Trust switch) control plane for a conversation: GET status, POST to
        // engage a verified target, DELETE to disengage. All key-gated.
        .route(
            "/zlauder/session/{conversation}/zdr",
            get(admin::zdr_get)
                .post(admin::zdr_set)
                .delete(admin::zdr_clear),
        )
        .route(
            "/zlauder/session/{conversation}/v1/messages",
            post(messages_session),
        )
        // Session-scoped count_tokens: a ZDR-active conversation's token-count must
        // route to the SAME (ZDR) target as its messages — and be masked — so it
        // can't fall through to the verbatim relay or silently hit Anthropic.
        .route(
            "/zlauder/session/{conversation}/v1/messages/count_tokens",
            post(count_tokens_session),
        )
        .route(
            "/zlauder/session/{conversation}/v1/chat/completions",
            post(openai_chat::chat_completions_session),
        )
        .route(
            "/zlauder/session/{conversation}/v1/responses",
            post(openai_responses::responses_session),
        )
        .route("/v1/messages", post(messages))
        .route("/v1/messages/count_tokens", post(count_tokens))
        .route("/v1/chat/completions", post(openai_chat::chat_completions))
        .route("/v1/responses", post(openai_responses::responses))
        .fallback(passthrough)
        .with_state(state)
}

/// Liveness + identity probe. Body is the build id (for stale-build recycling); the
/// `x-zlauder-nonce` header carries this launch's nonce (from `ZLAUDER_LAUNCH_NONCE`,
/// read at request time — it never changes for a live proxy) so the launcher can
/// confirm it adopted the instance it spawned. Unauthenticated by design (liveness).
async fn healthz() -> Response {
    let mut headers = HeaderMap::new();
    // Attach the launch nonce only if it forms a valid header value (it is hook-minted
    // hex, so it always does — but build the response so an odd env can never degrade
    // /healthz to a 500: liveness must answer 200 with the BUILD_ID body unconditionally).
    if let Ok(nonce) = std::env::var("ZLAUDER_LAUNCH_NONCE")
        && let Ok(value) = http::HeaderValue::from_str(&nonce)
    {
        headers.insert("x-zlauder-nonce", value);
    }
    respond(StatusCode::OK, headers, Body::from(zlauder_state::BUILD_ID))
}

/// Audit reveal: `GET /zlauder/reveal/{token}` with header `x-zlauder-key`.
/// Local operator affordance only; not reachable by the upstream model.
///
// EV-A INVARIANT (load-bearing, do not weaken):
/// Reveal is unconditional/local-only TODAY (key-gated, off the model path). If a future
/// EV-A clearance gate is added here, it MUST consume the [`PinnedMode`] captured at request
/// entry via [`resolve_pinned_mode`] → [`crate::zdr::RevealClearanceCtx::from_pinned`] →
/// `permits_reveal()`. It MUST NOT re-read `st.zdr_selection`/`st.zdr_sessions` nor the
/// statusline belief (a concurrent control-plane flip could strand an in-flight reveal), and
/// `PinnedMode::Normal` (incl. absent selection) ⇒ reveal-DENY.
async fn reveal(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if !st.authed(&hdrs) {
        return err(StatusCode::FORBIDDEN, "missing or invalid x-zlauder-key");
    }
    // Class-aware: distinguish an UNKNOWN handle (404) from one that EXISTS but is not
    // revealable here (409 for a broker secret — its value lives only at the tool boundary).
    // The broker value is never decrypted; we return only its registered name.
    match st.engine.reveal_audit(&token) {
        RevealAudit::Pii(plain) | RevealAudit::Local(plain) => {
            respond(StatusCode::OK, HeaderMap::new(), Body::from(plain))
        }
        RevealAudit::Broker { secret_name } => {
            let what = secret_name.as_deref().unwrap_or("a registered secret");
            err(
                StatusCode::CONFLICT,
                &format!(
                    "token is a broker secret ({what}) — resolved only at the tool boundary, \
                     never revealable here"
                ),
            )
        }
        RevealAudit::Unknown => err(StatusCode::NOT_FOUND, "unknown token"),
    }
}

/// `/v1/messages` — mask request, relay, unmask response (JSON or SSE).
async fn messages(State(st): State<AppState>, req: Request) -> Response {
    messages_inner(st, req, None).await
}

async fn messages_session(
    State(st): State<AppState>,
    Path(conversation): Path<String>,
    req: Request,
) -> Response {
    messages_inner(st, req, Some(conversation)).await
}

/// Resolve a request's trust posture ONCE at entry, from the **explicit
/// session-route conversation id** (never the monitor's content-derived id).
/// Fail-closed taxonomy:
///   - no conversation / no selection → [`PinnedMode::Normal`] (today's masked path);
///   - selection present but its target is unknown or not `user_verified` → **refuse**
///     (never silently downgrade to the default endpoint, never silently engage).
/// Returns the captured mode by value so a concurrent control-plane change can't
/// strand an in-flight request — it dispatches against what it captured here.
pub(crate) fn resolve_pinned_mode(
    st: &AppState,
    conversation: Option<&str>,
) -> Result<PinnedMode, Response> {
    let Some(conv) = conversation else {
        return Ok(PinnedMode::Normal);
    };
    let Some(sel) = st.zdr_selection(conv) else {
        return Ok(PinnedMode::Normal);
    };
    match st.zdr_target(&sel.target) {
        Some(t) if t.user_verified => Ok(PinnedMode::Zdr(t)),
        Some(_) => Err(err(
            StatusCode::FORBIDDEN,
            "ZDR selection references a target that is no longer user_verified — refusing \
             (fail-closed; never silently route to it or to the default endpoint)",
        )),
        None => Err(err(
            StatusCode::CONFLICT,
            "ZDR selection references an unknown target — refusing rather than silently sending \
             this conversation to the default endpoint",
        )),
    }
}

async fn messages_inner(st: AppState, req: Request, conversation: Option<String>) -> Response {
    if let Some(resp) = secrets_gate(&st) {
        return resp;
    }
    // Bare-path defense-in-depth: a bare `/v1/messages` carrying x-zlauder-conversation
    // naming a LIVE pin must refuse rather than route masked-Normal to the default
    // endpoint. NON-consuming header read BEFORE into_parts; runs only when the URL has
    // no session id (precedence: URL id > header id > none).
    if let Some(resp) = bare_path_zdr_guard(&st, &req, conversation.as_deref(), "/v1/messages") {
        return resp;
    }
    // Pin the trust posture from the session-route id BEFORE masking, by value.
    let pinned = match resolve_pinned_mode(&st, conversation.as_deref()) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "failed to read request body"),
    };

    let (masked, manifest) = match mask_body(&st, &body_bytes).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let conversation = conversation.or_else(|| monitor::conversation_from_headers(&parts.headers));
    let ticket = st.monitor.record_llm_request(
        "/v1/messages",
        parts.method.as_str(),
        conversation,
        &masked,
        &manifest,
        &pinned,
    );
    let record_id = ticket.id().to_string();
    if let Err(resp) = monitor::maybe_approve(&st, ticket).await {
        return resp;
    }

    st.monitor.record_dispatched(&record_id);
    let resp = match send_upstream(&st, &parts, masked, "/v1/messages", &pinned).await {
        Ok(r) => r,
        Err(resp) => {
            st.monitor
                .record_upstream_error(&record_id, "upstream request failed");
            return resp;
        }
    };

    let status = resp.status();
    let up_headers = resp.headers().clone();
    let is_sse = up_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("text/event-stream"))
        .unwrap_or(false);
    let out_headers = headers::downstream_response_headers(&up_headers, true);
    let manifest = Arc::new(manifest);

    if is_sse {
        let guard = monitor::CompletionGuard::new(
            st.monitor.clone(),
            record_id.clone(),
            status.as_u16(),
            manifest.as_ref(),
        );
        let body = sse::unmask_sse_body(
            Box::pin(resp.bytes_stream()),
            st.engine.clone(),
            manifest,
            guard,
        );
        respond(status, out_headers, body)
    } else {
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                st.monitor
                    .record_upstream_error(&record_id, "upstream body error");
                return err(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream body error: {e}"),
                );
            }
        };
        let out = walk::unmask_response(st.engine.as_ref(), &manifest, &bytes)
            .unwrap_or_else(|_| bytes.to_vec());
        st.monitor
            .record_response(&record_id, status.as_u16(), Some(&out), &manifest);
        respond(status, out_headers, Body::from(out))
    }
}

/// `/v1/messages/count_tokens` — mask request so counts reflect masked text;
/// response is `{"input_tokens":N}` (no PII), relayed verbatim.
async fn count_tokens(State(st): State<AppState>, req: Request) -> Response {
    count_tokens_inner(st, req, None).await
}

async fn count_tokens_session(
    State(st): State<AppState>,
    Path(conversation): Path<String>,
    req: Request,
) -> Response {
    count_tokens_inner(st, req, Some(conversation)).await
}

async fn count_tokens_inner(st: AppState, req: Request, conversation: Option<String>) -> Response {
    if let Some(resp) = secrets_gate(&st) {
        return resp;
    }
    // Bare-path defense-in-depth (header-named live pin → refuse). See `messages_inner`.
    if let Some(resp) =
        bare_path_zdr_guard(&st, &req, conversation.as_deref(), "/v1/messages/count_tokens")
    {
        return resp;
    }
    // Count tokens against the SAME trust target as the conversation's messages.
    let pinned = match resolve_pinned_mode(&st, conversation.as_deref()) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "failed to read request body"),
    };
    let (masked, manifest) = match mask_body(&st, &body_bytes).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    // count_tokens masks + forwards but never records a request. Feed the durable
    // session-token ledger directly so values masked only for a token-count are not
    // missing from the secrets ledger.
    st.monitor.ingest_session_tokens(&manifest);
    let resp = match send_upstream(&st, &parts, masked, "/v1/messages/count_tokens", &pinned).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let status = resp.status();
    let h = resp.headers().clone();
    match resp.bytes().await {
        Ok(bytes) => respond(
            status,
            headers::downstream_response_headers(&h, false),
            Body::from(bytes.to_vec()),
        ),
        Err(e) => err(
            StatusCode::BAD_GATEWAY,
            &format!("upstream body error: {e}"),
        ),
    }
}

/// Everything else (`/v1/models`, `/v1/files`, batches, …): relay verbatim.
async fn passthrough(State(st): State<AppState>, req: Request) -> Response {
    // Fail-closed: while required secrets are unresolved, hold ALL upstream traffic —
    // including this verbatim relay, which does NOT mask and is therefore the most
    // dangerous path for an unresolved secret (e.g. a batches body). `/healthz` and
    // the `/zlauder/*` control plane are explicit routes and never reach here.
    if let Some(resp) = secrets_gate(&st) {
        return resp;
    }
    relay_verbatim(&st, req).await
}

/// Parse a `/zlauder/session/<id>/<rest>` verbatim-relay path with a SIMPLE string
/// match (split on '/', the segment after `session` is the id, everything after it is
/// `rest`). Returns `(id, rest)` where `rest` begins with a leading '/' (the path the
/// upstream should see once the prefix is stripped, e.g. `/v1/files`). Returns `None`
/// for any path that is NOT session-prefixed.
fn parse_session_prefix(path: &str) -> Option<(String, String)> {
    // Path is "/zlauder/session/<id>/<rest...>". Strip the literal prefix, then split
    // the id off the remainder at the first '/'.
    let after = path.strip_prefix("/zlauder/session/")?;
    let (id, rest) = match after.split_once('/') {
        Some((id, rest)) => (id, rest),
        // "/zlauder/session/<id>" with no trailing path — no inner path to relay.
        None => (after, ""),
    };
    if id.is_empty() {
        return None;
    }
    Some((id.to_string(), format!("/{rest}")))
}

/// True when a (prefix-stripped) inner relay path targets `/v1/batches`. ZDR forbids
/// the batches path entirely (it is verbatim, never masked, and may carry PII), so a
/// pinned conversation must never reach it — via the session prefix or otherwise.
fn is_batches(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path);
    p == "/v1/batches" || p.starts_with("/v1/batches/")
}

/// True when any '/'-segment of `rest` is exactly `..` — a path traversal. A legit
/// client never sends one; we refuse it BEFORE any pin/batches check so `..` can never
/// evade those checks by hiding the real target behind a traversal segment.
fn has_traversal(rest: &str) -> bool {
    rest.split('/').any(|seg| seg == "..")
}

pub(crate) async fn relay_verbatim(st: &AppState, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "failed to read request body"),
    };
    let path_q = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let path_only = parts.uri.path();

    // Session-prefixed verbatim relay: `/zlauder/session/<id>/<rest>`.
    if let Some((id, rest)) = parse_session_prefix(path_only) {
        // Traversal hardening FIRST — a legit client never sends `..`; refusing here
        // prevents `..` from evading the is_batches / pin checks by masking the real
        // target (e.g. `/zlauder/session/c1/../v1/batches`).
        if has_traversal(&rest) {
            return err(
                StatusCode::BAD_REQUEST,
                "malformed session passthrough path (traversal segment refused)",
            );
        }
        // A pinned (ZDR) conversation must never relay verbatim to the DEFAULT endpoint —
        // the verbatim relay never masks, so this would egress plaintext. Refuse 409 with
        // ZERO bytes upstream (return BEFORE any send).
        if st.zdr_selection(&id).is_some() {
            return err(
                StatusCode::CONFLICT,
                "this conversation is ZDR-pinned — refusing to relay a verbatim passthrough to \
                 the default endpoint (fail-closed; the passthrough path does not mask)",
            );
        }
        // /v1/batches is always refused under the session prefix even when NOT pinned —
        // it is a verbatim, never-masked, potentially-PII-bearing path.
        if is_batches(&rest) {
            return err(
                StatusCode::CONFLICT,
                "/v1/batches is refused for a session-scoped conversation (never masked; \
                 fail-closed)",
            );
        }
        // Not pinned: STRIP the `/zlauder/session/<id>` prefix so the relayed path is
        // exactly the inner path (e.g. `/v1/files`), carrying the original query string.
        let relay_path = match parts.uri.query() {
            Some(q) => format!("{rest}?{q}"),
            None => rest,
        };
        let adapter =
            AnthropicNative::for_mode(&st.upstream_base, st.upstream_host(), &PinnedMode::Normal);
        let wire = adapter.build(&parts.headers, &relay_path, body_bytes.to_vec());
        return relay_built(st, &parts, wire).await;
    }

    // BARE passthrough (no `/zlauder/session/` prefix). The relay never masks, so a bare
    // request carrying `x-zlauder-conversation: <pinned>` would egress PLAINTEXT to the
    // default endpoint for a ZDR-pinned conversation. Refuse 409 ZERO bytes when the
    // header names a live pin — extending the header-present defense to EVERY egress path.
    if let Some(conv) = monitor::conversation_from_headers(&parts.headers)
        && st.zdr_selection(&conv).is_some()
    {
        return err(
            StatusCode::CONFLICT,
            "this conversation is ZDR-pinned (x-zlauder-conversation) — refusing to relay a \
             verbatim passthrough to the default endpoint (fail-closed; the passthrough path \
             does not mask)",
        );
    }

    // The verbatim relay (the `passthrough` fallback) is non-session, so it is always
    // Normal in the foundation — there is no conversation id to carry a ZDR selection.
    // Routing through the adapter keeps the egress seam uniform (and byte-identical
    // for the Normal path).
    let adapter = AnthropicNative::for_mode(&st.upstream_base, st.upstream_host(), &PinnedMode::Normal);
    let wire = adapter.build(&parts.headers, path_q, body_bytes.to_vec());
    relay_built(st, &parts, wire).await
}

/// Send a built verbatim-relay request and stream the upstream response back. Factored
/// out so the session-prefix-stripped path and the bare path share one egress site.
async fn relay_built(
    st: &AppState,
    parts: &http::request::Parts,
    wire: crate::wire_adapter::WireRequest,
) -> Response {
    let resp = match st
        .http
        .request(parts.method.clone(), &wire.url)
        .headers(wire.headers)
        .body(wire.body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_GATEWAY, &format!("upstream error: {e}")),
    };
    let status = resp.status();
    let h = resp.headers().clone();
    respond(
        status,
        headers::downstream_response_headers(&h, false),
        Body::from_stream(resp.bytes_stream()),
    )
}

/// Defense-in-depth for the BARE inner intake handlers (`/v1/messages`,
/// `/v1/messages/count_tokens`, `/v1/chat/completions`, `/v1/responses` — NO session
/// prefix in the URL). Runs ONLY when the path carries no conversation id, BEFORE
/// `resolve_pinned_mode` / `into_parts`, reading the `x-zlauder-conversation` header via
/// a NON-consuming `req.headers()`. If the header names a conversation with a LIVE ZDR
/// pin, refuse 409 ZERO bytes rather than route it masked-Normal to the default endpoint
/// — the header is a routing signal for a pinned conversation, so honouring it means
/// refusing the default-endpoint egress. Returns `None` (no header / no live pin) to let
/// the handler proceed as before. Precedence: URL session-id > header-id > none.
pub(crate) fn bare_path_zdr_guard(
    st: &AppState,
    req: &Request,
    conversation: Option<&str>,
    endpoint: &str,
) -> Option<Response> {
    // Only the header-id path is in scope here: a URL session-id already drove
    // `resolve_pinned_mode`, and a None header means there is no pin to consult.
    if conversation.is_some() {
        return None;
    }
    let conv = monitor::conversation_from_headers(req.headers())?;
    if st.zdr_selection(&conv).is_some() {
        return Some(err(
            StatusCode::CONFLICT,
            &format!(
                "this conversation is ZDR-pinned (x-zlauder-conversation) — refusing the bare \
                 {endpoint} request to the default endpoint (fail-closed; route it via the \
                 session-scoped ZDR path)"
            ),
        ));
    }
    None
}

// The `Err` variant is an axum `Response` (an early-return short-circuit), which
// is intentionally large; boxing it would just add an allocation on the error path.
#[allow(clippy::result_large_err)]
async fn mask_body(st: &AppState, body: &[u8]) -> Result<(Vec<u8>, UnmaskManifest), Response> {
    // When a model is Ready OR Loading, offload the whole request walk to a blocking
    // thread. This upholds the engine invariant that ML inference ONLY ever runs on a
    // `spawn_blocking` thread, so the engine's per-inference `ml_gate` (a std mutex)
    // never blocks the async executor. Serialization now lives in that gate
    // (per-inference, default max-inflight 1), NOT a per-walk permit — so with the
    // detection cache an all-hits turn and the one-time Ready-rescan no longer freeze
    // a second same-project window (the rescan interleaves per-leaf instead of holding
    // a walk-wide permit). Pure regex-only masking (ML Disabled/Failed) is cheap and
    // stays inline (zero spawn overhead — the common path).
    //
    // We offload on `Loading` too (cheap: no inference runs yet, so the gate is never
    // taken) specifically to CLOSE the `Loading -> Ready` race: were we to gate on
    // `Ready` only, a model flipping live mid-walk would run inference inline on the
    // executor thread. The remaining inline edge is the rarer `Disabled -> Loading`
    // user-initiated flip, bounded to one request, and the gate still serializes it.
    let result = if st.engine.ml_should_offload() {
        let engine = st.engine.clone();
        let body = body.to_vec();
        match tokio::task::spawn_blocking(move || walk::mask_request(engine.as_ref(), &body)).await
        {
            Ok(r) => r,
            Err(join) => {
                return Err(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("masking task failed: {join}"),
                ));
            }
        }
    } else {
        walk::mask_request(st.engine.as_ref(), body)
    };
    match result {
        Ok(x) => Ok(x),
        // Body wasn't even valid JSON (anomalous for /v1/messages). Refuse rather
        // than forward an unparsed, potentially PII-bearing body upstream.
        Err(walk::MaskError::Json(e)) => Err(err(
            StatusCode::BAD_REQUEST,
            &format!("unparseable request body, refusing to forward: {e}"),
        )),
        // The engine refused to mask (detection error, or an encryption failure).
        // Either way we do NOT forward — refusing is the safe outcome.
        Err(walk::MaskError::Engine(e)) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("masking error, request refused: {e}"),
        )),
    }
}

#[allow(clippy::result_large_err)]
pub(crate) async fn send_upstream(
    st: &AppState,
    parts: &http::request::Parts,
    body: Vec<u8>,
    path: &str,
    pinned: &PinnedMode,
) -> Result<reqwest::Response, Response> {
    // Dispatch through the egress seam. `Normal` is byte-identical to the prior flat
    // function; `Zdr` swaps base URL + credential (the masked body is unchanged —
    // masking always applies, ZDR is routing-only in the foundation).
    let adapter = AnthropicNative::for_mode(&st.upstream_base, st.upstream_host(), pinned);
    let wire = adapter.build(&parts.headers, path, body);
    st.http
        .post(&wire.url)
        .headers(wire.headers)
        .body(wire.body)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("upstream error: {e}")))
}

pub(crate) fn respond(status: StatusCode, headers: http::HeaderMap, body: Body) -> Response {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    *r.headers_mut() = headers;
    r
}

pub(crate) fn err(status: StatusCode, msg: &str) -> Response {
    let mut r = Response::new(Body::from(msg.to_string()));
    *r.status_mut() = status;
    r
}

/// Readiness gate for LLM intake: `Some(503)` while required secrets are unresolved
/// (fail-closed), `None` once the gate is open. Only the upstream-bound intake
/// handlers call this; `/healthz` and the control plane are never gated.
pub(crate) fn secrets_gate(st: &AppState) -> Option<Response> {
    if st.secrets_ready() {
        None
    } else {
        Some(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "zlauder: required secrets are not yet resolved (or failed to resolve) — intake held",
        ))
    }
}
