//! HTTP routing: mask requests, relay upstream, unmask responses.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::routing::{get, post};
use http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use zlauder_engine::UnmaskManifest;

use crate::{admin, headers, sse, state::AppState, walk};

const MAX_BODY: usize = 64 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        // Body is this proxy's build id — the SessionStart hook reads it to detect a
        // stale long-lived proxy (older build) and restart it. Health = HTTP 200.
        .route("/healthz", get(|| async { zlauder_state::BUILD_ID }))
        .route("/zlauder/reveal/{token}", get(reveal))
        // `/privacy` control plane (all key-gated; per-project proxy).
        .route(
            "/zlauder/config",
            get(admin::get_config).put(admin::put_config),
        )
        .route("/zlauder/enable", post(admin::enable))
        .route("/zlauder/disable", post(admin::disable))
        .route("/zlauder/reload", post(admin::reload))
        .route("/zlauder/ml/enable", post(admin::ml_enable))
        .route("/zlauder/ml/disable", post(admin::ml_disable))
        .route("/v1/messages", post(messages))
        .route("/v1/messages/count_tokens", post(count_tokens))
        .fallback(passthrough)
        .with_state(state)
}

/// Audit reveal: `GET /zlauder/reveal/{token}` with header `x-zlauder-key`.
/// Local operator affordance only; not reachable by the upstream model.
async fn reveal(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if !st.authed(&hdrs) {
        return err(StatusCode::FORBIDDEN, "missing or invalid x-zlauder-key");
    }
    match st.engine.reveal(&token) {
        Some(plain) => respond(StatusCode::OK, HeaderMap::new(), Body::from(plain)),
        None => err(StatusCode::NOT_FOUND, "unknown token"),
    }
}

/// `/v1/messages` — mask request, relay, unmask response (JSON or SSE).
async fn messages(State(st): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "failed to read request body"),
    };

    let (masked, manifest) = match mask_body(&st, &body_bytes).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };

    let resp = match send_upstream(&st, &parts, masked, "/v1/messages").await {
        Ok(r) => r,
        Err(resp) => return resp,
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
        let body = sse::unmask_sse_body(Box::pin(resp.bytes_stream()), st.engine.clone(), manifest);
        respond(status, out_headers, body)
    } else {
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return err(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream body error: {e}"),
                );
            }
        };
        let out = walk::unmask_response(st.engine.as_ref(), &manifest, &bytes)
            .unwrap_or_else(|_| bytes.to_vec());
        respond(status, out_headers, Body::from(out))
    }
}

/// `/v1/messages/count_tokens` — mask request so counts reflect masked text;
/// response is `{"input_tokens":N}` (no PII), relayed verbatim.
async fn count_tokens(State(st): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "failed to read request body"),
    };
    let (masked, _manifest) = match mask_body(&st, &body_bytes).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let resp = match send_upstream(&st, &parts, masked, "/v1/messages/count_tokens").await {
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
    let url = format!("{}{}", st.upstream_base, path_q);
    let up_headers = headers::upstream_request_headers(&parts.headers, st.upstream_host());
    let resp = match st
        .http
        .request(parts.method.clone(), &url)
        .headers(up_headers)
        .body(body_bytes.to_vec())
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
        match tokio::task::spawn_blocking(move || walk::mask_request(engine.as_ref(), &body)).await {
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
        // The engine refused to mask (fail_closed detection error, or an encryption
        // failure). Either way we do NOT forward — refusing is the safe outcome.
        Err(walk::MaskError::Engine(e)) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("masking error, request refused: {e}"),
        )),
    }
}

#[allow(clippy::result_large_err)]
async fn send_upstream(
    st: &AppState,
    parts: &http::request::Parts,
    body: Vec<u8>,
    path: &str,
) -> Result<reqwest::Response, Response> {
    let url = format!("{}{}", st.upstream_base, path);
    let up_headers = headers::upstream_request_headers(&parts.headers, st.upstream_host());
    st.http
        .post(&url)
        .headers(up_headers)
        .body(body)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("upstream error: {e}")))
}

fn respond(status: StatusCode, headers: http::HeaderMap, body: Body) -> Response {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    *r.headers_mut() = headers;
    r
}

fn err(status: StatusCode, msg: &str) -> Response {
    let mut r = Response::new(Body::from(msg.to_string()));
    *r.status_mut() = status;
    r
}
