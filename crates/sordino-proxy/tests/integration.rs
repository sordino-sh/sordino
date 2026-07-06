//! End-to-end: client -> sordino-proxy -> fake upstream. Verifies that the
//! upstream receives masked text + forwarded auth headers, and the client
//! receives an unmasked response.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Json};
use axum::routing::post;
use http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use sordino_engine::{EngineConfig, MaskEngine, token_regex};
use sordino_proxy::{
    config::ConfigLayers,
    monitor::Monitor,
    routes::router as proxy_router,
    state::AppState,
    zdr::{TrustBasis, ZdrSelection, ZdrTarget},
};

/// Insert a ZDR selection into the in-memory map ONLY (no disk persistence), for routing
/// tests that exercise `resolve_pinned_mode` and do NOT assert on-disk state. This keeps the
/// outer routing tests off the process-global `SORDINO_STATE_DIR`, so they never race the
/// `zdr_persist` tests' state-dir manipulation. The disk-writing `set_zdr_selection` is only
/// needed by the persistence tests, which isolate it under their own `StateDirGuard`.
fn engage_in_memory(state: &AppState, conversation: &str, target: &str) {
    state.zdr_sessions.lock().unwrap().insert(
        conversation.to_string(),
        ZdrSelection {
            target: target.to_string(),
        },
    );
}

/// Build an `AppState` for tests (no real config files; reload points at a
/// nonexistent user layer so it's a deterministic no-op).
fn mk_state(engine: MaskEngine, upstream_base: String, admin_key: &str) -> AppState {
    AppState {
        engine: Arc::new(engine),
        http: reqwest::Client::new(),
        upstream_base: Arc::new(upstream_base),
        admin_key: Arc::new(admin_key.into()),
        layers: Arc::new(ConfigLayers {
            user: std::path::PathBuf::from("/nonexistent/sordino/config.toml"),
            project: None,
            local: None,
        }),
        project_root: Arc::new("/tmp/sordino-test-project".into()),
        port: 0,
        monitor: Monitor::new(),
        ml_control: Arc::new(std::sync::Mutex::new(())),
        config_control: Arc::new(std::sync::Mutex::new(())),
        secrets_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        secrets_status: Arc::new(std::sync::RwLock::new(
            sordino_proxy::secrets::SecretsStatus::default(),
        )),
        zdr_targets: Arc::new(std::collections::HashMap::new()),
        zdr_default: Arc::new(None),
        zdr_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        masking_disabled: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
    }
}

#[derive(Clone, Default)]
struct Captured {
    body: Arc<Mutex<String>>,
    headers: Arc<Mutex<HeaderMap>>,
    bodies: Arc<Mutex<Vec<String>>>,
    paths: Arc<Mutex<Vec<String>>>,
}

async fn fake_upstream(
    State(cap): State<Captured>,
    req: axum::extract::Request,
) -> Json<serde_json::Value> {
    cap.paths
        .lock()
        .unwrap()
        .push(req.uri().path().to_string());
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8_lossy(&body).to_string();
    *cap.body.lock().unwrap() = s.clone();
    cap.bodies.lock().unwrap().push(s.clone());
    *cap.headers.lock().unwrap() = headers;
    // Echo whatever token the masked request carried, so the proxy can unmask it.
    let tok = token_regex()
        .find(&s)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    Json(serde_json::json!({
        "content": [{"type": "text", "text": format!("ack {tok}")}],
        "model": "claude-test",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1}
    }))
}

async fn fake_openai_chat_upstream(
    State(cap): State<Captured>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<serde_json::Value> {
    let s = String::from_utf8_lossy(&body).to_string();
    *cap.body.lock().unwrap() = s.clone();
    cap.bodies.lock().unwrap().push(s.clone());
    *cap.headers.lock().unwrap() = headers;
    let tok = token_regex()
        .find(&s)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    Json(serde_json::json!({
        "id": "chatcmpl_test",
        "object": "chat.completion",
        "model": "gpt-test",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": format!("ack {tok}"),
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "send", "arguments": format!("{{\"email\":\"{tok}\"}}")}
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
}

async fn fake_openai_chat_stream_upstream(
    State(cap): State<Captured>,
    body: Bytes,
) -> impl IntoResponse {
    let s = String::from_utf8_lossy(&body).to_string();
    *cap.body.lock().unwrap() = s.clone();
    cap.bodies.lock().unwrap().push(s.clone());
    let tok = token_regex()
        .find(&s)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let data1 = serde_json::json!({
        "id": "chatcmpl_stream",
        "object": "chat.completion.chunk",
        "model": "gpt-test",
        "choices": [{"index": 0, "delta": {"content": format!("ack {tok}")}, "finish_reason": null}]
    });
    let data2 = serde_json::json!({
        "id": "chatcmpl_stream",
        "object": "chat.completion.chunk",
        "model": "gpt-test",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    });
    let body = format!("data: {data1}\n\ndata: {data2}\n\ndata: [DONE]\n\n");
    (StatusCode::OK, [(CONTENT_TYPE, "text/event-stream")], body)
}

/// A chat stream whose reply ENDS on a viable-but-incomplete token prefix (no closing
/// `]`), so the relay's carry buffer holds the trailing fragment — which the relay used to
/// drop at stream end. Exercises the held-tail drain on the chat path.
async fn fake_openai_chat_stream_held_tail_upstream(
    State(cap): State<Captured>,
    body: Bytes,
) -> impl IntoResponse {
    *cap.body.lock().unwrap() = String::from_utf8_lossy(&body).to_string();
    let data1 = serde_json::json!({
        "id": "chatcmpl_tail", "object": "chat.completion.chunk", "model": "gpt-test",
        "choices": [{"index": 0, "delta": {"content": "tail [EMAIL_ADDRESS_a1b2c3"}, "finish_reason": null}]
    });
    // A dedicated finish_reason chunk before [DONE] — a client may stop here, so the held
    // tail must be flushed BEFORE this chunk, not only before [DONE].
    let data2 = serde_json::json!({
        "id": "chatcmpl_tail", "object": "chat.completion.chunk", "model": "gpt-test",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    });
    let body = format!("data: {data1}\n\ndata: {data2}\n\ndata: [DONE]\n\n");
    (StatusCode::OK, [(CONTENT_TYPE, "text/event-stream")], body)
}

/// A (non-standard but possible) chat stream where a SINGLE chunk carries both trailing
/// content ending mid-token AND finish_reason — exercises the content→tail→terminal split.
async fn fake_openai_chat_stream_content_and_finish_upstream(
    State(cap): State<Captured>,
    body: Bytes,
) -> impl IntoResponse {
    *cap.body.lock().unwrap() = String::from_utf8_lossy(&body).to_string();
    let data1 = serde_json::json!({
        "id": "chatcmpl_combo", "object": "chat.completion.chunk", "model": "gpt-test",
        "choices": [{"index": 0, "delta": {"content": "abc [EMAIL_ab"}, "finish_reason": "stop"}]
    });
    let body = format!("data: {data1}\n\ndata: [DONE]\n\n");
    (StatusCode::OK, [(CONTENT_TYPE, "text/event-stream")], body)
}

async fn fake_responses_upstream(
    State(cap): State<Captured>,
    body: Bytes,
) -> Json<serde_json::Value> {
    let s = String::from_utf8_lossy(&body).to_string();
    *cap.body.lock().unwrap() = s.clone();
    cap.bodies.lock().unwrap().push(s.clone());
    let tok = token_regex()
        .find(&s)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    Json(serde_json::json!({
        "id": "resp_test",
        "object": "response",
        "model": "gpt-test",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": format!("ack {tok}")}]
            },
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "send",
                "arguments": format!("{{\"email\":\"{tok}\"}}")
            }
        ],
        "output_text": format!("ack {tok}")
    }))
}

async fn fake_responses_stream_upstream(
    State(cap): State<Captured>,
    body: Bytes,
) -> impl IntoResponse {
    let s = String::from_utf8_lossy(&body).to_string();
    *cap.body.lock().unwrap() = s.clone();
    cap.bodies.lock().unwrap().push(s.clone());
    let tok = token_regex()
        .find(&s)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let split = tok.len() / 2;
    let (a, b) = tok.split_at(split);
    let data1 = serde_json::json!({
        "type": "response.output_text.delta",
        "sequence_number": 1,
        "item_id": "msg_1",
        "output_index": 0,
        "content_index": 0,
        "delta": format!("ack {a}")
    });
    let data2 = serde_json::json!({
        "type": "response.output_text.delta",
        "sequence_number": 2,
        "item_id": "msg_1",
        "output_index": 0,
        "content_index": 0,
        "delta": format!("{b} done")
    });
    let data3 = serde_json::json!({
        "type": "response.completed",
        "sequence_number": 3,
        "response": {"id": "resp_stream", "object": "response", "model": "gpt-test", "output": []}
    });
    let body = format!(
        "event: response.output_text.delta\ndata: {data1}\n\nevent: response.output_text.delta\ndata: {data2}\n\nevent: response.completed\ndata: {data3}\n\n"
    );
    (StatusCode::OK, [(CONTENT_TYPE, "text/event-stream")], body)
}

async fn spawn(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn end_to_end_mask_unmask_and_header_passthrough() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "test-key");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .header("x-api-key", "sk-secret-123")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "write to dana@example.com please"}
            ]}]
        }))
        .send()
        .await
        .unwrap();
    let client_text = resp.text().await.unwrap();

    // Upstream saw masked text — no plaintext email, a token instead.
    let up_body = cap.body.lock().unwrap().clone();
    assert!(
        !up_body.contains("dana@example.com"),
        "plaintext leaked upstream: {up_body}"
    );
    assert!(
        up_body.contains("[EMAIL_ADDRESS_"),
        "no token in upstream body: {up_body}"
    );

    // Auth header forwarded verbatim; Host rewritten to the upstream.
    let up_headers = cap.headers.lock().unwrap().clone();
    assert_eq!(
        up_headers.get("x-api-key").map(|v| v.to_str().unwrap()),
        Some("sk-secret-123")
    );
    assert_eq!(
        up_headers.get("host").map(|v| v.to_str().unwrap()),
        Some(up_addr.to_string().as_str())
    );

    // Client got the response with the email restored.
    assert!(
        client_text.contains("dana@example.com"),
        "response not unmasked: {client_text}"
    );
    assert!(
        !client_text.contains("[EMAIL_ADDRESS_"),
        "token leaked to client: {client_text}"
    );
}

#[tokio::test]
async fn openai_chat_completions_mask_unmask_and_header_passthrough() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/chat/completions", post(fake_openai_chat_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "test-key");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .header("authorization", "Bearer sk-secret-123")
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "write to dana@example.com please"}]
        }))
        .send()
        .await
        .unwrap();
    let client_text = resp.text().await.unwrap();

    let up_body = cap.body.lock().unwrap().clone();
    assert!(
        !up_body.contains("dana@example.com"),
        "plaintext leaked upstream: {up_body}"
    );
    assert!(up_body.contains("[EMAIL_ADDRESS_"));

    let up_headers = cap.headers.lock().unwrap().clone();
    assert_eq!(
        up_headers.get("authorization").map(|v| v.to_str().unwrap()),
        Some("Bearer sk-secret-123")
    );

    assert!(
        client_text.contains("dana@example.com"),
        "response not unmasked: {client_text}"
    );
    assert!(
        !client_text.contains("[EMAIL_ADDRESS_"),
        "token leaked to client: {client_text}"
    );
    assert!(
        client_text.contains("{\\\"email\\\":\\\"dana@example.com\\\"}"),
        "tool arguments were not unmasked without markers: {client_text}"
    );
}

#[tokio::test]
async fn openai_chat_completions_streaming_unmasks_and_preserves_done() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route(
            "/v1/chat/completions",
            post(fake_openai_chat_stream_upstream),
        )
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "test-key");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let text = client
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "stream": true,
            "messages": [{"role": "user", "content": "write to stream@example.com please"}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let up_body = cap.body.lock().unwrap().clone();
    assert!(!up_body.contains("stream@example.com"));
    assert!(up_body.contains("[EMAIL_ADDRESS_"));
    assert!(text.contains("stream@example.com"), "not unmasked: {text}");
    assert!(
        text.contains("data: [DONE]"),
        "DONE marker not preserved: {text}"
    );
}

// A chat stream that ends mid-incomplete-token must flush the held tail to BOTH the wire
// (before [DONE]) and the monitor record — not silently drop it. Regression for the
// cumulative-audit finding that the OpenAI relays never drained their carry buffer, and
// the first integration coverage of the OpenAI chat capture→record path.
#[tokio::test]
async fn openai_chat_stream_held_tail_reaches_client_and_monitor() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route(
            "/v1/chat/completions",
            post(fake_openai_chat_stream_held_tail_upstream),
        )
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "tail-key");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let text = client
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // The held trailing fragment is flushed to the client BEFORE the finish_reason chunk
    // (and thus before [DONE]) — a client that stops at finish_reason still receives it.
    let tail_idx = text
        .find("[EMAIL_ADDRESS_a1b2c3")
        .unwrap_or_else(|| panic!("held tail dropped from the wire: {text}"));
    let finish_idx = text.find("\"stop\"").expect("finish_reason chunk present");
    let done_idx = text.find("[DONE]").expect("[DONE] present");
    assert!(tail_idx < finish_idx, "held tail must precede the finish_reason chunk: {text}");
    assert!(finish_idx < done_idx, "[DONE] is last: {text}");

    // And it is captured onto the monitor record — the reply is not truncated.
    let snap: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/monitor/snapshot"))
        .header("x-sordino-key", "tail-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rec = snap["records"]
        .as_array()
        .and_then(|rs| rs.first())
        .expect("one recorded request");
    assert_eq!(rec["decision"], "completed");
    let preview = rec["response_preview"].as_str().unwrap_or_default();
    assert!(
        preview.contains("tail [EMAIL_ADDRESS_a1b2c3"),
        "captured streamed reply was truncated: {preview}"
    );
}

// A single chunk carrying BOTH content (ending mid-token) and finish_reason must not let
// the flushed held tail jump ahead of that chunk's own content. Wire order must be
// content → tail → terminal, and the captured reply must keep the same order.
#[tokio::test]
async fn openai_chat_stream_content_and_finish_in_one_chunk_orders_correctly() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route(
            "/v1/chat/completions",
            post(fake_openai_chat_stream_content_and_finish_upstream),
        )
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "combo-key");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let text = client
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // Wire order: content "abc " → held tail → finish_reason — never reversed.
    let abc = text.find("abc ").expect("content on the wire");
    let tail = text.find("[EMAIL_ab").expect("held tail on the wire");
    let stop = text.find("\"stop\"").expect("finish_reason present");
    assert!(abc < tail, "content must precede the held tail: {text}");
    assert!(tail < stop, "held tail must precede finish_reason: {text}");

    // The captured reply preserves the correct order (wire == capture).
    let snap: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/monitor/snapshot"))
        .header("x-sordino-key", "combo-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rec = snap["records"]
        .as_array()
        .and_then(|rs| rs.first())
        .expect("one recorded request");
    let preview = rec["response_preview"].as_str().unwrap_or_default();
    assert!(
        preview.contains("abc [EMAIL_ab"),
        "captured reply order reversed: {preview}"
    );
}

#[tokio::test]
async fn openai_responses_mask_unmask_json_response() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/responses", post(fake_responses_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "test-key");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let out = client
        .post(format!("http://{proxy_addr}/v1/responses"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "input": "protect response@example.com now"
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let up_body = cap.body.lock().unwrap().clone();
    assert!(
        !up_body.contains("response@example.com"),
        "plaintext leaked upstream: {up_body}"
    );
    assert!(up_body.contains("[EMAIL_ADDRESS_"));
    assert!(out.contains("response@example.com"), "not unmasked: {out}");
    assert!(
        !out.contains("[EMAIL_ADDRESS_"),
        "token leaked to client: {out}"
    );
    assert!(
        out.contains("{\\\"email\\\":\\\"response@example.com\\\"}"),
        "function call arguments were not unmasked: {out}"
    );
}

#[tokio::test]
async fn openai_responses_streaming_unmasks_and_preserves_sse_events() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/responses", post(fake_responses_stream_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "test-key");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let text = client
        .post(format!("http://{proxy_addr}/v1/responses"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "stream": true,
            "input": "stream to response-stream@example.com"
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let up_body = cap.body.lock().unwrap().clone();
    assert!(!up_body.contains("response-stream@example.com"));
    assert!(up_body.contains("[EMAIL_ADDRESS_"));
    assert!(
        text.contains("response-stream@example.com"),
        "not unmasked: {text}"
    );
    assert!(
        text.contains("event: response.output_text.delta"),
        "event framing not preserved: {text}"
    );
    assert!(
        text.contains("event: response.completed"),
        "completed event missing: {text}"
    );
    assert!(
        !text.contains("[EMAIL_ADDRESS_"),
        "token leaked to client: {text}"
    );

    // The STREAMED reply must also land on the monitor record (the headline fix): the
    // operator sees the model's response on THIS turn, not only once the next request
    // resends it as transcript. By the time `.text()` resolved the stream had drained, so
    // CompletionGuard::complete() already finalized the record.
    let snap: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/monitor/snapshot"))
        .header("x-sordino-key", "test-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rec = snap["records"]
        .as_array()
        .and_then(|rs| rs.first())
        .expect("one recorded request");
    assert_eq!(rec["decision"], "completed", "streamed turn finalized");
    let resp_blob = rec["response_surfaces"].to_string() + &rec["response_preview"].to_string();
    assert!(
        resp_blob.contains("response-stream@example.com"),
        "streamed reply not captured onto the record: {}",
        rec["response_preview"]
    );
    // The captured reply text is UNMASKED (the run text + raw preview carry plaintext, not
    // handles). The handle still rides each token run's `TokenRef` metadata — that is the
    // same local, key-gated handle→value mapping the request surfaces carry, by design.
    let preview = rec["response_preview"].as_str().unwrap_or_default();
    assert!(
        !preview.contains("[EMAIL_ADDRESS_"),
        "masked handle leaked into the captured response text: {preview}"
    );
}

// Deterministic placeholders within a session: the SAME request masked twice
// produces a BYTE-IDENTICAL upstream body, so Anthropic's prompt-cache prefix
// stays stable across turns (R3). Also exercises cross-turn store persistence:
// a token minted on turn 1 is still resolvable on a later turn's response.
#[tokio::test]
async fn deterministic_masking_preserves_cache_prefix() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    // One engine for the whole "session" (one salt), as the proxy runs per session.
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "model": "claude-test", "max_tokens": 10,
        "system": "ops contact is eve@example.com",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "ping eve@example.com from 10.1.2.3"}
        ]}]
    });

    // Send the identical request twice (two "turns").
    for _ in 0..2 {
        let _ = client
            .post(format!("http://{proxy_addr}/v1/messages"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .text()
            .await;
    }

    let bodies = cap.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 2);
    assert!(
        bodies[0].contains("[EMAIL_ADDRESS_"),
        "not masked: {}",
        bodies[0]
    );
    assert!(!bodies[0].contains("eve@example.com"));
    // The crux: byte-identical masked output across turns → cache prefix stable.
    assert_eq!(
        bodies[0], bodies[1],
        "masked output is not deterministic across turns"
    );
}

// The `/privacy` control plane: endpoints are key-gated, and `disable` flips the
// live proxy to transparent passthrough (plaintext reaches the upstream — the
// user's explicit choice). This is the per-project live toggle.
#[tokio::test]
async fn config_endpoints_gated_and_toggle_masking() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "secret-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // GET /sordino/config without the key → 403.
    let unauth = client
        .get(format!("http://{proxy_addr}/sordino/config"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 403, "config must be key-gated");

    // With the key → 200 and `enabled: true`.
    let cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "secret-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["enabled"], serde_json::json!(true));
    assert_eq!(cfg["config"]["enabled"], serde_json::json!(true));

    // disable without the key → 403 (the injection-defense case).
    let bad = client
        .post(format!("http://{proxy_addr}/sordino/disable"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403);

    // disable WITH the key → masking off.
    let off: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/disable"))
        .header("x-sordino-key", "secret-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(off["enabled"], serde_json::json!(false));

    // Now a request with PII passes through UNMASKED (disabled == passthrough).
    let _ = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "m", "max_tokens": 10,
            "messages": [{"role":"user","content":[{"type":"text","text":"mail frank@example.com"}]}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await;
    let body_off = cap.body.lock().unwrap().clone();
    assert!(
        body_off.contains("frank@example.com"),
        "disabled should pass through: {body_off}"
    );
    assert!(!body_off.contains("[EMAIL_ADDRESS_"));

    // Re-enable and masking resumes.
    let on: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/enable"))
        .header("x-sordino-key", "secret-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(on["enabled"], serde_json::json!(true));

    let _ = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "m", "max_tokens": 10,
            "messages": [{"role":"user","content":[{"type":"text","text":"mail grace@example.com"}]}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await;
    let body_on = cap.body.lock().unwrap().clone();
    assert!(
        !body_on.contains("grace@example.com"),
        "re-enabled should mask: {body_on}"
    );
    assert!(body_on.contains("[EMAIL_ADDRESS_"));
}

// The POSTURE=DISABLED contract: flipping the master switch off is a quick, temporary
// "filter off" that must NOT touch the data policy (profile / threshold / categories /
// operators). The monitor UI's DISABLED option drives exactly these enable/disable
// endpoints, so this pins the property the feature promises: toggle masking without
// disturbing the configured policy, and get the SAME policy back on re-enable.
#[tokio::test]
async fn master_switch_toggle_preserves_data_policy() {
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, "http://127.0.0.1:1".into(), "secret-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // Establish a distinctive, hand-tuned data policy via the live control plane.
    let put = client
        .put(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "secret-key")
        .json(&serde_json::json!({
            "score_threshold": 0.73,
            "enabled_categories": ["secrets", "financial"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "policy PUT should apply");

    // Snapshot the policy fields that DISABLED must never disturb.
    let get_policy = |client: reqwest::Client, addr: String| async move {
        client
            .get(format!("http://{addr}/sordino/config"))
            .header("x-sordino-key", "secret-key")
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
    };
    let before = get_policy(client.clone(), proxy_addr.to_string()).await;
    assert_eq!(before["enabled"], serde_json::json!(true));
    // Capture the live values as the baseline (score_threshold is stored f32 and widens on
    // serialize, so compare against THIS baseline, not a decimal literal — the property under
    // test is preservation across the toggle, not the exact float rendering).
    let thresh_before = before["config"]["score_threshold"].clone();
    let cats_before = before["config"]["enabled_categories"].clone();
    assert!(
        (thresh_before.as_f64().unwrap() - 0.73).abs() < 1e-6,
        "PUT should have set the threshold: {thresh_before}"
    );

    // DISABLE (the master switch the DISABLED posture drives).
    let off: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/disable"))
        .header("x-sordino-key", "secret-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(off["enabled"], serde_json::json!(false), "master switch off");
    // The crux: the data policy is UNTOUCHED while masking is off.
    assert_eq!(
        off["config"]["score_threshold"], thresh_before,
        "threshold must survive a DISABLED toggle"
    );
    assert_eq!(
        off["config"]["enabled_categories"], cats_before,
        "categories must survive a DISABLED toggle"
    );

    // RE-ENABLE → masking back on, and the exact same policy is restored.
    let on: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/enable"))
        .header("x-sordino-key", "secret-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(on["enabled"], serde_json::json!(true), "master switch on");
    assert_eq!(on["config"]["score_threshold"], thresh_before);
    assert_eq!(on["config"]["enabled_categories"], cats_before);
}

// The ML control plane: the snapshot exposes an `ml` block (so the status line /
// `model status` can read it), the endpoints are key-gated, and `ml/disable` is a
// safe no-network operation. We deliberately do NOT exercise `ml/enable` with the
// key here — that would kick off a real model download.
#[tokio::test]
async fn ml_endpoints_gated_and_snapshot_shape() {
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, "http://127.0.0.1:1".into(), "mlkey");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // Snapshot carries the ml block: off + default model + status "disabled".
    let cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "mlkey")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["ml"]["enabled"], serde_json::json!(false));
    assert_eq!(cfg["ml"]["status"], serde_json::json!("disabled"));
    assert_eq!(
        cfg["ml"]["model"],
        serde_json::json!("openai/privacy-filter")
    );

    // Enabling is key-gated (no key → 403, and crucially triggers no load).
    let unauth = client
        .post(format!("http://{proxy_addr}/sordino/ml/enable"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 403);

    // Disable with the key is a safe no-network op → 200, still "disabled".
    let off: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/ml/disable"))
        .header("x-sordino-key", "mlkey")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(off["ml"]["status"], serde_json::json!("disabled"));
    assert_eq!(off["ml"]["enabled"], serde_json::json!(false));
}

// Live-ownership: a generic `PUT /sordino/config` must NOT enable ML even if the
// posted config says `ml.enabled = true` — only `/sordino/ml/{enable,disable}` flip
// it. (Otherwise a stale/older client could turn the model on via the wrong path,
// and crucially trigger a model load.)
#[tokio::test]
async fn put_config_cannot_flip_ml_enabled() {
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, "http://127.0.0.1:1".into(), "k2");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let mut cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "k2")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Forge `config.ml.enabled = true` and PUT it.
    let mut wire = cfg["config"].take();
    wire["ml"]["enabled"] = serde_json::json!(true);
    let put: serde_json::Value = client
        .put(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "k2")
        .json(&wire)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // ML stays disabled — no load was triggered through the generic PUT.
    assert_eq!(put["ml"]["status"], serde_json::json!("disabled"));
    assert_eq!(put["ml"]["enabled"], serde_json::json!(false));
}

// PUT /sordino/config swaps the live policy (here: turn EMAIL into redaction).
#[tokio::test]
async fn put_config_replaces_live_policy() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "kk");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // Pull the current config, set EMAIL_ADDRESS -> redact, PUT it back.
    let mut cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "kk")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wire = cfg["config"].take();
    let mut wire = wire;
    wire["entity_operators"]["EMAIL_ADDRESS"] = serde_json::json!({"kind": "redact"});
    let put = client
        .put(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "kk")
        .json(&wire)
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);

    let _ = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "m", "max_tokens": 10,
            "messages": [{"role":"user","content":[{"type":"text","text":"mail heidi@example.com"}]}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await;
    let body = cap.body.lock().unwrap().clone();
    assert!(
        body.contains("[REDACTED]"),
        "policy swap to redact didn't take: {body}"
    );
    assert!(!body.contains("heidi@example.com"));
    assert!(
        !body.contains("[EMAIL_ADDRESS_"),
        "should be redacted, not tokenized: {body}"
    );
}

#[tokio::test]
async fn monitor_default_observes_without_blocking() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "mon");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "m", "max_tokens": 10,
            "messages": [{"role":"user","content":[{"type":"text","text":"mail monitor@example.com"}]}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(cap.bodies.lock().unwrap().len(), 1);

    let snap: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/monitor/snapshot"))
        .header("x-sordino-key", "mon")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snap["mode"], "off");
    assert_eq!(snap["records"][0]["decision"], "completed");
    assert_eq!(snap["records"][0]["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(
        snap["records"][0]["request_spans"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        snap["records"][0]["response_spans"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        snap["records"][0]["request_preview"]
            .as_str()
            .unwrap()
            .contains("[EMAIL_ADDRESS_")
    );
}

#[tokio::test]
async fn monitor_backpressure_rejects_when_pending_queue_is_full() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "bp-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let mode = client
        .post(format!("http://{proxy_addr}/sordino/monitor/mode"))
        .header("x-sordino-key", "bp-key")
        .json(&serde_json::json!({
            "mode": "manual_all_llm",
            "max_pending_approvals": 1
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(mode.status(), 200);

    let c2 = client.clone();
    let first = tokio::spawn(async move {
        c2.post(format!("http://{proxy_addr}/v1/messages"))
            .json(&serde_json::json!({
                "model": "m", "max_tokens": 10,
                "messages": [{"role":"user","content":[{"type":"text","text":"mail first-bp@example.com"}]}]
            }))
            .send()
            .await
            .unwrap()
    });

    let id = wait_for_pending(&client, proxy_addr, "bp-key").await;

    let second = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "m", "max_tokens": 10,
            "messages": [{"role":"user","content":[{"type":"text","text":"mail second-bp@example.com"}]}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 403);

    let snap: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/monitor/snapshot"))
        .header("x-sordino-key", "bp-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snap["pending_count"], 1);
    assert_eq!(snap["max_pending_approvals"], 1);
    assert!(
        snap["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["decision"] == "backpressure_rejected")
    );

    let ok = client
        .post(format!(
            "http://{proxy_addr}/sordino/monitor/requests/{id}/approve"
        ))
        .header("x-sordino-key", "bp-key")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(first.await.unwrap().status(), 200);
    assert_eq!(cap.bodies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn monitor_manual_reject_never_reaches_upstream() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "reject-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let mode = client
        .post(format!("http://{proxy_addr}/sordino/monitor/mode"))
        .header("x-sordino-key", "reject-key")
        .json(&serde_json::json!({"mode":"manual_all_llm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(mode.status(), 200);

    let c2 = client.clone();
    let pending = tokio::spawn(async move {
        c2.post(format!("http://{proxy_addr}/v1/messages"))
            .json(&serde_json::json!({
                "model": "m", "max_tokens": 10,
                "messages": [{"role":"user","content":[{"type":"text","text":"mail reject@example.com"}]}]
            }))
            .send()
            .await
            .unwrap()
    });

    let id = wait_for_pending(&client, proxy_addr, "reject-key").await;
    let rej = client
        .post(format!(
            "http://{proxy_addr}/sordino/monitor/requests/{id}/reject"
        ))
        .header("x-sordino-key", "reject-key")
        .json(&serde_json::json!({"reason":"test reject"}))
        .send()
        .await
        .unwrap();
    assert_eq!(rej.status(), 200);
    let resp = pending.await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(cap.bodies.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn monitor_manual_approve_releases_request() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "approve-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    client
        .post(format!("http://{proxy_addr}/sordino/monitor/mode"))
        .header("x-sordino-key", "approve-key")
        .json(&serde_json::json!({"mode":"manual_all_llm"}))
        .send()
        .await
        .unwrap();

    let c2 = client.clone();
    let pending = tokio::spawn(async move {
        c2.post(format!("http://{proxy_addr}/v1/messages"))
            .json(&serde_json::json!({
                "model": "m", "max_tokens": 10,
                "messages": [{"role":"user","content":[{"type":"text","text":"mail approve@example.com"}]}]
            }))
            .send()
            .await
            .unwrap()
    });

    let id = wait_for_pending(&client, proxy_addr, "approve-key").await;
    let ok = client
        .post(format!(
            "http://{proxy_addr}/sordino/monitor/requests/{id}/approve"
        ))
        .header("x-sordino-key", "approve-key")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let resp = pending.await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(cap.bodies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn monitor_custom_mask_applies_to_future_requests() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "custom-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{proxy_addr}/sordino/monitor/custom-mask"))
        .header("x-sordino-key", "custom-key")
        .json(&serde_json::json!({"pattern":"ACME-ALPHA"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let _ = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "m", "max_tokens": 10,
            "messages": [{"role":"user","content":[{"type":"text","text":"project ACME-ALPHA ships"}]}]
        }))
        .send()
        .await
        .unwrap();
    let body = cap.body.lock().unwrap().clone();
    assert!(!body.contains("ACME-ALPHA"), "custom value leaked: {body}");
    assert!(
        body.contains("[CUSTOM_KEYWORD_"),
        "custom token missing: {body}"
    );
}

#[tokio::test]
async fn monitor_session_prefixed_route_groups_by_conversation() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "session-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "http://{proxy_addr}/sordino/session/convo-123/v1/messages"
        ))
        .json(&serde_json::json!({
            "model": "m", "max_tokens": 10,
            "messages": [{"role":"user","content":[{"type":"text","text":"mail session@example.com"}]}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let snap: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/monitor/snapshot"))
        .header("x-sordino-key", "session-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snap["records"][0]["conversation_id"], "convo-123");
}

// Per-conversation masking switch: turning masking OFF for ONE conversation lets that
// conversation's PII egress unmasked, WITHOUT affecting any other conversation or the
// project master switch — and re-enabling resumes masking. The endpoint is key-gated.
#[tokio::test]
async fn per_conversation_disable_isolates_to_that_conversation() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "mkey");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // Helper: send one user message on a conversation's session route, return the exact
    // bytes the (fake) upstream received.
    async fn send(client: &reqwest::Client, addr: SocketAddr, conv: &str, text: &str) -> () {
        let r = client
            .post(format!("http://{addr}/sordino/session/{conv}/v1/messages"))
            .json(&serde_json::json!({
                "model": "m", "max_tokens": 10,
                "messages": [{"role":"user","content":[{"type":"text","text": text}]}]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    // Baseline: conversation "alpha" masks its email.
    send(&client, proxy_addr, "alpha", "mail alpha1@example.com").await;
    let b = cap.body.lock().unwrap().clone();
    assert!(b.contains("[EMAIL_ADDRESS_"), "baseline should mask: {b}");
    assert!(!b.contains("alpha1@example.com"));

    // The masking endpoint is key-gated.
    let unauth = client
        .post(format!("http://{proxy_addr}/sordino/session/alpha/masking"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 403, "masking control must be key-gated");

    // Disable masking for "alpha" only.
    let off: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/session/alpha/masking"))
        .header("x-sordino-key", "mkey")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(off["disabled"], serde_json::json!(true));
    assert_eq!(off["changed"], serde_json::json!(true));
    assert_eq!(
        off["master_enabled"],
        serde_json::json!(true),
        "the project master switch stays ON"
    );

    // Now alpha's PII egresses UNMASKED.
    send(&client, proxy_addr, "alpha", "mail alpha2@example.com").await;
    let b = cap.body.lock().unwrap().clone();
    assert!(
        b.contains("alpha2@example.com"),
        "disabled conversation should pass through: {b}"
    );
    assert!(!b.contains("[EMAIL_ADDRESS_"));

    // A DIFFERENT conversation is unaffected — still masks.
    send(&client, proxy_addr, "beta", "mail beta@example.com").await;
    let b = cap.body.lock().unwrap().clone();
    assert!(
        b.contains("[EMAIL_ADDRESS_") && !b.contains("beta@example.com"),
        "other conversations must still mask: {b}"
    );

    // The config snapshot lists alpha (and only alpha) as masking-disabled.
    let cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "mkey")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cfg["masking_disabled_conversations"],
        serde_json::json!(["alpha"])
    );

    // Re-enable alpha → masking resumes.
    let on: serde_json::Value = client
        .delete(format!("http://{proxy_addr}/sordino/session/alpha/masking"))
        .header("x-sordino-key", "mkey")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(on["disabled"], serde_json::json!(false));
    assert_eq!(on["changed"], serde_json::json!(true), "was disabled → re-enabled");

    send(&client, proxy_addr, "alpha", "mail alpha3@example.com").await;
    let b = cap.body.lock().unwrap().clone();
    assert!(
        b.contains("[EMAIL_ADDRESS_") && !b.contains("alpha3@example.com"),
        "re-enabled conversation must mask again: {b}"
    );
}

async fn wait_for_pending(client: &reqwest::Client, proxy_addr: SocketAddr, key: &str) -> String {
    for _ in 0..50 {
        let snap: serde_json::Value = client
            .get(format!("http://{proxy_addr}/sordino/monitor/snapshot"))
            .header("x-sordino-key", key)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(record) =
            snap["records"].as_array().unwrap().iter().find(|r| {
                r.get("decision") == Some(&serde_json::Value::String("pending".to_string()))
            })
        {
            return record["id"].as_str().unwrap().to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("request never became pending");
}

/// Build an `AppState` whose Local layer + project_root point at a real temp dir so
/// persistence (profile / custom-mask) can be exercised end-to-end.
fn mk_state_in(
    engine: MaskEngine,
    upstream_base: String,
    admin_key: &str,
    root: &std::path::Path,
) -> AppState {
    AppState {
        engine: Arc::new(engine),
        http: reqwest::Client::new(),
        upstream_base: Arc::new(upstream_base),
        admin_key: Arc::new(admin_key.into()),
        layers: Arc::new(ConfigLayers {
            user: std::path::PathBuf::from("/nonexistent/sordino/config.toml"),
            project: Some(root.join("sordino.toml")),
            local: Some(root.join("sordino.local.toml")),
        }),
        project_root: Arc::new(root.to_string_lossy().to_string()),
        port: 0,
        monitor: Monitor::new(),
        ml_control: Arc::new(std::sync::Mutex::new(())),
        config_control: Arc::new(std::sync::Mutex::new(())),
        secrets_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        secrets_status: Arc::new(std::sync::RwLock::new(
            sordino_proxy::secrets::SecretsStatus::default(),
        )),
        zdr_targets: Arc::new(std::collections::HashMap::new()),
        zdr_default: Arc::new(None),
        zdr_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        masking_disabled: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
    }
}

// POST /sordino/profile/{name} applies the profile (threshold+categories+operator
// together) live, and a file scope persists to sordino.local.toml.
#[tokio::test]
async fn profile_endpoint_applies_and_persists() {
    let dir = std::env::temp_dir().join(format!(
        "sordino-prof-ep-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state_in(engine, "http://127.0.0.1:1".into(), "pk", &dir);
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // Apply "strict" with local scope.
    let resp: serde_json::Value = client
        .post(format!(
            "http://{proxy_addr}/sordino/profile/strict?scope=local"
        ))
        .header("x-sordino-key", "pk")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Live config reflects strict's seeded fields.
    assert_eq!(resp["config"]["profile"], serde_json::json!("strict"));
    assert!((resp["config"]["score_threshold"].as_f64().unwrap() - 0.4).abs() < 1e-6);
    let cats = resp["config"]["enabled_categories"].as_array().unwrap();
    assert!(cats.iter().any(|c| c == "personal"), "strict adds personal");
    assert_eq!(resp["scope"], serde_json::json!("local"));
    assert_eq!(resp["session_only"], serde_json::json!(false));

    // Persisted to sordino.local.toml.
    let persisted = std::fs::read_to_string(dir.join("sordino.local.toml")).unwrap();
    assert!(persisted.contains("profile = \"strict\""), "{persisted}");
    assert!(persisted.contains("score_threshold = 0.4"), "{persisted}");

    // The back-compat alias resolves to secrets_only.
    let resp: serde_json::Value = client
        .post(format!(
            "http://{proxy_addr}/sordino/profile/development_safe?scope=session"
        ))
        .header("x-sordino-key", "pk")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["config"]["profile"], serde_json::json!("secrets_only"));
    assert_eq!(resp["session_only"], serde_json::json!(true));

    // An unknown profile is a 400.
    let bad = client
        .post(format!("http://{proxy_addr}/sordino/profile/bogus"))
        .header("x-sordino-key", "pk")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    let _ = std::fs::remove_dir_all(&dir);
}

// A PARTIAL PUT merges onto the live config: omitted fields are preserved.
#[tokio::test]
async fn put_config_merges_partial_body() {
    let mut cfg = EngineConfig::default();
    cfg.entity_operators
        .insert("EMAIL_ADDRESS".into(), sordino_engine::Operator::Redact);
    let engine = MaskEngine::new(cfg).unwrap();
    let state = mk_state(engine, "http://127.0.0.1:1".into(), "mp");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // PUT ONLY a new threshold.
    let put: serde_json::Value = client
        .put(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "mp")
        .json(&serde_json::json!({ "score_threshold": 0.77 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!((put["config"]["score_threshold"].as_f64().unwrap() - 0.77).abs() < 1e-6);
    // The pre-existing entity_operators override survived the partial PUT.
    assert_eq!(
        put["config"]["entity_operators"]["EMAIL_ADDRESS"]["kind"],
        serde_json::json!("redact")
    );
}

// PUT with a typo'd entity_operators key is rejected (item 2c).
#[tokio::test]
async fn put_config_rejects_unknown_entity_operator_key() {
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, "http://127.0.0.1:1".into(), "uk");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let bad = client
        .put(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "uk")
        .json(&serde_json::json!({ "entity_operators": { "EMIAL": { "kind": "redact" } } }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    let msg = bad.text().await.unwrap();
    assert!(
        msg.contains("EMIAL"),
        "rejection should name the typo: {msg}"
    );
}

// Custom-mask: add persists to sordino.local.toml, list reflects it, remove clears
// both live and the file.
#[tokio::test]
async fn custom_mask_persist_list_remove() {
    let dir = std::env::temp_dir().join(format!("sordino-cm-{}-{}", std::process::id(), line!()));
    let _ = std::fs::create_dir_all(&dir);
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state_in(engine, "http://127.0.0.1:1".into(), "cm", &dir);
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let add: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/monitor/custom-mask"))
        .header("x-sordino-key", "cm")
        .json(&serde_json::json!({"pattern":"ACME-XYZ"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(add["session_only"], serde_json::json!(false));
    assert!(add["persisted"].is_string());
    let file = std::fs::read_to_string(dir.join("sordino.local.toml")).unwrap();
    assert!(file.contains("ACME-XYZ"), "{file}");

    // List shows it.
    let list: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/monitor/custom-mask"))
        .header("x-sordino-key", "cm")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rules = list["custom_replacements"].as_array().unwrap();
    assert!(rules.iter().any(|r| r["pattern"] == "ACME-XYZ"));

    // Remove clears both live and file.
    let rm: serde_json::Value = client
        .request(
            reqwest::Method::DELETE,
            format!("http://{proxy_addr}/sordino/monitor/custom-mask"),
        )
        .header("x-sordino-key", "cm")
        .json(&serde_json::json!({"pattern":"ACME-XYZ"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rm["removed_live"], serde_json::json!(true));
    assert_eq!(rm["removed_persisted"], serde_json::json!(true));
    let file = std::fs::read_to_string(dir.join("sordino.local.toml")).unwrap();
    assert!(!file.contains("ACME-XYZ"), "file still has rule: {file}");

    let _ = std::fs::remove_dir_all(&dir);
}

// Reveal-to-model: a custom keyphrase is allow-listed (egresses plaintext) AND its
// backing rule is dropped; the choice persists to the local allow-list. Re-mask lifts
// the allow-list entry durably.
#[tokio::test]
async fn reveal_then_remask_keyphrase_roundtrip() {
    let dir = std::env::temp_dir().join(format!("sordino-rev-{}-{}", std::process::id(), line!()));
    let _ = std::fs::create_dir_all(&dir);
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state_in(engine, "http://127.0.0.1:1".into(), "rv", &dir);
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // Seed a custom keyphrase, then reveal it to the model.
    client
        .post(format!("http://{proxy_addr}/sordino/monitor/custom-mask"))
        .header("x-sordino-key", "rv")
        .json(&serde_json::json!({"pattern":"SEKRET-1"}))
        .send()
        .await
        .unwrap();

    let rev: serde_json::Value = client
        .post(format!("http://{proxy_addr}/sordino/monitor/reveal"))
        .header("x-sordino-key", "rv")
        .json(&serde_json::json!({"value":"SEKRET-1","pattern":"SEKRET-1","entity_type":"CUSTOM_KEYWORD"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rev["ok"], serde_json::json!(true));
    assert_eq!(rev["removed_rule"], serde_json::json!(true), "backing custom rule dropped");
    assert!(rev["persisted"].is_string(), "reveal persisted: {rev}");
    // The value is now allow-listed in the returned config...
    let allowed = rev["config"]["allow_list"]["exact"].as_array().unwrap();
    assert!(allowed.iter().any(|v| v == "SEKRET-1"), "value allow-listed: {rev}");
    // ...written to the local file's [engine.allow_list], and the custom rule is gone.
    let file = std::fs::read_to_string(dir.join("sordino.local.toml")).unwrap();
    assert!(file.contains("SEKRET-1"), "allow-list persisted: {file}");
    assert!(file.contains("allow_list"), "allow_list table written: {file}");

    // The live config endpoint confirms the value egresses plaintext now.
    let cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/config"))
        .header("x-sordino-key", "rv")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let live_allowed = cfg["config"]["allow_list"]["exact"].as_array().unwrap();
    assert!(live_allowed.iter().any(|v| v == "SEKRET-1"));

    // Re-mask: lift the allow-list suppression durably.
    let rem: serde_json::Value = client
        .request(
            reqwest::Method::DELETE,
            format!("http://{proxy_addr}/sordino/monitor/reveal"),
        )
        .header("x-sordino-key", "rv")
        .json(&serde_json::json!({"value":"SEKRET-1"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rem["removed_live"], serde_json::json!(true));
    let live_allowed = rem["config"]["allow_list"]["exact"].as_array().unwrap();
    assert!(!live_allowed.iter().any(|v| v == "SEKRET-1"), "remask cleared live: {rem}");
    let file = std::fs::read_to_string(dir.join("sordino.local.toml")).unwrap();
    assert!(!file.contains("SEKRET-1"), "remask cleared the persisted allow-list: {file}");

    // Reveal/remask is key-gated like the rest of the control plane.
    let unauth = client
        .post(format!("http://{proxy_addr}/sordino/monitor/reveal"))
        .json(&serde_json::json!({"value":"x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::FORBIDDEN);

    let _ = std::fs::remove_dir_all(&dir);
}

// A8: READ-ONLY per-session inbound observability. `GET /sordino/session/{id}/routed`
// reports `routed_recently:false` for an id with no inbound, flips to `true` after a
// real inbound (keyed off Codex's `session-id` header — the override-detection case),
// and is key-gated like the rest of the control plane.
#[tokio::test]
async fn session_routed_reflects_inbound_and_is_gated() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "obs-key");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // The Codex session id (sent as the `session-id`/`thread-id` headers — Codex never
    // sends `x-sordino-conversation`).
    let sid = "019f0504-a6af-7253-8f6e-b6a41e31d7c4";

    // 1) No inbound yet for this id → routed_recently:false, last_seen_ms:null.
    let before: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/session/{sid}/routed"))
        .header("x-sordino-key", "obs-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before["routed_recently"], serde_json::json!(false));
    assert_eq!(before["last_seen_ms"], serde_json::Value::Null);

    // 2) Drive a real inbound carrying ONLY the Codex `session-id`/`thread-id` headers.
    // This proves the proxy reads the Codex header into the conversation key — without
    // that, the inbound would key as missing and the endpoint could never attribute it.
    let resp = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .header("x-api-key", "sk-secret-123")
        .header("anthropic-version", "2023-06-01")
        .header("session-id", sid)
        .header("thread-id", sid)
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "hello"}
            ]}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let _ = resp.text().await.unwrap();

    // 3) The endpoint now attributes that inbound to the session id.
    let after: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/session/{sid}/routed"))
        .header("x-sordino-key", "obs-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        after["routed_recently"],
        serde_json::json!(true),
        "inbound keyed by Codex session-id must read as routed_recently"
    );
    assert!(
        after["last_seen_ms"].as_u64().is_some(),
        "last_seen_ms must be a timestamp after inbound: {after}"
    );

    // A different, never-seen id is still not routed (no false positive on liveness).
    let other: serde_json::Value = client
        .get(format!("http://{proxy_addr}/sordino/session/never-seen-id/routed"))
        .header("x-sordino-key", "obs-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(other["routed_recently"], serde_json::json!(false));
    assert_eq!(other["last_seen_ms"], serde_json::Value::Null);

    // 4) Key-gated: no `x-sordino-key` → 403, exactly like the rest of the control plane.
    let unauth = client
        .get(format!("http://{proxy_addr}/sordino/session/{sid}/routed"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::FORBIDDEN);
}

// ---- ZDR (Trust switch) routing — chunk 2 ------------------------------------

/// Build a test state with a single registered ZDR target as the `[zdr]` default.
fn zdr_state(engine: MaskEngine, default_base: String, target: ZdrTarget) -> AppState {
    let mut s = mk_state(engine, default_base, "test-key");
    let name = target.name.clone();
    let mut map = std::collections::HashMap::new();
    map.insert(name.clone(), Arc::new(target));
    s.zdr_targets = Arc::new(map);
    s.zdr_default = Arc::new(Some(name));
    s
}

// A ZDR-active conversation routes to the verified target bearing the injected ZDR
// key — NOT the client's subscription token — and the default upstream is never hit.
// Masking still fully applies (routing-only): the ZDR upstream sees only a token.
#[tokio::test]
async fn zdr_session_routes_to_target_with_zdr_key_not_subscription() {
    let zdr_cap = Captured::default();
    let zdr_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(zdr_cap.clone());
    let zdr_addr = spawn(zdr_up).await;

    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let target = ZdrTarget::new(
        "trusted".into(),
        &format!("http://{zdr_addr}"),
        TrustBasis::SelfHosted,
        true,
        vec![],
        "zdr-key-xyz".into(),
    )
    .unwrap();

    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = zdr_state(engine, format!("http://{def_addr}"), target);
    engage_in_memory(&state, "conv1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/sordino/session/conv1/v1/messages"))
        // The client's subscription credentials — both must be stripped.
        .header("authorization", "Bearer sk-ant-oat01-SUBSCRIPTION")
        .header("x-api-key", "sk-client-key")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model":"claude-test","max_tokens":10,
            "messages":[{"role":"user","content":[{"type":"text","text":"email dana@example.com"}]}]
        }))
        .send()
        .await
        .unwrap();
    let client_text = resp.text().await.unwrap();

    let zdr_headers = zdr_cap.headers.lock().unwrap().clone();
    assert_eq!(
        zdr_headers.get("x-api-key").map(|v| v.to_str().unwrap()),
        Some("zdr-key-xyz"),
        "ZDR credential must be injected"
    );
    assert!(
        zdr_headers.get("authorization").is_none(),
        "subscription token must be stripped, never sent to the ZDR endpoint"
    );
    assert_eq!(
        zdr_headers.get("host").map(|v| v.to_str().unwrap()),
        Some(zdr_addr.to_string().as_str()),
        "Host rewritten to the ZDR target"
    );
    // Routing-only: masking still applies — the ZDR upstream sees a token, not PII.
    let zdr_body = zdr_cap.body.lock().unwrap().clone();
    assert!(
        !zdr_body.contains("dana@example.com"),
        "plaintext leaked to ZDR upstream: {zdr_body}"
    );
    assert!(zdr_body.contains("[EMAIL_ADDRESS_"));
    // The default upstream was never contacted.
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "default upstream must not be hit while ZDR-active"
    );
    // Client got the unmasked response.
    assert!(client_text.contains("dana@example.com"));
}

// H4/D4: the CAPTURED upstream destination rides each RequestRecord, value-free
// (target NAME only), so a ZDR-routed request is distinguishable from a silently-
// degraded Normal one in BOTH the snapshot JSON and (via `r.upstream`) the monitor UI.
// A ZDR pin (engaged via the in-memory selection) records `"zdr:box"`; an unpinned
// request records `"anthropic"`. The value is sourced from the PinnedMode captured at
// routing time, NOT a re-read of `zdr_sessions` — and never carries the ZdrKey.
#[tokio::test]
async fn request_record_captures_destination() {
    // --- ZDR-pinned request: captured upstream == "zdr:box" ---
    let zdr_cap = Captured::default();
    let zdr_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(zdr_cap.clone());
    let zdr_addr = spawn(zdr_up).await;

    let secret_zdr_key = "zdr-key-SECRET-bytes-xyz";
    let target = ZdrTarget::new(
        "box".into(),
        &format!("http://{zdr_addr}"),
        TrustBasis::SelfHosted,
        true,
        vec![],
        secret_zdr_key.into(),
    )
    .unwrap();
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = zdr_state(engine, format!("http://{zdr_addr}"), target);
    engage_in_memory(&state, "conv1", "box");
    // Hold a Monitor handle before `state` is moved into the router.
    let monitor = state.monitor.clone();
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    client
        .post(format!("http://{proxy_addr}/sordino/session/conv1/v1/messages"))
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model":"claude-test","max_tokens":10,
            "messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let snap = monitor.snapshot();
    let rec = snap
        .records
        .iter()
        .find(|r| r.conversation_id == "conv1")
        .expect("a record for the ZDR conversation");
    assert_eq!(
        rec.upstream.as_deref(),
        Some("zdr:box"),
        "ZDR pin captures the target NAME as the destination"
    );
    // VALUE-FREE: the serialized record carries only the target NAME, never key bytes.
    let serialized = serde_json::to_string(rec).unwrap();
    assert!(
        !serialized.contains(secret_zdr_key),
        "ZdrKey bytes must NEVER appear in a serialized record: {serialized}"
    );

    // --- unpinned (Normal) request: captured upstream == "anthropic" ---
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;
    let engine2 = MaskEngine::new(EngineConfig::default()).unwrap();
    let state2 = mk_state(engine2, format!("http://{def_addr}"), "test-key");
    let monitor2 = state2.monitor.clone();
    let proxy2_addr = spawn(proxy_router(state2)).await;

    client
        .post(format!("http://{proxy2_addr}/v1/messages"))
        .header("x-api-key", "sk-secret-123")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model":"claude-test","max_tokens":10,
            "messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let snap2 = monitor2.snapshot();
    let rec2 = snap2.records.first().expect("a record for the Normal request");
    assert_eq!(
        rec2.upstream.as_deref(),
        Some("anthropic"),
        "an unpinned request records the Normal destination (distinguishable from ZDR)"
    );
}

// A selection naming an UNKNOWN target refuses (409) — fail-closed, never silently
// routed to the default endpoint.
#[tokio::test]
async fn zdr_unknown_selection_refuses_fail_closed() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;
    let target = ZdrTarget::new(
        "trusted".into(),
        &format!("http://{def_addr}"),
        TrustBasis::SelfHosted,
        true,
        vec![],
        "k".into(),
    )
    .unwrap();
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = zdr_state(engine, format!("http://{def_addr}"), target);
    engage_in_memory(&state, "conv1", "ghost"); // not in the registry
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/sordino/session/conv1/v1/messages"))
        .json(&serde_json::json!({"model":"m","max_tokens":1,"messages":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "fail-closed: nothing dispatched on an unresolvable selection"
    );
}

// A selection referencing a non-`user_verified` target refuses (403) — defense in
// depth beyond the engage-time check.
#[tokio::test]
async fn zdr_unverified_target_refuses_fail_closed() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;
    let target = ZdrTarget::new(
        "unverified".into(),
        &format!("http://{def_addr}"),
        TrustBasis::SelfHosted,
        false, // not user_verified
        vec![],
        "k".into(),
    )
    .unwrap();
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = zdr_state(engine, format!("http://{def_addr}"), target);
    engage_in_memory(&state, "conv1", "unverified");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/sordino/session/conv1/v1/messages"))
        .json(&serde_json::json!({"model":"m","max_tokens":1,"messages":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(def_cap.body.lock().unwrap().is_empty());
}

// H1 race seal (A5): a RESTORED selection — one already present in the in-memory
// `zdr_sessions` map at AppState construction, exactly as A4's `reload_zdr_sessions`
// feeds it BEFORE the server begins serving — whose target is invalidated to
// `!user_verified` by a concurrent control-plane change, is RE-VALIDATED AT ENTRY
// (`resolve_pinned_mode`) and refuses 403 with ZERO bytes egressed. It must never
// dispatch against an engage-time verification snapshot (which would be `Ok(Normal)`
// → a silent leak). This codifies that the entry-time fail-closed taxonomy survives
// A4: the selection is placed (engage succeeds while verified) and only THEN the
// registry is swapped to the same-named-but-unverified target, so the refusal can
// only come from the re-read at request entry, not from the engage-time path.
#[tokio::test]
async fn entry_revalidation_refuses_unverified_restored() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    // Construct with the target VERIFIED so the selection can be placed (mirrors A4
    // restoring a pin that was valid at the time it was persisted).
    let verified = ZdrTarget::new(
        "restored".into(),
        &format!("http://{def_addr}"),
        TrustBasis::SelfHosted,
        true, // user_verified at engage time
        vec![],
        "k".into(),
    )
    .unwrap();
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let mut state = zdr_state(engine, format!("http://{def_addr}"), verified);
    // Place the RESTORED selection in the in-memory map (as A4's reload would, before
    // the server serves).
    engage_in_memory(&state, "conv1", "restored");

    // Concurrent control-plane change: the SAME target is now `!user_verified`. Swap the
    // registry before serving — the restored selection is now stale-but-still-pinned.
    let invalidated = ZdrTarget::new(
        "restored".into(),
        &format!("http://{def_addr}"),
        TrustBasis::SelfHosted,
        false, // no longer user_verified
        vec![],
        "k".into(),
    )
    .unwrap();
    let mut map = std::collections::HashMap::new();
    map.insert("restored".to_string(), Arc::new(invalidated));
    state.zdr_targets = Arc::new(map);

    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/sordino/session/conv1/v1/messages"))
        .json(&serde_json::json!({"model":"m","max_tokens":1,"messages":[]}))
        .send()
        .await
        .unwrap();
    // resolve_pinned_mode returned Err (403), never Ok(Normal): the restored pin is
    // re-validated at entry and refused.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a restored selection whose target is now !user_verified must refuse 403 at entry, \
         never silently downgrade to Normal"
    );
    // Zero bytes egressed to the default upstream — the fail-closed taxonomy held.
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "fail-closed: nothing may be dispatched on a restored-then-invalidated selection"
    );
}

// The OpenAI-compatible endpoints refuse a ZDR-active conversation (501) — the
// foundation is Anthropic-wire only; never silently route it to Anthropic.
#[tokio::test]
async fn zdr_openai_path_refuses() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/chat/completions", post(fake_openai_chat_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;
    let target = ZdrTarget::new(
        "trusted".into(),
        &format!("http://{def_addr}"),
        TrustBasis::SelfHosted,
        true,
        vec![],
        "k".into(),
    )
    .unwrap();
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = zdr_state(engine, format!("http://{def_addr}"), target);
    engage_in_memory(&state, "conv1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://{proxy_addr}/sordino/session/conv1/v1/chat/completions"
        ))
        .json(&serde_json::json!({"model":"gpt","messages":[{"role":"user","content":"hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_IMPLEMENTED);
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "must not dispatch when refusing"
    );
}

// The control endpoint: engage (verified) warns about the cache break and sets
// active; GET reflects it; unverified→400, unknown→404; DELETE disengages; all
// key-gated.
#[tokio::test]
async fn zdr_control_endpoint_engage_status_and_refuse() {
    // This test drives the LIVE POST/DELETE /zdr routes, whose handlers
    // (`set_zdr_selection`/`clear_zdr_selection`) write to the process-global
    // `state_dir()`. Isolate that I/O under the shared `ENV_LOCK` + a private temp
    // dir so a concurrent `zdr_persist` test can never see this test's selection
    // file land in its single-tenant temp dir (the prior load-dependent flake).
    // Safe to hold across `.await`: every test here is current-thread `#[tokio::test]`.
    let _state_dir = zdr_persist::StateDirGuard::new("zdr-control-endpoint");
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;
    let verified = ZdrTarget::new(
        "trusted".into(),
        &format!("http://{def_addr}"),
        TrustBasis::SelfHosted,
        true,
        vec![],
        "k".into(),
    )
    .unwrap();
    let unverified = ZdrTarget::new(
        "raw".into(),
        &format!("http://{def_addr}"),
        TrustBasis::SelfHosted,
        false,
        vec![],
        "k".into(),
    )
    .unwrap();
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let mut state = mk_state(engine, format!("http://{def_addr}"), "test-key");
    let mut map = std::collections::HashMap::new();
    map.insert("trusted".to_string(), Arc::new(verified));
    map.insert("raw".to_string(), Arc::new(unverified));
    state.zdr_targets = Arc::new(map);
    state.zdr_default = Arc::new(Some("trusted".into()));
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    // Key-gated.
    let unauth = client
        .post(format!("http://{proxy_addr}/sordino/session/c/zdr"))
        .json(&serde_json::json!({"config":"trusted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::FORBIDDEN);

    // Engage a verified config.
    let ok = client
        .post(format!("http://{proxy_addr}/sordino/session/c/zdr"))
        .header("x-sordino-key", "test-key")
        .json(&serde_json::json!({"config":"trusted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(body["active"], serde_json::json!("trusted"));
    assert!(
        body["warning"].as_str().unwrap_or("").contains("cache"),
        "engage must warn about the cache break: {body}"
    );

    // GET status reflects the active selection.
    let st = client
        .get(format!("http://{proxy_addr}/sordino/session/c/zdr"))
        .header("x-sordino-key", "test-key")
        .send()
        .await
        .unwrap();
    let stj: serde_json::Value = st.json().await.unwrap();
    assert_eq!(stj["active"], serde_json::json!("trusted"));

    // Engaging an unverified config → 400.
    let unv = client
        .post(format!("http://{proxy_addr}/sordino/session/c2/zdr"))
        .header("x-sordino-key", "test-key")
        .json(&serde_json::json!({"config":"raw"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unv.status(), reqwest::StatusCode::BAD_REQUEST);

    // Engaging an unknown config → 404.
    let unk = client
        .post(format!("http://{proxy_addr}/sordino/session/c3/zdr"))
        .header("x-sordino-key", "test-key")
        .json(&serde_json::json!({"config":"nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unk.status(), reqwest::StatusCode::NOT_FOUND);

    // DELETE disengages.
    let del = client
        .delete(format!("http://{proxy_addr}/sordino/session/c/zdr"))
        .header("x-sordino-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), reqwest::StatusCode::OK);
    let delj: serde_json::Value = del.json().await.unwrap();
    assert_eq!(delj["active"], serde_json::Value::Null);
    assert_eq!(delj["disengaged"], serde_json::json!(true));
}

// ===========================================================================
// A4 / H1 / D1 — persist + reload + re-validate per-conversation ZDR selection
// ===========================================================================
//
// These tests drive `state_dir()` (which keys off the process-global
// `SORDINO_STATE_DIR` env var) so they SERIALIZE behind a single mutex and each
// points at its own temp dir. They are synchronous (`#[test]`) because every
// persistence method (set/clear/load/reload) is synchronous.

mod zdr_persist {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex as StdMutex;
    use sordino_proxy::state::{PersistedLoad, PersistedSelection, ReloadOutcome};

    // Serializes the `SORDINO_STATE_DIR` env mutation across the parallel test harness.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    /// RAII: set `SORDINO_STATE_DIR` to a fresh temp dir for the duration, restoring the
    /// prior value (and removing the temp tree) on drop. Holds the serialization guard.
    ///
    /// `pub(super)` so live-route tests OUTSIDE this module that write to `state_dir()`
    /// (e.g. the control-endpoint POST/DELETE test) can serialize behind the SAME
    /// `ENV_LOCK` and land their writes in an isolated temp dir — otherwise their
    /// unguarded `set_zdr_selection` writes leak into a concurrent guard's temp dir and
    /// break the single-tenant `find_one` assumption here.
    pub(super) struct StateDirGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        dir: PathBuf,
        prev: Option<std::ffi::OsString>,
    }
    impl StateDirGuard {
        pub(super) fn new(tag: &str) -> StateDirGuard {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "sordino-zdr-persist-{}-{}-{}",
                std::process::id(),
                tag,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os("SORDINO_STATE_DIR");
            // SAFETY: serialized by ENV_LOCK; no other thread reads/writes this var
            // concurrently for the guard's lifetime.
            unsafe { std::env::set_var("SORDINO_STATE_DIR", &dir) };
            StateDirGuard {
                _lock: lock,
                dir,
                prev,
            }
        }
        fn path(&self) -> &Path {
            &self.dir
        }
    }
    impl Drop for StateDirGuard {
        fn drop(&mut self) {
            // SAFETY: still serialized by the held ENV_LOCK guard.
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("SORDINO_STATE_DIR", v),
                    None => std::env::remove_var("SORDINO_STATE_DIR"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn engine() -> MaskEngine {
        MaskEngine::new(EngineConfig::default()).unwrap()
    }

    /// An `AppState` rooted at a stable project path so `project_key` (and thus the
    /// selections/report file names) are deterministic for a single test.
    fn state_for(root: &str, targets: Vec<ZdrTarget>) -> AppState {
        let mut s = mk_state(engine(), "http://127.0.0.1:1".into(), "test-key");
        s.project_root = Arc::new(root.to_string());
        let mut map = std::collections::HashMap::new();
        for t in targets {
            map.insert(t.name.clone(), Arc::new(t));
        }
        s.zdr_targets = Arc::new(map);
        s
    }

    fn target(name: &str, verified: bool) -> ZdrTarget {
        ZdrTarget::new(
            name.into(),
            "http://127.0.0.1:9",
            TrustBasis::SelfHosted,
            verified,
            vec![],
            "zdr-secret-key-bytes".into(),
        )
        .unwrap()
    }

    // The selections/global files are named by `project_key(root)`, which the test crate
    // cannot recompute (no direct blake3/sordino-state dep). Each test uses its OWN temp
    // state dir, so there is at most ONE such file — discover it by globbing rather than by
    // name. (`root` is accepted for call-site clarity; the dir is single-tenant per test.)
    fn selections_path(dir: &Path, _root: &str) -> PathBuf {
        find_one(&dir.join("zdr-sessions"), |n| {
            n.ends_with(".json") && !n.contains(".corrupt-")
        })
        .unwrap_or_else(|| dir.join("zdr-sessions").join("MISSING.json"))
    }
    fn report_path(dir: &Path, conversation: &str) -> PathBuf {
        dir.join("zdr-reports").join(format!("{conversation}.json"))
    }
    fn global_report_path(dir: &Path, _root: &str) -> PathBuf {
        find_one(&dir.join("zdr-reports"), |n| n.ends_with(".global.json"))
            .unwrap_or_else(|| dir.join("zdr-reports").join("MISSING.global.json"))
    }

    /// The single directory entry whose file name matches `pred`, or `None`.
    fn find_one(dir: &Path, pred: impl Fn(&str) -> bool) -> Option<PathBuf> {
        std::fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(&pred)
                    .unwrap_or(false)
            })
    }

    #[cfg(unix)]
    fn set_mode(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Make the `zdr-sessions` SUBDIR un-creatable by occupying its path with a regular
    /// FILE — a robust write-failure injection that the production `create_dir_all` +
    /// `chmod 0700` cannot undo (chmod on a dir we own is always permitted, so a 0500 mode
    /// would be silently reset; a wrong file TYPE is permanent). Returns the path so the
    /// caller can remove it for cleanup.
    fn block_sessions_dir(state_dir: &Path) -> PathBuf {
        let p = state_dir.join("zdr-sessions");
        let _ = std::fs::remove_dir_all(&p);
        std::fs::write(&p, b"not a dir").unwrap();
        p
    }
    /// Same robust injection for the report dir (used to force the global-revert write to
    /// fail on the Corrupt branch).
    fn block_reports_dir(state_dir: &Path) -> PathBuf {
        let p = state_dir.join("zdr-reports");
        let _ = std::fs::remove_dir_all(&p);
        std::fs::write(&p, b"not a dir").unwrap();
        p
    }

    // ---- ACCEPTANCE: concrete trace 1 -------------------------------------
    // Persisted [box(verified), gone(missing)] + unverified entry → restored verified,
    // dropped missing, dropped unverified, disk rewritten, NO credential bytes on disk,
    // the persisted JSON carries the NAME "box" not the resolved key bytes.
    #[test]
    fn persisted_selection_revalidates_fail_closed() {
        let g = StateDirGuard::new("revalidate");
        let root = "/proj/revalidate";

        // First, durably engage three conversations on a state where ALL three targets
        // resolve verified, so the selections file holds all three.
        {
            let s = state_for(
                root,
                vec![target("box", true), target("old", true), target("raw", true)],
            );
            s.set_zdr_selection("c1", "box").unwrap();
            s.set_zdr_selection("c2", "old").unwrap(); // will be "missing" on reload
            s.set_zdr_selection("c3", "raw").unwrap(); // will be "unverified" on reload
        }

        // The on-disk selections file must carry the NAME, never the key bytes.
        let sel_bytes = std::fs::read(selections_path(g.path(), root)).unwrap();
        let sel_str = String::from_utf8(sel_bytes).unwrap();
        assert!(sel_str.contains("\"box\""), "persisted name present: {sel_str}");
        assert!(
            !sel_str.contains("zdr-secret-key-bytes"),
            "NO credential bytes may reach the selections file: {sel_str}"
        );

        // Reload with a registry where only `box` resolves verified; `old` is absent and
        // `raw` is present-but-unverified.
        let s2 = state_for(root, vec![target("box", true), target("raw", false)]);
        let load = s2.load_persisted_selections();
        assert!(matches!(load, PersistedLoad::Loaded(_)), "{load:?}");
        let report = s2.reload_zdr_sessions(load).expect("reload must not fail");

        // In-memory map: only c1→box survives.
        assert_eq!(
            s2.zdr_selection("c1").map(|s| s.target),
            Some("box".to_string())
        );
        assert!(s2.zdr_selection("c2").is_none(), "missing target dropped");
        assert!(s2.zdr_selection("c3").is_none(), "unverified target dropped");

        // Report outcomes.
        assert!(report.outcomes.contains(&ReloadOutcome::Restored {
            conversation: "c1".into(),
            target: "box".into()
        }));
        assert!(report.outcomes.contains(&ReloadOutcome::Reverted {
            conversation: "c2".into(),
            reason: "target no longer configured".into()
        }));
        assert!(report.outcomes.contains(&ReloadOutcome::Reverted {
            conversation: "c3".into(),
            reason: "target no longer user_verified".into()
        }));

        // Per-conversation report files written.
        let r1: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report_path(g.path(), "c1")).unwrap()).unwrap();
        assert_eq!(r1["kind"], "restored");
        assert_eq!(r1["target"], "box");
        let r2: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report_path(g.path(), "c2")).unwrap()).unwrap();
        assert_eq!(r2["kind"], "reverted");

        // Disk rewritten to ONLY the surviving entry, still carrying the name not the key.
        let rewritten = std::fs::read_to_string(selections_path(g.path(), root)).unwrap();
        assert!(rewritten.contains("\"box\""));
        assert!(!rewritten.contains("\"old\""), "dropped entry gone from disk");
        assert!(!rewritten.contains("\"raw\""), "dropped entry gone from disk");
        assert!(!rewritten.contains("zdr-secret-key-bytes"));
    }

    // ---- ACCEPTANCE (A10fix3 Fix 1): dedupe duplicate-conversation entries on reload ----
    // A 0600 selections file is normally serialized from a HashMap (never duplicated), but
    // the user could hand-edit it. A file with TWO entries for the same conversation —
    // [{c, valid}, {c, missing}] — must NOT process `c` twice (which used to restore `c`
    // into the map via the first/valid entry AND overwrite c.json=Reverted via the
    // second/missing entry — a map says ZDR / report says Reverted contradiction). The
    // dedupe (last-wins) processes `c` EXACTLY ONCE: the LAST entry (missing target) wins,
    // so the map drops `c` AND c.json reports Reverted — they AGREE.
    #[test]
    fn reload_dedupes_duplicate_conversation_map_matches_report() {
        let g = StateDirGuard::new("dedupe-last-wins");
        let root = "/proj/dedupe-last-wins";

        // Create the real key-named selections file via a single engage, then overwrite it
        // in place with a hand-tampered DUPLICATE-conversation array (still valid JSON).
        {
            let s = state_for(root, vec![target("box", true)]);
            s.set_zdr_selection("seed", "box").unwrap();
        }
        let sp = selections_path(g.path(), root);
        // [{c, box(valid)}, {c, gone(missing)}] — duplicate conversation `c`, last = missing.
        let dup = serde_json::json!([
            {"conversation": "c", "target": "box"},
            {"conversation": "c", "target": "gone"},
        ]);
        std::fs::write(&sp, serde_json::to_vec(&dup).unwrap()).unwrap();

        // Reload with a registry where ONLY `box` resolves verified; `gone` is absent.
        let s2 = state_for(root, vec![target("box", true)]);
        let load = s2.load_persisted_selections();
        assert!(matches!(load, PersistedLoad::Loaded(_)), "{load:?}");
        let report = s2.reload_zdr_sessions(load).expect("reload must not fail");

        // Processed EXACTLY ONCE: exactly one outcome for `c`.
        let c_outcomes: Vec<_> = report
            .outcomes
            .iter()
            .filter(|o| {
                matches!(o,
                    ReloadOutcome::Restored { conversation, .. }
                    | ReloadOutcome::Reverted { conversation, .. } if conversation == "c")
            })
            .collect();
        assert_eq!(
            c_outcomes.len(),
            1,
            "duplicate conversation must be processed exactly once (got {c_outcomes:?})"
        );

        // Last-wins: the `gone` (missing) entry wins → Reverted, NOT Restored.
        assert!(
            matches!(c_outcomes[0], ReloadOutcome::Reverted { .. }),
            "last-occurrence (missing target) must win → Reverted (got {:?})",
            c_outcomes[0]
        );

        // MAP == REPORT: the in-memory map drops `c` (routes masked-Normal) AND the
        // c.json report says Reverted — no contradiction.
        assert!(
            s2.zdr_selection("c").is_none(),
            "last-wins missing target means the in-memory map must NOT route `c` ZDR"
        );
        let rep: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report_path(g.path(), "c")).unwrap()).unwrap();
        assert_eq!(
            rep["kind"], "reverted",
            "c.json must AGREE with the dropped-from-map decision (both Normal/Reverted)"
        );

        // The rewritten survivors file has NO duplicate `c` entry (the dropped one is gone).
        let rewritten = std::fs::read_to_string(selections_path(g.path(), root)).unwrap();
        let survivors: Vec<PersistedSelection> = serde_json::from_str(&rewritten).unwrap();
        assert!(
            !survivors.iter().any(|e| e.conversation == "c"),
            "a reverted (missing) conversation must not linger on disk: {rewritten}"
        );
    }

    // ---- ACCEPTANCE (A10fix3 Fix 1, mirror): last-wins where the LAST entry is VALID ----
    // [{c, gone(missing)}, {c, box(valid)}] → last (valid) wins → Restored, map routes ZDR,
    // c.json=Restored — again map==report, processed once.
    #[test]
    fn reload_dedupe_last_valid_wins_map_matches_report() {
        let g = StateDirGuard::new("dedupe-last-valid");
        let root = "/proj/dedupe-last-valid";

        {
            let s = state_for(root, vec![target("box", true)]);
            s.set_zdr_selection("seed", "box").unwrap();
        }
        let sp = selections_path(g.path(), root);
        // Duplicate `c`: first missing, LAST valid → last-wins keeps the valid one.
        let dup = serde_json::json!([
            {"conversation": "c", "target": "gone"},
            {"conversation": "c", "target": "box"},
        ]);
        std::fs::write(&sp, serde_json::to_vec(&dup).unwrap()).unwrap();

        let s2 = state_for(root, vec![target("box", true)]);
        let load = s2.load_persisted_selections();
        let report = s2.reload_zdr_sessions(load).expect("reload must not fail");

        let c_outcomes: Vec<_> = report
            .outcomes
            .iter()
            .filter(|o| {
                matches!(o,
                    ReloadOutcome::Restored { conversation, .. }
                    | ReloadOutcome::Reverted { conversation, .. } if conversation == "c")
            })
            .collect();
        assert_eq!(c_outcomes.len(), 1, "processed exactly once: {c_outcomes:?}");

        // Last (valid) wins → Restored, map routes ZDR, report Restored — agree.
        assert_eq!(
            s2.zdr_selection("c").map(|s| s.target),
            Some("box".to_string()),
            "last-occurrence valid target must restore `c` into the map"
        );
        let rep: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report_path(g.path(), "c")).unwrap()).unwrap();
        assert_eq!(rep["kind"], "restored");
        assert_eq!(rep["target"], "box");
    }

    // ---- ACCEPTANCE: corrupt boot fails when the global revert is unwritable ----
    // S1 ordering: corrupt selections file present + report dir unwritable → the
    // global-revert WRITE fails → reload returns Err (boot fails; no silent empty map).
    #[test]
    #[cfg(unix)]
    fn corrupt_boot_fails_when_global_revert_unwritable() {
        let g = StateDirGuard::new("corrupt-fatal");
        let root = "/proj/corrupt-fatal";

        // Create the real key-named selections file by engaging once, then corrupt it
        // in place (torn write — invalid JSON).
        {
            let s = state_for(root, vec![target("box", true)]);
            s.set_zdr_selection("seed", "box").unwrap();
        }
        let sp = selections_path(g.path(), root);
        std::fs::write(&sp, b"{\"conversa").unwrap();

        // Make the report dir UN-CREATABLE so the global-revert write fails (occupy its
        // path with a regular file — survives the production create_dir_all/chmod).
        let blocked = block_reports_dir(g.path());

        let s = state_for(root, vec![target("box", true)]);
        let load = s.load_persisted_selections();
        assert!(
            matches!(load, PersistedLoad::Corrupt(_)),
            "torn write must classify Corrupt, got {load:?}"
        );
        let res = s.reload_zdr_sessions(load);
        // Remove the blocker so the temp tree can be cleaned up.
        let _ = std::fs::remove_file(&blocked);
        assert!(
            res.is_err(),
            "a failed global-revert write on Corrupt MUST fail the boot (no silent empty map)"
        );
        // The in-memory map stays empty (never silently Normal-routed with a hidden ZDR).
        assert!(s.zdr_selection("c1").is_none());
    }

    // ---- ACCEPTANCE: Corrupt distinct from first boot ---------------------
    // Corrupt → empty map + global "*" revert (epoch-bearing) + file quarantined.
    // Absent → empty map, NO report, silent.
    #[test]
    fn corrupt_emits_global_revert_absent_is_silent() {
        // Corrupt path.
        {
            let g = StateDirGuard::new("corrupt-visible");
            let root = "/proj/corrupt-visible";
            // Create the real key-named selections file, then corrupt it in place.
            {
                let seed = state_for(root, vec![target("box", true)]);
                seed.set_zdr_selection("seed", "box").unwrap();
            }
            let sp = selections_path(g.path(), root);
            std::fs::write(&sp, b"{\"conversa").unwrap();

            let s = state_for(root, vec![]);
            let report = s
                .reload_zdr_sessions(s.load_persisted_selections())
                .expect("global revert is writable here → Ok");
            // Single global "*" revert.
            assert_eq!(report.outcomes.len(), 1);
            assert!(matches!(
                &report.outcomes[0],
                ReloadOutcome::Reverted { conversation, .. } if conversation == "*"
            ));
            // Global file carries an epoch.
            let gv: serde_json::Value =
                serde_json::from_slice(&std::fs::read(global_report_path(g.path(), root)).unwrap())
                    .unwrap();
            assert_eq!(gv["conversation"], "*");
            assert!(gv["epoch"].as_u64().unwrap() > 0, "epoch must be present: {gv}");
            // The unparseable file was quarantined (renamed away) → original gone.
            assert!(!sp.exists(), "corrupt file must be quarantined (renamed)");
            let quarantined: Vec<_> = std::fs::read_dir(sp.parent().unwrap())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .contains(".json.corrupt-")
                })
                .collect();
            assert_eq!(quarantined.len(), 1, "exactly one quarantined file");
            assert!(s.zdr_selection("anything").is_none());
        }
        // Absent path: first boot → empty map, NO report, silent.
        {
            let g = StateDirGuard::new("first-boot");
            let root = "/proj/first-boot";
            let s = state_for(root, vec![]);
            assert!(matches!(s.load_persisted_selections(), PersistedLoad::Absent));
            let report = s
                .reload_zdr_sessions(s.load_persisted_selections())
                .unwrap();
            assert!(report.outcomes.is_empty(), "first boot must be silent");
            assert!(!global_report_path(g.path(), root).exists());
        }
    }

    // ---- ACCEPTANCE (A10fix4): the global Corrupt sentinel is a CURRENT-INSTANCE signal ----
    // A past corrupt boot writes `<project_key>.global.json`. On a LATER clean boot (Absent or
    // Loaded) the sentinel must be REMOVED — otherwise A6's consume_zdr_transitions narrates the
    // stale "ALL ZDR selections lost" line to every conversation first seen on the clean boot
    // (including brand-new ones), crying wolf forever. We drive a real corrupt boot first so the
    // sentinel lands at the EXACT production path (the test crate cannot recompute project_key),
    // then assert a subsequent clean reload removes it.
    #[test]
    fn clean_boot_clears_stale_global_sentinel() {
        // --- Absent clean boot clears the stale sentinel ---
        {
            let g = StateDirGuard::new("clean-clears-sentinel-absent");
            let root = "/proj/clean-clears-sentinel-absent";

            // Prior corrupt boot: seed + corrupt the selections file, reload → writes sentinel
            // AND quarantines the file (so the NEXT load is Absent).
            {
                let seed = state_for(root, vec![target("box", true)]);
                seed.set_zdr_selection("seed", "box").unwrap();
            }
            let sp = selections_path(g.path(), root);
            std::fs::write(&sp, b"{\"conversa").unwrap();
            let corrupt = state_for(root, vec![]);
            corrupt
                .reload_zdr_sessions(corrupt.load_persisted_selections())
                .expect("global revert writable → Ok");
            let sentinel = global_report_path(g.path(), root);
            assert!(
                sentinel.exists(),
                "the prior corrupt boot must have written the global sentinel"
            );

            // Now a CLEAN Absent boot (the corrupt file was quarantined away).
            let clean = state_for(root, vec![]);
            assert!(matches!(
                clean.load_persisted_selections(),
                PersistedLoad::Absent
            ));
            clean
                .reload_zdr_sessions(clean.load_persisted_selections())
                .expect("clean Absent reload ok");
            assert!(
                !sentinel.exists(),
                "an Absent clean boot MUST remove the stale global Corrupt sentinel (else it \
                 cries wolf to every new conversation)"
            );
        }

        // --- Loaded clean boot clears the stale sentinel ---
        {
            let g = StateDirGuard::new("clean-clears-sentinel-loaded");
            let root = "/proj/clean-clears-sentinel-loaded";

            // Prior corrupt boot writes the sentinel at the real path.
            {
                let seed = state_for(root, vec![target("box", true)]);
                seed.set_zdr_selection("seed", "box").unwrap();
            }
            let sp = selections_path(g.path(), root);
            std::fs::write(&sp, b"{\"conversa").unwrap();
            let corrupt = state_for(root, vec![]);
            corrupt
                .reload_zdr_sessions(corrupt.load_persisted_selections())
                .expect("global revert writable → Ok");
            let sentinel = global_report_path(g.path(), root);
            assert!(sentinel.exists(), "corrupt boot wrote the sentinel");

            // Re-seed a VALID selections file (the quarantine removed the corrupt one) so the
            // next load is Loaded(_), then clean-reload it.
            {
                let seed = state_for(root, vec![target("box", true)]);
                seed.set_zdr_selection("seed", "box").unwrap();
            }
            let clean = state_for(root, vec![target("box", true)]);
            assert!(
                matches!(clean.load_persisted_selections(), PersistedLoad::Loaded(_)),
                "re-seeded file must classify Loaded"
            );
            clean
                .reload_zdr_sessions(clean.load_persisted_selections())
                .expect("clean Loaded reload ok");
            assert!(
                !sentinel.exists(),
                "a Loaded clean boot MUST remove the stale global Corrupt sentinel"
            );
        }
    }

    // ---- ACCEPTANCE (A10fix4): a CURRENT-instance corrupt boot STILL writes the sentinel ----
    // The fix must NOT over-correct: when THIS boot is corrupt, the epoch-bearing sentinel must
    // be (re)written so consumers narrate the real corrupt revert.
    #[test]
    fn corrupt_boot_still_writes_current_sentinel() {
        let g = StateDirGuard::new("corrupt-writes-current-sentinel");
        let root = "/proj/corrupt-writes-current-sentinel";

        {
            let seed = state_for(root, vec![target("box", true)]);
            seed.set_zdr_selection("seed", "box").unwrap();
        }
        let sp = selections_path(g.path(), root);
        std::fs::write(&sp, b"{\"conversa").unwrap();

        let s = state_for(root, vec![]);
        let report = s
            .reload_zdr_sessions(s.load_persisted_selections())
            .expect("global revert writable → Ok");
        // Single global "*" revert outcome, as before.
        assert_eq!(report.outcomes.len(), 1);
        assert!(matches!(
            &report.outcomes[0],
            ReloadOutcome::Reverted { conversation, .. } if conversation == "*"
        ));
        // The sentinel exists and carries a current (>0) epoch — the current-instance corrupt
        // signal still fires.
        let sentinel = global_report_path(g.path(), root);
        assert!(
            sentinel.exists(),
            "a CURRENT corrupt boot MUST write the global sentinel (no over-correction)"
        );
        let gv: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&sentinel).unwrap()).unwrap();
        assert_eq!(gv["conversation"], "*");
        assert!(
            gv["epoch"].as_u64().unwrap() > 0,
            "current-instance corrupt sentinel must carry an epoch: {gv}"
        );
    }

    // ---- ACCEPTANCE: perm-denied selections file → Corrupt (never Absent) ----
    #[test]
    #[cfg(unix)]
    fn perm_denied_selections_classifies_corrupt_not_absent() {
        let g = StateDirGuard::new("perm-denied");
        let root = "/proj/perm-denied";
        // Create the real key-named selections file, then make it unreadable.
        {
            let seed = state_for(root, vec![target("box", true)]);
            seed.set_zdr_selection("seed", "box").unwrap();
        }
        let sp = selections_path(g.path(), root);
        set_mode(&sp, 0o000); // unreadable

        let s = state_for(root, vec![]);
        let load = s.load_persisted_selections();
        set_mode(&sp, 0o600); // restore for cleanup
        assert!(
            matches!(load, PersistedLoad::Corrupt(_)),
            "perm-denied must be Corrupt, never Absent/silent: {load:?}"
        );
    }

    // ---- ACCEPTANCE: clean empty array is Loaded(vec![]), not Corrupt ------
    #[test]
    fn empty_array_is_loaded_not_corrupt() {
        let g = StateDirGuard::new("empty-array");
        let root = "/proj/empty-array";
        // Create the real key-named selections file, then overwrite with a clean empty array.
        {
            let seed = state_for(root, vec![target("box", true)]);
            seed.set_zdr_selection("seed", "box").unwrap();
        }
        let sp = selections_path(g.path(), root);
        std::fs::write(&sp, b"[]").unwrap();
        let s = state_for(root, vec![]);
        match s.load_persisted_selections() {
            PersistedLoad::Loaded(v) => assert!(v.is_empty()),
            other => panic!("clean empty array must be Loaded(vec![]), got {other:?}"),
        }
        let report = s
            .reload_zdr_sessions(s.load_persisted_selections())
            .unwrap();
        assert!(report.outcomes.is_empty(), "no false global revert on []");
        assert!(!global_report_path(g.path(), root).exists());
    }

    // ---- ACCEPTANCE: one unwritable per-conv report does not abort reload --
    // NEW CONTRACT (A10/D1): a per-conv report write failure is non-fatal AND — for a REVERTED
    // outcome — must NOT silently drop the entry from disk. Here c1 REVERTS (its target is no
    // longer verified) and its report write is forced to fail; c2 RESTORES (target still verified).
    // The failed-report REVERT must be RETAINED on disk (next boot retries the revert report), the
    // map stays fail-closed (c1 NOT restored), and c2's restore is intact in both map and disk.
    #[test]
    #[cfg(unix)]
    fn loaded_boot_survives_unwritable_one_report() {
        let g = StateDirGuard::new("one-report-fail");
        let root = "/proj/one-report-fail";

        // Engage c1→old and c2→box durably (both verified at engage time).
        {
            let s = state_for(root, vec![target("old", true), target("box", true)]);
            s.set_zdr_selection("c1", "old").unwrap();
            s.set_zdr_selection("c2", "box").unwrap();
        }

        // Pre-create c1.json as a DIRECTORY so the per-conv report file write for c1 fails,
        // while c2's write still succeeds.
        let reports = g.path().join("zdr-reports");
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::create_dir_all(reports.join("c1.json")).unwrap();

        // Reload with ONLY "box" verified → c1 reverts (target gone), c2 restores.
        let s2 = state_for(root, vec![target("box", true)]);
        let report = s2
            .reload_zdr_sessions(s2.load_persisted_selections())
            .expect("a single unwritable report must NOT fail the boot");

        // c1 reverted → fail-closed: NOT in the in-memory map.
        assert!(
            s2.zdr_selection("c1").is_none(),
            "reverted c1 must stay dropped from the map (masked-Normal, data-safe)"
        );
        // c2 restored → in the map.
        assert_eq!(
            s2.zdr_selection("c2").map(|s| s.target),
            Some("box".to_string())
        );
        assert_eq!(report.outcomes.len(), 2);
        // c2's report file was still written.
        assert!(report_path(g.path(), "c2").is_file());

        // The FAILED-report REVERT (c1) must be RETAINED on disk so the next boot retries it,
        // while the RESTORED c2 is also on disk. (Previously c1 was dropped → a silent loss.)
        let sel = std::fs::read_to_string(selections_path(g.path(), root)).unwrap();
        assert!(
            sel.contains("\"c1\""),
            "reverted c1 with a failed report MUST be kept on disk for next-boot retry: {sel}"
        );
        assert!(sel.contains("\"c2\""), "restored c2 still on disk: {sel}");
    }

    // ---- ACCEPTANCE (A10/D1): a Reverted entry whose report write fails is KEPT on disk for
    // a next-boot retry (never a silent Normal egress), while the in-memory map stays fail-closed
    // and a SAME-boot Restored entry is unaffected. ----
    #[test]
    #[cfg(unix)]
    fn reverted_report_write_failure_keeps_entry_for_retry() {
        let g = StateDirGuard::new("revert-retry");
        let root = "/proj/revert-retry";

        // Durably engage rev→old and keep→box (both verified at engage time).
        {
            let s = state_for(root, vec![target("old", true), target("box", true)]);
            s.set_zdr_selection("rev", "old").unwrap();
            s.set_zdr_selection("keep", "box").unwrap();
        }

        // Force rev's report write to FAIL by occupying its report path with a directory.
        let reports = g.path().join("zdr-reports");
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::create_dir_all(reports.join("rev.json")).unwrap();

        // Reload with only "box" verified → rev reverts (target gone, report write fails), keep
        // restores.
        let s2 = state_for(root, vec![target("box", true)]);
        let report = s2
            .reload_zdr_sessions(s2.load_persisted_selections())
            .expect("a failed revert report must NOT abort the boot");

        // Map is fail-closed: rev NOT restored (routes masked-Normal), keep restored.
        assert!(
            s2.zdr_selection("rev").is_none(),
            "reverted rev must NEVER be in the map (fail-closed)"
        );
        assert_eq!(
            s2.zdr_selection("keep").map(|s| s.target),
            Some("box".to_string())
        );

        // On disk: rev RETAINED (failed report → keep for retry), keep RETAINED (restored).
        let sel = std::fs::read_to_string(selections_path(g.path(), root)).unwrap();
        assert!(
            sel.contains("\"rev\""),
            "failed-report revert kept on disk for next-boot retry (no silent loss): {sel}"
        );
        assert!(sel.contains("\"keep\""), "restored keep on disk: {sel}");

        // Next boot RETRIES: clear the blocking directory so the report write can succeed, reload
        // again from the retained disk state. rev re-reverts and now WRITES its report (visible),
        // then is dropped from disk; keep stays restored.
        std::fs::remove_dir_all(reports.join("rev.json")).unwrap();
        let s3 = state_for(root, vec![target("box", true)]);
        let _report3 = s3
            .reload_zdr_sessions(s3.load_persisted_selections())
            .expect("retry boot ok");
        assert!(s3.zdr_selection("rev").is_none(), "still fail-closed on retry");
        assert!(
            report_path(g.path(), "rev").is_file(),
            "the retry boot finally WRITES rev's revert report → eventually visible"
        );
        // rev now reported → dropped from disk; keep still present.
        let sel3 = std::fs::read_to_string(selections_path(g.path(), root)).unwrap();
        assert!(
            !sel3.contains("\"rev\""),
            "after a SUCCESSFUL revert report, rev is dropped from disk: {sel3}"
        );
        assert!(sel3.contains("\"keep\""), "keep still on disk after retry: {sel3}");
        let _ = report;
    }

    // ---- ACCEPTANCE (S1): live engage rolls back on persist failure --------
    #[test]
    #[cfg(unix)]
    fn live_engage_rolls_back_on_persist_failure() {
        let g = StateDirGuard::new("engage-rollback");
        let root = "/proj/engage-rollback";

        // Make the zdr-sessions dir UN-CREATABLE so the selections write fails.
        let blocked = block_sessions_dir(g.path());

        let s = state_for(root, vec![target("box", true)]);
        let res = s.set_zdr_selection("c", "box");
        let _ = std::fs::remove_file(&blocked); // cleanup
        assert!(res.is_err(), "unwritable dir must surface Err (S1)");
        assert!(
            s.zdr_selection("c").is_none(),
            "in-memory insert MUST be rolled back on write failure (no silent loss across recycle)"
        );
    }

    // ---- ACCEPTANCE (S1): live disengage re-inserts on persist failure -----
    #[test]
    #[cfg(unix)]
    fn live_disengage_rolls_back_on_persist_failure() {
        let g = StateDirGuard::new("disengage-rollback");
        let root = "/proj/disengage-rollback";

        let s = state_for(root, vec![target("box", true)]);
        // Durably engage first (dir writable).
        s.set_zdr_selection("c", "box").unwrap();
        assert_eq!(s.zdr_selection("c").map(|x| x.target), Some("box".into()));

        // Now make the dir un-creatable so the disengage write fails.
        let blocked = block_sessions_dir(g.path());
        let res = s.clear_zdr_selection("c");
        let _ = std::fs::remove_file(&blocked); // cleanup
        assert!(res.is_err(), "unwritable dir must surface Err (S1)");
        assert_eq!(
            s.zdr_selection("c").map(|x| x.target),
            Some("box".to_string()),
            "disengage write failure MUST re-insert (else next recycle resurrects ZDR off-disk)"
        );
    }

    // ---- ACCEPTANCE (A10fix2 / Fix 1): disengage is WRITE-FIRST, no Normal window -----
    // A failed durable write must NEVER have removed the in-memory entry — the conversation
    // stays ZDR-pinned (memory==disk==engaged) so a still-durably-pinned conversation can never
    // route Normal during the write window. This strengthens the rollback test to the
    // write-first ordering: there is no removed-then-reinserted transient at all.
    #[test]
    #[cfg(unix)]
    fn disengage_write_failure_keeps_conversation_engaged_no_normal_window() {
        let g = StateDirGuard::new("disengage-writefirst");
        let root = "/proj/disengage-writefirst";

        let s = state_for(root, vec![target("box", true)]);
        s.set_zdr_selection("c", "box").unwrap();
        assert_eq!(s.zdr_selection("c").map(|x| x.target), Some("box".into()));

        // Make the sessions dir un-writable so the disengage write fails.
        let blocked = block_sessions_dir(g.path());
        let res = s.clear_zdr_selection("c");
        let _ = std::fs::remove_file(&blocked); // cleanup
        assert!(res.is_err(), "unwritable dir must surface Err (fail-closed)");
        assert_eq!(
            s.zdr_selection("c").map(|x| x.target),
            Some("box".to_string()),
            "write-FIRST: the entry was NEVER removed (no Normal window); still durably ZDR-pinned"
        );
    }

    // ---- ACCEPTANCE (A10fix2 / Fix 1): success removes ONLY after a durable write -----
    #[test]
    fn disengage_success_removes_only_after_durable_write() {
        let g = StateDirGuard::new("disengage-success");
        let root = "/proj/disengage-success";

        let s = state_for(root, vec![target("box", true)]);
        s.set_zdr_selection("c", "box").unwrap();
        assert_eq!(s.zdr_selection("c").map(|x| x.target), Some("box".into()));

        // Writable dir: disengage succeeds and reports the entry was present.
        let was_present = s.clear_zdr_selection("c").expect("clear must succeed");
        assert!(was_present, "clear of a present conversation returns Ok(true)");
        assert!(
            s.zdr_selection("c").is_none(),
            "after a successful durable write the entry IS removed (disengaged)"
        );

        // The on-disk selections file no longer contains the conversation.
        let on_disk = std::fs::read_to_string(selections_path(g.path(), root)).unwrap();
        assert!(
            !on_disk.contains("\"c\""),
            "durable selections file no longer holds c after disengage: {on_disk}"
        );
    }

    // ---- ACCEPTANCE (A10fix2 / Fix 2): prune preserves unconsumed reports -------------
    // An OLD per-conversation `<conv>.json` report is an UNCONSUMED transition signal and must
    // survive prune (else a >14d-dormant reverted user gets a SILENT Normal routing change). The
    // genuinely-ageable artifacts — a `.global-seen` marker and a `.json.corrupt-<ts>`
    // quarantine — ARE pruned. prune_old_reports is private; it always runs first inside
    // reload_zdr_sessions, so an Absent reload drives it.
    #[test]
    #[cfg(unix)]
    fn prune_keeps_unconsumed_report_removes_stale_marker() {
        let g = StateDirGuard::new("prune-preserve");
        let root = "/proj/prune-preserve";

        let s = state_for(root, vec![target("box", true)]);
        // Ensure the reports dir exists.
        std::fs::create_dir_all(g.path().join("zdr-reports")).unwrap();

        let reports = g.path().join("zdr-reports");
        let report = report_path(g.path(), "conv-a"); // <conv>.json — pending signal
        let marker = reports.join("conv-a.global-seen"); // hooks-internal consumed marker
        let quarantine = reports.join("pk.json.corrupt-1700000000"); // dead quarantine
        // REGRESSION (A10fix2 round 2): a conversation id literally containing `.json.corrupt-`
        // sanitizes UNCHANGED (sanitize_component keeps `.`/`-`/`_`/alnum), so its pending report
        // file is `evil.json.corrupt-9.json` — it `contains(".json.corrupt-")` and would be wrongly
        // pruned by an unanchored quarantine match, silently dropping an unconsumed revert signal.
        // The `.json`-ending guard must keep it. (All chars here are filename-safe so the test
        // filename is byte-identical to the production sanitize_component output.)
        let report_namespace_trap = report_path(g.path(), "evil.json.corrupt-9");
        std::fs::write(&report, b"{\"some\":\"report\"}").unwrap();
        std::fs::write(&marker, b"epoch").unwrap();
        std::fs::write(&quarantine, b"corrupt bytes").unwrap();
        std::fs::write(&report_namespace_trap, b"{\"trap\":\"report\"}").unwrap();

        // Age all four well past REPORT_MAX_AGE_SECS (14d).
        for p in [&report, &marker, &quarantine, &report_namespace_trap] {
            let out = std::process::Command::new("touch")
                .arg("-d")
                .arg("30 days ago")
                .arg(p)
                .status()
                .expect("touch runs");
            assert!(out.success(), "touch -d must succeed");
        }

        // Drive prune via an Absent reload (prune runs unconditionally, first).
        s.reload_zdr_sessions(PersistedLoad::Absent)
            .expect("absent reload ok");

        assert!(
            report.is_file(),
            "an UNCONSUMED <conv>.json report is a pending signal and MUST survive prune"
        );
        assert!(
            report_namespace_trap.is_file(),
            "a <conv>.json report whose id contains `.json.corrupt-` is STILL a pending signal and \
             MUST survive prune (the `.json`-ending guard, not the unanchored contains-match)"
        );
        assert!(
            !marker.exists(),
            "an OLD .global-seen marker IS ageable and must be pruned"
        );
        assert!(
            !quarantine.exists(),
            "an OLD .json.corrupt-<ts> quarantine is dead and must be pruned"
        );
    }

    // ---- ACCEPTANCE (S1): zdr_set returns 5xx (not 200) on persist failure --
    // Drives the admin surface through the router with an unwritable state dir.
    #[tokio::test]
    #[cfg(unix)]
    async fn zdr_set_returns_5xx_when_persist_fails() {
        let g = StateDirGuard::new("set-5xx");
        let root = "/proj/set-5xx";

        // Make the zdr-sessions dir un-creatable so the durable write fails.
        let blocked = block_sessions_dir(g.path());

        let mut s = state_for(root, vec![target("box", true)]);
        s.zdr_default = Arc::new(Some("box".into()));
        let proxy_addr = spawn(proxy_router(s)).await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{proxy_addr}/sordino/session/cx/zdr"))
            .header("x-sordino-key", "test-key")
            .json(&serde_json::json!({"config":"box"}))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.text().await.unwrap();
        let _ = std::fs::remove_file(&blocked); // cleanup

        assert!(
            status.is_server_error(),
            "persist failure MUST surface as 5xx (not 200), got {status}"
        );
        assert!(
            !body.contains("\"engaged\""),
            "body must NOT claim engaged on a persist failure: {body}"
        );
    }

    // ---- ACCEPTANCE (finding 1): a failed SWITCH rolls back to the prior target ----
    // Engage c on X durably, then a switch c X->Y whose write fails must leave c==X (NOT
    // None) in memory AND X still on disk — never a third diverged state.
    #[test]
    #[cfg(unix)]
    fn live_engage_switch_rolls_back_to_prior_target() {
        let g = StateDirGuard::new("switch-rollback");
        let root = "/proj/switch-rollback";

        let s = state_for(root, vec![target("X", true), target("Y", true)]);
        // Durably engage c on X (dir writable).
        s.set_zdr_selection("c", "X").unwrap();
        assert_eq!(s.zdr_selection("c").map(|x| x.target), Some("X".into()));

        // Now make the dir un-creatable so the SWITCH write fails.
        let blocked = block_sessions_dir(g.path());
        let res = s.set_zdr_selection("c", "Y");
        let _ = std::fs::remove_file(&blocked); // cleanup
        assert!(res.is_err(), "unwritable dir must surface Err (S1)");
        assert_eq!(
            s.zdr_selection("c").map(|x| x.target),
            Some("X".to_string()),
            "a failed switch MUST restore the PRIOR target X (not None); else X is dropped \
             unannounced and resurrects on the next recycle"
        );

        // Disk faithfulness: re-persist from the (rolled-back) memory now that the dir is
        // writable again, and confirm the durable file holds ONLY X — proving the failed
        // switch never durably advanced to Y and memory==disk==X.
        s.set_zdr_selection("c", "X").unwrap();
        let on_disk = std::fs::read_to_string(selections_path(g.path(), root)).unwrap();
        assert!(on_disk.contains("\"X\""), "disk holds X: {on_disk}");
        assert!(!on_disk.contains("\"Y\""), "Y never persisted: {on_disk}");
    }

    // ---- ACCEPTANCE (finding 2): the cap is enforced VISIBLY at engage time ----
    // Once the live map holds MAX distinct conversations, a NEW engage is refused with Err
    // (→ 5xx) rather than silently truncated off disk; the persisted set always equals the
    // in-memory set (no silent divergence).
    #[test]
    fn engage_refuses_when_cap_reached() {
        const MAX: usize = 1000; // mirrors MAX_PERSISTED_SELECTIONS
        let g = StateDirGuard::new("cap-visible");
        let root = "/proj/cap-visible";

        let s = state_for(root, vec![target("box", true)]);
        // Fill the live map to MAX with distinct conversations.
        for i in 0..MAX {
            s.set_zdr_selection(&format!("c{i:04}"), "box").unwrap();
        }
        assert_eq!(s.zdr_active().len(), MAX, "map filled to MAX");

        // A NEW engage past the cap is refused (fail-closed-and-visible).
        let res = s.set_zdr_selection("overflow", "box");
        assert!(res.is_err(), "a NEW engage at the cap MUST surface Err (→5xx)");
        assert!(
            s.zdr_selection("overflow").is_none(),
            "the refused conversation must NOT be in memory"
        );

        // A switch/re-engage of an EXISTING conversation is still allowed (no growth).
        s.set_zdr_selection("c0000", "box").unwrap();

        // The persisted file's entry count exactly equals the in-memory map length — no
        // silent truncation divergence.
        let persisted: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(selections_path(g.path(), root)).unwrap())
                .unwrap();
        assert_eq!(
            persisted.len(),
            s.zdr_active().len(),
            "persisted set count MUST equal the in-memory map length (no silent truncation)"
        );
        assert_eq!(persisted.len(), MAX);
    }

    // ---- ACCEPTANCE (finding 3): concurrent set/clear keep disk == final memory ----
    // Multiple threads doing set/clear on DISTINCT conversations against one shared AppState
    // must observe NO spurious Err (no temp-path collision) and leave the on-disk persisted
    // set exactly equal to the final in-memory map (no stale-snapshot rename winning).
    #[test]
    fn concurrent_set_clear_keeps_disk_consistent() {
        let g = StateDirGuard::new("concurrent");
        let root = "/proj/concurrent";

        let s = std::sync::Arc::new(state_for(root, vec![target("box", true)]));
        let spurious_err = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut handles = Vec::new();
        for t in 0..4 {
            let s = std::sync::Arc::clone(&s);
            let spurious_err = std::sync::Arc::clone(&spurious_err);
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    let conv = format!("t{t}-c{i:03}");
                    if let Err(_e) = s.set_zdr_selection(&conv, "box") {
                        spurious_err.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    // Disengage every other one so the final map is a known mix.
                    if i % 2 == 0 {
                        if let Err(_e) = s.clear_zdr_selection(&conv) {
                            spurious_err.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert!(
            !spurious_err.load(std::sync::atomic::Ordering::Relaxed),
            "no spurious PersistError may occur from a temp-path collision"
        );

        // On-disk persisted set must exactly equal the FINAL in-memory map.
        let persisted: Vec<PersistedSelection> =
            serde_json::from_slice(&std::fs::read(selections_path(g.path(), root)).unwrap())
                .unwrap();
        let mut disk: Vec<(String, String)> = persisted
            .into_iter()
            .map(|p| (p.conversation, p.target))
            .collect();
        disk.sort();
        let mut mem = s.zdr_active();
        mem.sort();
        assert_eq!(
            disk, mem,
            "on-disk persisted set MUST equal the final in-memory map (no stale-snapshot rename)"
        );
    }
}

// ---- A7 / H2+H3 / D2: ZDR-aware passthrough + bare-path defense-in-depth ------------

/// A capture upstream that records EVERY request (path + body) on ANY path via a
/// fallback — so passthrough relays (`/v1/files`, `/v1/batches`, …) and stripped session
/// paths are all observed. Reuses the shared `Captured` (its `paths` Vec + `body`).
async fn fake_capture_any(State(cap): State<Captured>, req: axum::extract::Request) -> StatusCode {
    cap.paths
        .lock()
        .unwrap()
        .push(req.uri().path().to_string());
    let body = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8_lossy(&body).to_string();
    *cap.body.lock().unwrap() = s.clone();
    cap.bodies.lock().unwrap().push(s);
    StatusCode::OK
}

fn capture_any_state(default_base: String) -> (AppState, Captured) {
    // A registered, user_verified target so engaging a pin resolves (PinnedMode::Zdr).
    let def_cap = Captured::default();
    let target = ZdrTarget::new(
        "trusted".into(),
        // The target base is irrelevant for the refusal tests (they never reach upstream),
        // but must be a valid http base; point it at a sink the test never spawns.
        "http://127.0.0.1:1/zdr-unused",
        TrustBasis::SelfHosted,
        true,
        vec![],
        "zdr-key".into(),
    )
    .unwrap();
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = zdr_state(engine, default_base, target);
    (state, def_cap)
}

// Pinned session passthrough: `/sordino/session/<pinned>/v1/files` and `/v1/batches`
// → 409, ZERO bytes on the default upstream. Non-pinned `/sordino/session/<c>/v1/files`
// → the default upstream records EXACTLY `/v1/files` (prefix stripped).
#[tokio::test]
async fn passthrough_refuses_pinned_zero_bytes() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .fallback(fake_capture_any)
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    // `zdr_state` already registered the `trusted` target. Pin one conversation in-memory;
    // the strip path uses a second, NON-pinned conversation id (`c1`).
    engage_in_memory(&state, "pinned", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();

    // (a) pinned /v1/files via session prefix → 409, nothing upstream.
    let r_files = client
        .post(format!("http://{proxy_addr}/sordino/session/pinned/v1/files"))
        .body("plaintext eve@example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(r_files.status(), reqwest::StatusCode::CONFLICT);

    // (b) pinned /v1/batches via session prefix → 409, nothing upstream.
    let r_batch = client
        .post(format!("http://{proxy_addr}/sordino/session/pinned/v1/batches"))
        .body("plaintext eve@example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(r_batch.status(), reqwest::StatusCode::CONFLICT);

    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "fail-closed: ZERO bytes egressed to the default upstream for a pinned passthrough"
    );
    assert!(
        def_cap.paths.lock().unwrap().is_empty(),
        "default upstream must never be contacted for a pinned passthrough"
    );

    // (c) NON-pinned session /v1/files → relayed, recorded path EXACTLY /v1/files.
    let r_ok = client
        .post(format!("http://{proxy_addr}/sordino/session/c1/v1/files"))
        .body("hi")
        .send()
        .await
        .unwrap();
    assert_eq!(r_ok.status(), reqwest::StatusCode::OK);
    let paths = def_cap.paths.lock().unwrap().clone();
    assert_eq!(
        paths,
        vec!["/v1/files".to_string()],
        "non-pinned session prefix must be stripped to exactly /v1/files (got {paths:?})"
    );
}

// THE round-1 HIGH leak: a BARE `POST /v1/files` (no session prefix) carrying
// `x-sordino-conversation: <pinned>` + a PII body MUST refuse 409 with ZERO bytes — the
// verbatim relay never masks, so any egress here would be PLAINTEXT to the default endpoint.
#[tokio::test]
async fn bare_passthrough_header_refuses_pinned_zero_bytes() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .fallback(fake_capture_any)
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    engage_in_memory(&state, "c1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/v1/files"))
        .header("x-sordino-conversation", "c1")
        .body("attach eve@example.com here")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "fail-closed: NO body (plaintext OR masked) may egress on a header-pinned bare passthrough"
    );
    assert!(
        def_cap.paths.lock().unwrap().is_empty(),
        "the default upstream must never be contacted for a header-pinned bare passthrough"
    );
}

// Traversal hardening: `/sordino/session/c1/../v1/batches` (c1 NOT pinned) must be refused
// 400 BEFORE the is_batches/pin checks — never relayed as `/../v1/batches`.
#[tokio::test]
async fn session_traversal_batches_refused() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .fallback(fake_capture_any)
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    // c1 deliberately NOT pinned — the refusal must come from traversal hardening, not a pin.
    let proxy_addr = spawn(proxy_router(state)).await;

    // reqwest/url normalize `..` out of the path before sending, which would defeat the
    // test. Send a RAW HTTP/1.1 request over a TcpStream so the literal `..` segment
    // reaches the handler verbatim.
    let status = raw_post_status(
        proxy_addr,
        "/sordino/session/c1/../v1/batches",
        "plaintext eve@example.com",
    )
    .await;
    assert_eq!(status, 400, "traversal must be refused 400 (got {status})");
    assert!(
        def_cap.body.lock().unwrap().is_empty() && def_cap.paths.lock().unwrap().is_empty(),
        "a traversal must be refused, never relayed (no bytes/path upstream)"
    );
}

// A10fix3 Fix 2: the verbatim relay's session-prefix pin check must percent-DECODE the
// conversation-id segment before the pin lookup, so a percent-encoded id resolves to the
// SAME key the control plane persists (axum `Path<String>` decodes; the pin in zdr_sessions
// is keyed on the decoded id). `c%31` decodes to `c1`; a relay to
// `/sordino/session/c%31/v1/files` for the pinned `c1` MUST be REFUSED (409, ZERO bytes
// upstream) — not relayed because the raw segment `c%31` missed the pin. reqwest would decode
// `%31` before sending, defeating the test, so drive a RAW HTTP/1.1 request that keeps the
// literal `%31` on the wire.
#[tokio::test]
async fn relay_pin_check_decodes_percent_encoded_session_id() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .fallback(fake_capture_any)
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    // Pin the DECODED id `c1` — exactly the key the session handlers / zdr_set persist.
    engage_in_memory(&state, "c1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    // Percent-encoded "c1" == "c%31". Send raw so the encoding survives to the handler.
    let status =
        raw_post_status(proxy_addr, "/sordino/session/c%31/v1/files", "plaintext eve@example.com")
            .await;
    assert_eq!(
        status, 409,
        "a percent-encoded session id for a pinned conversation must resolve to the pin and \
         REFUSE the verbatim relay (got {status})"
    );
    assert!(
        def_cap.body.lock().unwrap().is_empty() && def_cap.paths.lock().unwrap().is_empty(),
        "fail-closed: ZERO bytes egressed to the default upstream for the percent-encoded \
         pinned passthrough"
    );
}

/// Send a RAW HTTP/1.1 POST with the path verbatim (no URL normalization) and return the
/// numeric status code from the response status line. Used to drive `..`-traversal cases
/// that reqwest would otherwise normalize away.
async fn raw_post_status(addr: SocketAddr, raw_path: &str, body: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {raw_path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    // Status line: "HTTP/1.1 400 Bad Request"
    resp.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0)
}

// Bare `/v1/messages` + `x-sordino-conversation: <pinned>` → 409, ZERO bytes upstream.
#[tokio::test]
async fn bare_path_header_refuses_pinned() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    engage_in_memory(&state, "c1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .header("x-sordino-conversation", "c1")
        .json(&serde_json::json!({
            "model":"m","max_tokens":1,
            "messages":[{"role":"user","content":[{"type":"text","text":"eve@example.com"}]}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "fail-closed: a header-pinned bare /v1/messages must egress ZERO bytes"
    );
}

// Bare `/v1/chat/completions` + header (pinned) → 409, ZERO bytes upstream.
#[tokio::test]
async fn bare_openai_chat_header_refuses_pinned() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/chat/completions", post(fake_openai_chat_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    engage_in_memory(&state, "c1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .header("x-sordino-conversation", "c1")
        .json(&serde_json::json!({
            "model":"gpt","messages":[{"role":"user","content":"eve@example.com"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "fail-closed: a header-pinned bare /v1/chat/completions must egress ZERO bytes"
    );
}

// Bare `/v1/responses` + header (pinned) → 409, ZERO bytes upstream.
#[tokio::test]
async fn bare_openai_responses_header_refuses_pinned() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/responses", post(fake_responses_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    engage_in_memory(&state, "c1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/v1/responses"))
        .header("x-sordino-conversation", "c1")
        .json(&serde_json::json!({"model":"gpt","input":"eve@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(
        def_cap.body.lock().unwrap().is_empty(),
        "fail-closed: a header-pinned bare /v1/responses must egress ZERO bytes"
    );
}

// RESIDUAL (data-safe, NOT a kill-condition): a pinned conversation, bare `/v1/messages`
// with NO header → routed masked-Normal to the default upstream (a masked token, never
// plaintext). The pin can't be looked up without an id, so this is by-design.
#[tokio::test]
async fn bare_path_no_header_is_masked_normal() {
    let def_cap = Captured::default();
    let def_up = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(def_cap.clone());
    let def_addr = spawn(def_up).await;

    let (state, _) = capture_any_state(format!("http://{def_addr}"));
    engage_in_memory(&state, "c1", "trusted");
    let proxy_addr = spawn(proxy_router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model":"m","max_tokens":1,
            "messages":[{"role":"user","content":[{"type":"text","text":"eve@example.com"}]}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = def_cap.body.lock().unwrap().clone();
    assert!(
        !body.is_empty() && !body.contains("eve@example.com") && body.contains("[EMAIL_ADDRESS_"),
        "header-absent bare request is masked-Normal (masked token, never plaintext): {body}"
    );
}

// ===========================================================================
// A2b — registered-secret tripwire (GAP-CLOSURE G1/L20).
//
// When a registered secret's EXACT value appears in a never-rewritten
// schema/contract subtree (tool.input_schema, an OpenAI contract-key subtree,
// or an `extra` flatten sink), the proxy REFUSES with 409 and ZERO bytes
// upstream instead of forwarding it verbatim. Detect-then-refuse: the subtree
// is still never masked (the no-mask-schema invariant is untouched).
// ===========================================================================

/// A distinctive registered-secret value used across the tripwire tests.
const A2B_SECRET_VAL: &str = "S3cr3tRegisteredValue";
/// The secret's registered NAME — appears in the 409 body; its value never does.
const A2B_SECRET_NAME: &str = "prod_api_key";

/// Engine with one registered secret (`Hash` operator; A2b is detect-only so the
/// operator is immaterial). `disabled`/`no_secrets` variants exercise the invariant that
/// `registered_secret_hit` reads the live secret set unconditionally.
fn a2b_engine_with_secret() -> MaskEngine {
    let e = MaskEngine::new(EngineConfig::default()).unwrap();
    e.set_secret_rules(vec![sordino_engine::SecretRule {
        name: A2B_SECRET_NAME.into(),
        value: sordino_engine::SecretValue::new(A2B_SECRET_VAL),
        operator: sordino_engine::Operator::Hash,
        case_sensitive: true,
        apply_to_surfaces: None,
    }])
    .unwrap();
    e
}

// --- Test 1a: Anthropic tool.input_schema → 409, zero upstream bytes. -------
#[tokio::test]
async fn a2b_anthropic_input_schema_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10, "messages": [],
            "tools": [{
                "name": "send", "description": "d",
                "input_schema": {"type": "object", "properties": {
                    "default_key": {"const": A2B_SECRET_VAL}
                }}
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- Test 1b: OpenAI-chat tools[].function.parameters → 409, zero bytes. ----
#[tokio::test]
async fn a2b_openai_chat_tool_parameters_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/chat/completions", post(fake_openai_chat_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {
                "name": "send",
                "parameters": {"type": "object", "properties": {
                    "default_key": {"const": A2B_SECRET_VAL}
                }}
            }}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- Test 1c: OpenAI-responses input_schema (extra sink) → 409, zero bytes. -
#[tokio::test]
async fn a2b_openai_responses_input_schema_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/responses", post(fake_responses_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/responses"))
        .json(&serde_json::json!({
            "model": "gpt-test", "input": "hi",
            "input_schema": {"type": "object", "properties": {
                "default_key": {"const": A2B_SECRET_VAL}
            }}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- Test 2: FAIL-SAFE — malformed top-level field fails the typed ApiRequest
// parse, so the fallback value-walk runs; a secret in tools[].input_schema must
// STILL 409 (proves tool_value_safe's OWN input_schema arm scans — the
// match-arm-ordering trap where the guard never sees input_schema). -----------
#[tokio::test]
async fn a2b_failsafe_fallback_walk_input_schema_secret_refuses_409() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    // `max_tokens` as a STRING fails the typed `u32` parse (but is valid JSON), so the
    // Anthropic path falls to the structure-agnostic value_safe walk.
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": "not_a_number", "messages": [],
            "tools": [{
                "name": "send", "description": "d",
                "input_schema": {"type": "object", "properties": {
                    "default_key": {"const": A2B_SECRET_VAL}
                }}
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- Test 3: OBJECT-KEY — the secret value used as a JSON object KEY
// (`properties.<SECRET>`) → 409 (proves keys are scanned, not just values). ----
#[tokio::test]
async fn a2b_object_key_secret_refuses_409() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    // The secret sits as a `properties` KEY — build the JSON as a raw string so the key
    // is a dynamic value. (No JSON-special chars in the secret, so it needs no escaping.)
    let raw = format!(
        r#"{{"model":"claude-test","max_tokens":10,"messages":[],"tools":[{{"name":"send","description":"d","input_schema":{{"type":"object","properties":{{"{A2B_SECRET_VAL}":{{"type":"string"}}}}}}}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .header(CONTENT_TYPE, "application/json")
        .body(raw)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- Test 4a: BASE64-COINCIDENCE (Anthropic) — the secret's literal bytes
// inside a base64 image `data` field must NOT be refused (L18 binary boundary). -
#[tokio::test]
async fn a2b_base64_coincidence_anthropic_not_refused_200() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let data = format!("QUJD{A2B_SECRET_VAL}WFla");
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "look"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}
            ]}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK, "base64 coincidence must not 409");
    let up = cap.body.lock().unwrap().clone();
    assert!(up.contains(A2B_SECRET_VAL), "base64 data passes through verbatim (never scanned): {up}");
}

// --- Test 4b: BASE64-COINCIDENCE (OpenAI-chat) — secret bytes in a base64
// `data` field carried through `extra` must NOT be refused. -------------------
#[tokio::test]
async fn a2b_base64_coincidence_openai_chat_not_refused_200() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/chat/completions", post(fake_openai_chat_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let data = format!("QUJD{A2B_SECRET_VAL}");
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "x_blob": {"type": "base64", "data": data}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK, "base64 coincidence must not 409");
    let up = cap.body.lock().unwrap().clone();
    assert!(up.contains(A2B_SECRET_VAL), "base64 data passes through verbatim: {up}");
}

// --- Test 4c: BASE64-COINCIDENCE (OpenAI-responses) — must NOT be refused.
// This specifically proves the responses `value_safe` combined `if` was SPLIT:
// were the base64-data and contract-key legs still fused with a scan attached,
// the base64 `data` would 409. -----------------------------------------------
#[tokio::test]
async fn a2b_base64_coincidence_openai_responses_not_refused_200() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/responses", post(fake_responses_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let data = format!("QUJD{A2B_SECRET_VAL}");
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/responses"))
        .json(&serde_json::json!({
            "model": "gpt-test", "input": "hi",
            "x_blob": {"type": "base64", "data": data}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK, "base64 coincidence must not 409");
    let up = cap.body.lock().unwrap().clone();
    assert!(up.contains(A2B_SECRET_VAL), "base64 data passes through verbatim: {up}");
}

// --- Test 5: SUBSTRING — the secret as a substring of a larger string leaf →
// 409 (registered_secret_hit is a substring/Aho-Corasick match, not whole-leaf). -
#[tokio::test]
async fn a2b_substring_secret_refuses_409() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let embedded = format!("prefix-{A2B_SECRET_VAL}-suffix");
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10, "messages": [],
            "tools": [{
                "name": "send", "description": "d",
                "input_schema": {"type": "object", "properties": {
                    "default_key": {"const": embedded}
                }}
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
}

// --- Test 6: ENGINE-DISABLED — with masking turned OFF the secret in
// input_schema must STILL 409 (registered_secret_hit reads the live secret set
// unconditionally). -----------------------------------------------------------
#[tokio::test]
async fn a2b_engine_disabled_still_refuses_409() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let engine = a2b_engine_with_secret();
    engine.set_enabled(false); // master masking switch OFF
    assert!(!engine.is_enabled());
    let state = mk_state(engine, format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10, "messages": [],
            "tools": [{
                "name": "send", "description": "d",
                "input_schema": {"type": "object", "properties": {
                    "default_key": {"const": A2B_SECRET_VAL}
                }}
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
}

// --- Test 7: NO SECRETS registered — identical body forwards normally (200),
// zero behavior change. -------------------------------------------------------
#[tokio::test]
async fn a2b_no_secrets_registered_forwards_200() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    // Default engine — NO registered secrets.
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10, "messages": [],
            "tools": [{
                "name": "send", "description": "d",
                "input_schema": {"type": "object", "properties": {
                    "default_key": {"const": A2B_SECRET_VAL}
                }}
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let up = cap.body.lock().unwrap().clone();
    assert!(
        up.contains(A2B_SECRET_VAL),
        "with no secrets the input_schema const forwards verbatim: {up}"
    );
}

// --- Test 8: DEPTH-129 — a programmatically-nested body (129 nested objects)
// with the secret deep inside is REFUSED with zero upstream bytes because
// serde_json's 128-depth parse limit rejects the body BEFORE any walker runs.
// KILL-CONDITION: a 200 with the body forwarded would mean an unparseable-body
// passthrough exists (the walker is bypassable by deep nesting) — a
// FOUNDATION-level finding, not something to paper over. --------------------
#[tokio::test]
async fn a2b_depth_129_body_refused_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    // 129 nested `{"properties": …}` objects around the secret leaf → deeper than
    // serde_json's 128 recursion limit, so BOTH the typed and the fallback Value parse
    // fail before any walker runs.
    let mut deep = format!("\"{A2B_SECRET_VAL}\"");
    for _ in 0..129 {
        deep = format!("{{\"properties\":{deep}}}");
    }
    let raw = format!(
        r#"{{"model":"claude-test","max_tokens":10,"messages":[],"tools":[{{"name":"x","description":"d","input_schema":{deep}}}]}}"#
    );

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .header(CONTENT_TYPE, "application/json")
        .body(raw)
        .send()
        .await
        .unwrap();

    assert_ne!(
        resp.status(),
        reqwest::StatusCode::OK,
        "KILL-CONDITION: a 129-deep body must be REFUSED (serde depth cap), not forwarded"
    );
    assert!(resp.status().is_client_error(), "refused as a 4xx: {}", resp.status());
    assert!(
        cap.body.lock().unwrap().is_empty() && cap.bodies.lock().unwrap().is_empty(),
        "KILL-CONDITION: ZERO bytes upstream for an unparseable deep body"
    );
}

// ===========================================================================
// A2b FIX ROUND — sibling TYPED never-rewritten contract/structured-output
// fields (not just `tools`). A registered secret's exact value in these fields
// previously forwarded UPSTREAM in plaintext (200); it must now REFUSE 409 with
// ZERO bytes upstream, exactly like the `tools` carve-out. One test per wire per
// field family; each proves the field is scanned in the walker's request().
// ===========================================================================

// --- Anthropic `output_config.format.schema` → 409, zero upstream bytes. ----
#[tokio::test]
async fn a2b_anthropic_output_config_schema_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10, "messages": [],
            "output_config": {
                "format": {"type": "json_schema", "schema": {"const": A2B_SECRET_VAL}}
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- OpenAI-chat `response_format` schema → 409, zero upstream bytes. --------
#[tokio::test]
async fn a2b_openai_chat_response_format_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/chat/completions", post(fake_openai_chat_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"schema": {"properties": {"k": {"const": A2B_SECRET_VAL}}}}
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- OpenAI-chat `guided_choice` (Vec<String> contract field) → 409. --------
// Proves the typed String/Vec guided-decoding fields are scanned, not just the
// `Value` ones.
#[tokio::test]
async fn a2b_openai_chat_guided_choice_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/chat/completions", post(fake_openai_chat_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hi"}],
            "guided_choice": ["alpha", A2B_SECRET_VAL, "omega"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- OpenAI-responses `text` (structured-output) → 409, zero upstream bytes. -
#[tokio::test]
async fn a2b_openai_responses_text_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/responses", post(fake_responses_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/responses"))
        .json(&serde_json::json!({
            "model": "gpt-test", "input": "hi",
            "text": {"format": {"type": "json_schema", "schema": {"const": A2B_SECRET_VAL}}}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- OpenAI-responses `tool_choice` → 409, zero upstream bytes. -------------
#[tokio::test]
async fn a2b_openai_responses_tool_choice_secret_refuses_409_zero_bytes() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/responses", post(fake_responses_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/responses"))
        .json(&serde_json::json!({
            "model": "gpt-test", "input": "hi",
            "tool_choice": {"type": "function", "name": A2B_SECRET_VAL}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(body.contains(A2B_SECRET_NAME), "409 body names the secret: {body}");
    assert!(!body.contains(A2B_SECRET_VAL), "409 body must NEVER echo the value: {body}");
    assert!(cap.body.lock().unwrap().is_empty(), "zero bytes upstream");
    assert!(cap.bodies.lock().unwrap().is_empty(), "fake upstream never hit");
}

// --- Negative: a NON-secret value in these sibling fields still forwards 200
// (the scan is detect-then-refuse, never a blanket block of contract fields). -
#[tokio::test]
async fn a2b_output_config_without_secret_forwards_200() {
    let cap = Captured::default();
    let upstream = Router::new()
        .route("/v1/messages", post(fake_upstream))
        .with_state(cap.clone());
    let up_addr = spawn(upstream).await;
    let state = mk_state(a2b_engine_with_secret(), format!("http://{up_addr}"), "k");
    let proxy_addr = spawn(proxy_router(state)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-test", "max_tokens": 10, "messages": [],
            "output_config": {
                "format": {"type": "json_schema", "schema": {"const": "not-a-secret"}}
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let up = cap.body.lock().unwrap().clone();
    assert!(
        up.contains("not-a-secret"),
        "a non-secret output_config schema forwards verbatim: {up}"
    );
}
