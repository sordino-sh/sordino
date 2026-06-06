//! End-to-end: client -> zlauder-proxy -> fake upstream. Verifies that the
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
use zlauder_engine::{EngineConfig, MaskEngine, token_regex};
use zlauder_proxy::{
    config::ConfigLayers, monitor::Monitor, routes::router as proxy_router, state::AppState,
};

/// Build an `AppState` for tests (no real config files; reload points at a
/// nonexistent user layer so it's a deterministic no-op).
fn mk_state(engine: MaskEngine, upstream_base: String, admin_key: &str) -> AppState {
    AppState {
        engine: Arc::new(engine),
        http: reqwest::Client::new(),
        upstream_base: Arc::new(upstream_base),
        admin_key: Arc::new(admin_key.into()),
        layers: Arc::new(ConfigLayers {
            user: std::path::PathBuf::from("/nonexistent/zlauder/config.toml"),
            project: None,
            local: None,
        }),
        project_root: Arc::new("/tmp/zlauder-test-project".into()),
        port: 0,
        monitor: Monitor::new(),
        ml_control: Arc::new(std::sync::Mutex::new(())),
    }
}

#[derive(Clone, Default)]
struct Captured {
    body: Arc<Mutex<String>>,
    headers: Arc<Mutex<HeaderMap>>,
    bodies: Arc<Mutex<Vec<String>>>,
}

async fn fake_upstream(
    State(cap): State<Captured>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<serde_json::Value> {
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

    // GET /zlauder/config without the key → 403.
    let unauth = client
        .get(format!("http://{proxy_addr}/zlauder/config"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 403, "config must be key-gated");

    // With the key → 200 and `enabled: true`.
    let cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/zlauder/config"))
        .header("x-zlauder-key", "secret-key")
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
        .post(format!("http://{proxy_addr}/zlauder/disable"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403);

    // disable WITH the key → masking off.
    let off: serde_json::Value = client
        .post(format!("http://{proxy_addr}/zlauder/disable"))
        .header("x-zlauder-key", "secret-key")
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
        .post(format!("http://{proxy_addr}/zlauder/enable"))
        .header("x-zlauder-key", "secret-key")
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
        .get(format!("http://{proxy_addr}/zlauder/config"))
        .header("x-zlauder-key", "mlkey")
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
        .post(format!("http://{proxy_addr}/zlauder/ml/enable"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 403);

    // Disable with the key is a safe no-network op → 200, still "disabled".
    let off: serde_json::Value = client
        .post(format!("http://{proxy_addr}/zlauder/ml/disable"))
        .header("x-zlauder-key", "mlkey")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(off["ml"]["status"], serde_json::json!("disabled"));
    assert_eq!(off["ml"]["enabled"], serde_json::json!(false));
}

// Live-ownership: a generic `PUT /zlauder/config` must NOT enable ML even if the
// posted config says `ml.enabled = true` — only `/zlauder/ml/{enable,disable}` flip
// it. (Otherwise a stale/older client could turn the model on via the wrong path,
// and crucially trigger a model load.)
#[tokio::test]
async fn put_config_cannot_flip_ml_enabled() {
    let engine = MaskEngine::new(EngineConfig::default()).unwrap();
    let state = mk_state(engine, "http://127.0.0.1:1".into(), "k2");
    let proxy_addr = spawn(proxy_router(state)).await;
    let client = reqwest::Client::new();

    let mut cfg: serde_json::Value = client
        .get(format!("http://{proxy_addr}/zlauder/config"))
        .header("x-zlauder-key", "k2")
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
        .put(format!("http://{proxy_addr}/zlauder/config"))
        .header("x-zlauder-key", "k2")
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

// PUT /zlauder/config swaps the live policy (here: turn EMAIL into redaction).
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
        .get(format!("http://{proxy_addr}/zlauder/config"))
        .header("x-zlauder-key", "kk")
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
        .put(format!("http://{proxy_addr}/zlauder/config"))
        .header("x-zlauder-key", "kk")
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
        .get(format!("http://{proxy_addr}/zlauder/monitor/snapshot"))
        .header("x-zlauder-key", "mon")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snap["mode"], "off");
    assert_eq!(snap["records"][0]["decision"], "completed");
    assert_eq!(snap["records"][0]["tokens"].as_array().unwrap().len(), 1);
    assert!(
        snap["records"][0]["request_preview"]
            .as_str()
            .unwrap()
            .contains("[EMAIL_ADDRESS_")
    );
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
        .post(format!("http://{proxy_addr}/zlauder/monitor/mode"))
        .header("x-zlauder-key", "reject-key")
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
            "http://{proxy_addr}/zlauder/monitor/requests/{id}/reject"
        ))
        .header("x-zlauder-key", "reject-key")
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
        .post(format!("http://{proxy_addr}/zlauder/monitor/mode"))
        .header("x-zlauder-key", "approve-key")
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
            "http://{proxy_addr}/zlauder/monitor/requests/{id}/approve"
        ))
        .header("x-zlauder-key", "approve-key")
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
        .post(format!("http://{proxy_addr}/zlauder/monitor/custom-mask"))
        .header("x-zlauder-key", "custom-key")
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
            "http://{proxy_addr}/zlauder/session/convo-123/v1/messages"
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
        .get(format!("http://{proxy_addr}/zlauder/monitor/snapshot"))
        .header("x-zlauder-key", "session-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snap["records"][0]["conversation_id"], "convo-123");
}

async fn wait_for_pending(client: &reqwest::Client, proxy_addr: SocketAddr, key: &str) -> String {
    for _ in 0..50 {
        let snap: serde_json::Value = client
            .get(format!("http://{proxy_addr}/zlauder/monitor/snapshot"))
            .header("x-zlauder-key", key)
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
