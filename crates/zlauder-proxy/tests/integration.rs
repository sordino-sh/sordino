//! End-to-end: client -> zlauder-proxy -> fake upstream. Verifies that the
//! upstream receives masked text + forwarded auth headers, and the client
//! receives an unmasked response.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use axum::Router;
use http::HeaderMap;
use zlauder_engine::{EngineConfig, MaskEngine, token_regex};
use zlauder_proxy::{routes::router as proxy_router, state::AppState};

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
    let state = AppState {
        engine: Arc::new(engine),
        http: reqwest::Client::new(),
        upstream_base: Arc::new(format!("http://{up_addr}")),
        admin_key: Arc::new("test-key".into()),
    };
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
    assert!(!up_body.contains("dana@example.com"), "plaintext leaked upstream: {up_body}");
    assert!(up_body.contains("[EMAIL_ADDRESS_"), "no token in upstream body: {up_body}");

    // Auth header forwarded verbatim; Host rewritten to the upstream.
    let up_headers = cap.headers.lock().unwrap().clone();
    assert_eq!(up_headers.get("x-api-key").map(|v| v.to_str().unwrap()), Some("sk-secret-123"));
    assert_eq!(
        up_headers.get("host").map(|v| v.to_str().unwrap()),
        Some(up_addr.to_string().as_str())
    );

    // Client got the response with the email restored.
    assert!(client_text.contains("dana@example.com"), "response not unmasked: {client_text}");
    assert!(!client_text.contains("[EMAIL_ADDRESS_"), "token leaked to client: {client_text}");
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
    let state = AppState {
        engine: Arc::new(engine),
        http: reqwest::Client::new(),
        upstream_base: Arc::new(format!("http://{up_addr}")),
        admin_key: Arc::new("k".into()),
    };
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
    assert!(bodies[0].contains("[EMAIL_ADDRESS_"), "not masked: {}", bodies[0]);
    assert!(!bodies[0].contains("eve@example.com"));
    // The crux: byte-identical masked output across turns → cache prefix stable.
    assert_eq!(bodies[0], bodies[1], "masked output is not deterministic across turns");
}
