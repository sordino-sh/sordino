//! End-to-end: client -> zlauder-proxy -> fake upstream. Verifies that the
//! upstream receives masked text + forwarded auth headers, and the client
//! receives an unmasked response.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use http::HeaderMap;
use zlauder_engine::{EngineConfig, MaskEngine, token_regex};
use zlauder_proxy::{config::ConfigLayers, routes::router as proxy_router, state::AppState};

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
