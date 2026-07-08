//! End-to-end proof of the opt-in policy-event ledger: a request whose body carries a
//! registered secret trips the verbatim-relay 409 tripwire AND appends exactly one
//! class-only JSONL line — and the secret VALUE never appears in the file (the no-value
//! invariant, asserted as a test).

use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use sordino_engine::{EngineConfig, MaskEngine};
use sordino_proxy::{
    config::ConfigLayers,
    monitor::{Ledger, LedgerEvent, Monitor},
    routes::router as proxy_router,
    state::AppState,
};

/// The registered secret value placed in the request body. Deliberately distinctive so
/// the "value never appears in the file" assertion is unambiguous.
const SECRET: &str = "sk-live-ledger-9f8e7d6c5b4a";
/// The project root the test proxy binds — the ledger `project` field must equal its key.
const ROOT: &str = "/tmp/sordino-ledger-test-project";

fn unique_ledger_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sordino-ledger-events-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// A `MaskEngine` with `SECRET` registered (Tier-1 exact) — mirrors integration.rs's
/// `f1f9_engine_with_secret`.
fn engine_with_secret() -> MaskEngine {
    let e = MaskEngine::new(EngineConfig::default()).unwrap();
    e.set_secret_rules(vec![sordino_engine::SecretRule {
        name: "wire_test_key".into(),
        value: sordino_engine::SecretValue::new(SECRET),
        operator: sordino_engine::Operator::Hash,
        case_sensitive: true,
        apply_to_surfaces: None,
    }])
    .unwrap();
    e
}

/// Build an `AppState` for `engine` with the ledger ENABLED at `ledger_path`. Upstream
/// points at a dead loopback port — the tripwire refuses BEFORE any egress, so no real
/// upstream is needed.
fn state_with_ledger(engine: MaskEngine, ledger_path: &std::path::Path) -> AppState {
    let project = sordino_state::project_key(ROOT);
    let ledger = Ledger::open(ledger_path, project).expect("open ledger");
    AppState {
        engine: Arc::new(engine),
        http: reqwest::Client::new(),
        upstream_base: Arc::new("http://127.0.0.1:1".into()),
        admin_key: Arc::new("k".into()),
        layers: Arc::new(ConfigLayers {
            user: std::path::PathBuf::from("/nonexistent/sordino/config.toml"),
            project: None,
            local: None,
        }),
        project_root: Arc::new(ROOT.into()),
        port: 0,
        monitor: Monitor::new(),
        ledger: Some(Arc::new(ledger)),
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

async fn spawn(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn wire_refusal_appends_one_class_only_ledger_line() {
    let ledger_path = unique_ledger_path();
    let _ = std::fs::remove_file(&ledger_path);

    let state = state_with_ledger(engine_with_secret(), &ledger_path);
    let proxy_addr = spawn(proxy_router(state)).await;

    // A verbatim-relay body carrying the registered secret → 409, ZERO bytes upstream.
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/files"))
        .body(format!("please attach {SECRET} to the upload"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "a registered-secret body must refuse 409"
    );

    // Exactly one JSONL line, correctly shaped.
    let mut contents = String::new();
    std::fs::File::open(&ledger_path)
        .expect("ledger file must exist after a refusal")
        .read_to_string(&mut contents)
        .unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 1, "exactly one wire_refusal line, got {lines:?}");

    let ev: LedgerEvent = serde_json::from_str(lines[0]).expect("valid JSONL event");
    assert_eq!(ev.action, "wire_refusal");
    assert_eq!(
        ev.project,
        sordino_state::project_key(ROOT),
        "project must be this proxy's project key"
    );
    assert_eq!(ev.entity_class, "registered_secret");
    assert_eq!(ev.channel, "body");
    assert!(
        ev.ts.contains('T') && ev.ts.ends_with('Z'),
        "ts must be RFC3339 UTC, got {}",
        ev.ts
    );

    // The no-value invariant: the secret's plaintext must NOT appear anywhere in the file.
    assert!(
        !contents.contains(SECRET),
        "the ledger must NEVER contain the secret value"
    );

    let _ = std::fs::remove_file(&ledger_path);
}
