//! zlauder-proxy — local reverse proxy that masks PII in Claude Code's
//! Anthropic Messages API traffic and unmasks responses on the wire.
//!
//! One proxy per project (the SessionStart hook launches it on a project-derived
//! port). The proxy is the authoritative writer of its state file: after it binds
//! the port it records its real key/salt/pid, so the `zlauder-hooks` CLI always
//! reaches a key that matches the live proxy — even if two sessions race to start.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use clap::Parser;
use zlauder_engine::{EngineConfig, MaskEngine, MlConfig};
use zlauder_proxy::{config, ml, monitor::Monitor, routes, secrets as proxy_secrets, state::AppState};

#[derive(Parser, Debug)]
#[command(name = "zlauder-proxy", version, about)]
struct Args {
    /// Port to listen on (overrides config; default 8787).
    #[arg(long, env = "ZLAUDER_PORT")]
    port: Option<u16>,
    /// Bind address (overrides config; default 127.0.0.1).
    #[arg(long, env = "ZLAUDER_BIND")]
    bind: Option<String>,
    /// Path to zlauder.toml (the project-scope config layer).
    #[arg(long, env = "ZLAUDER_CONFIG")]
    config: Option<PathBuf>,
    /// Upstream base URL (overrides config; default https://api.anthropic.com).
    #[arg(long, env = "ZLAUDER_UPSTREAM")]
    upstream: Option<String>,
    /// Absolute project root this proxy serves (for the state record / config GET).
    #[arg(long, env = "ZLAUDER_PROJECT_ROOT")]
    project_root: Option<PathBuf>,
    /// Download + cache the ML model, then exit (do NOT start the server). Pre-warms
    /// the HuggingFace cache so a later `/zlauder:privacy model on` is fast.
    #[arg(long)]
    download_model: bool,
    /// Override the ML model repo id for `--download-model` (else the config's
    /// `[engine.ml].model`, default `openai/privacy-filter`).
    #[arg(long)]
    model: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zlauder_proxy=info,warn".into()),
        )
        .init();

    let args = Args::parse();
    let cfg = config::load(args.config.as_deref())?;

    // One-shot model download mode: fetch/cache the weights and exit.
    if args.download_model {
        return download_model(cfg.engine.ml, args.model).await;
    }

    let port = args.port.unwrap_or(cfg.port);
    let bind = args.bind.unwrap_or(cfg.bind);
    let upstream = args.upstream.unwrap_or(cfg.upstream_base_url);
    let project_root = resolve_project_root(args.project_root);

    // Registered-secret refs (resolved in the background after we bind). Captured
    // before `cfg.engine` is moved into `build_engine`.
    let secret_specs = cfg.secrets;
    let broker_allows = cfg.broker_allows;
    let secrets_gating = secret_specs.iter().any(|s| s.required);
    let proot_for_secrets = project_root.clone();

    // Keep the ML config to drive the background load once we're serving.
    let ml_cfg = cfg.engine.ml.clone();
    let engine = build_engine(cfg.engine)?;
    // Install the broker policy (glob-compiled). A bad rule fails CLOSED: log it and
    // leave the default-deny policy so no broker secret can resolve.
    if !broker_allows.is_empty() {
        match proxy_secrets::build_broker_policy(&broker_allows) {
            Ok(p) => engine.set_broker_policy(p),
            Err(e) => tracing::error!(
                "zlauder: invalid [broker] policy ({e}); broker resolution DISABLED (default-deny)"
            ),
        }
    }
    let (_key, salt) = engine.session_handle();
    let salt_hex = hex_encode(&salt);
    // The `x-zlauder-key` is a control token DERIVED from the AES key (blake3), not
    // the key itself — so the 0600 state file grants control-plane access but not
    // offline decryption of the transcript.
    let admin_key = engine.control_token();
    let http = reqwest::Client::builder()
        .build()
        .context("building HTTP client")?;

    let state = AppState {
        engine: Arc::new(engine),
        http,
        upstream_base: Arc::new(upstream.clone()),
        admin_key: Arc::new(admin_key.clone()),
        layers: Arc::new(cfg.layers),
        project_root: Arc::new(project_root.clone()),
        port,
        monitor: Monitor::new(),
        ml_control: Arc::new(std::sync::Mutex::new(())),
        config_control: Arc::new(std::sync::Mutex::new(())),
        // Open immediately when nothing is `required` (zero overhead for no-secret
        // projects); else closed until the background resolve confirms all required.
        secrets_ready: Arc::new(AtomicBool::new(!secrets_gating)),
        secrets_status: Arc::new(RwLock::new(proxy_secrets::SecretsStatus::default())),
    };

    // Hold engine/secrets handles so we can kick off background work after we start
    // serving (the router consumes `state`).
    let engine_for_ml = state.engine.clone();
    let engine_for_secrets = state.engine.clone();
    let secrets_ready = state.secrets_ready.clone();
    let secrets_status = state.secrets_status.clone();
    let app = routes::router(state);
    let addr = format!("{bind}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;

    // We bound the port → we are the live proxy for it. Record authoritative
    // state BEFORE serving so the CLI never reads a key that doesn't match us.
    // (A racing rival that failed to bind exits above and never writes.)
    let base_url = format!("http://127.0.0.1:{port}");
    if let Err(e) = zlauder_state::write_state(&zlauder_state::ProxyState {
        port,
        admin_key,
        salt: salt_hex,
        base_url,
        pid: std::process::id(),
        project_root,
    }) {
        tracing::warn!("could not write state file (reveal/config CLI may not find the key): {e}");
    }

    tracing::info!("zlauder-proxy listening on http://{addr} -> {upstream}");

    // We're serving (bound above). Kick off the ML model load in the background if
    // it's enabled in config — masking runs regex-only until it reports `Ready`.
    if ml_cfg.enabled {
        ml::spawn_ml_load(engine_for_ml, ml_cfg);
    }

    // Resolve registered secrets in the background (provider CLIs may block on
    // gpg-agent etc.). Until all REQUIRED secrets resolve, the readiness gate holds
    // LLM intake at 503 (fail-closed); `/healthz` already answers above for liveness.
    if !secret_specs.is_empty() {
        tokio::spawn(async move {
            let registry =
                zlauder_secrets::default_registry(Some(PathBuf::from(&proot_for_secrets)));
            let (status, all_ok) =
                proxy_secrets::resolve_and_install(&secret_specs, &engine_for_secrets, &registry)
                    .await;
            let (resolved, total) = (status.resolved(), status.entries.len());
            if let Ok(mut slot) = secrets_status.write() {
                *slot = status;
            }
            if all_ok {
                secrets_ready.store(true, Ordering::Relaxed);
                tracing::info!("zlauder: {resolved}/{total} secret(s) resolved; intake open");
            } else {
                tracing::warn!(
                    "zlauder: required secret(s) unresolved ({resolved}/{total}); LLM intake held at 503"
                );
            }
        });
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

/// Canonical absolute project root: `--project-root`/env, else `CLAUDE_PROJECT_DIR`,
/// else the current working directory.
fn resolve_project_root(explicit: Option<PathBuf>) -> String {
    let raw = explicit
        .or_else(|| std::env::var_os("CLAUDE_PROJECT_DIR").map(PathBuf::from))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::canonicalize(&raw)
        .unwrap_or(raw)
        .to_string_lossy()
        .into_owned()
}

/// Build the engine, reusing the SessionStart-issued *salt* from the environment
/// when present (so token minting stays stable across a proxy restart). The
/// encryption key is always fresh — the reversible store is in-memory only, so the
/// key never needs to persist, and not persisting it keeps decryption material off
/// disk and out of the process environment.
fn build_engine(cfg: EngineConfig) -> anyhow::Result<MaskEngine> {
    match std::env::var("ZLAUDER_SESSION_SALT").ok() {
        Some(s) => {
            let salt = decode_hex_array::<16>(&s).context("ZLAUDER_SESSION_SALT (need 32 hex)")?;
            MaskEngine::with_salt(cfg, salt).context("building engine")
        }
        None => MaskEngine::new(cfg).context("building engine"),
    }
}

/// `--download-model`: fetch + cache the model weights, then exit. Heavy +
/// blocking, so it runs on a blocking thread (the loader drives hf-hub on its own
/// runtime). Independent of `[engine.ml].enabled` — it only pre-warms the cache.
async fn download_model(mut ml: MlConfig, model_override: Option<String>) -> anyhow::Result<()> {
    if let Some(m) = model_override {
        ml.model = m;
    }
    println!(
        "ZlauDeR: downloading ML model '{}' for CPU inference. The first run can be \
         large and slow; it caches under the HuggingFace cache (HF_HOME / \
         ~/.cache/huggingface).",
        ml.model
    );
    let model = ml.model.clone();
    let res = tokio::task::spawn_blocking(move || zlauder_engine::ml::download(&ml))
        .await
        .context("download task panicked")?;
    match res {
        Ok(()) => {
            println!(
                "ZlauDeR: model '{model}' downloaded and cached. Enable it with \
                 `/zlauder:privacy model on`."
            );
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "downloading model '{model}': {e}. Check the repo id, network / HF_TOKEN, \
             and free disk space."
        )),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex_array<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    let s = s.trim();
    anyhow::ensure!(
        s.len() == N * 2,
        "expected {} hex chars, got {}",
        N * 2,
        s.len()
    );
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex at byte {i}"))?;
    }
    Ok(out)
}

async fn shutdown_signal() {
    // The proxy runs detached (the hooks launcher setsid's it on Unix / spawns it
    // DETACHED on Windows), so it must drain gracefully on SIGTERM as well as SIGINT —
    // SIGTERM is what a bare `kill <pid>`, an OS shutdown, and an updated launcher all
    // send. Catching only ctrl_c (SIGINT) would let those hard-terminate it mid-request.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            // Couldn't register SIGTERM — fall back to SIGINT-only rather than never draining.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutting down");
}
