//! zlauder-proxy — local reverse proxy that masks PII in Claude Code's
//! Anthropic Messages API traffic and unmasks responses on the wire.
//!
//! One proxy per project (the SessionStart hook launches it). By default it binds an
//! OS-assigned ephemeral port (sticky-reusing its last port when free); a static
//! `[proxy] port` pins one instead. The proxy is the authoritative writer of its
//! project-keyed rendezvous record: after it binds it records the real port + key/salt/
//! pid, so the `zlauder-hooks` CLI always reaches a key that matches the live proxy —
//! even if two sessions race to start.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use clap::Parser;
use zlauder_engine::{EngineConfig, MaskEngine, MlConfig};
use zlauder_proxy::{
    bind, config, ml, monitor::Monitor, routes, secrets as proxy_secrets, state::AppState,
};

#[derive(Parser, Debug)]
#[command(name = "zlauder-proxy", version, about)]
struct Args {
    /// Static port to pin (overrides config). Omitted ⇒ OS-assigned ephemeral port
    /// (the default), sticky-reusing this project's last port when it's free.
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

    // A user-pinned `[proxy] port`/`--port` is a static pin; absent ⇒ ephemeral.
    let static_port = args.port.or(cfg.port);
    let bind = args.bind.unwrap_or(cfg.bind);
    let upstream = args.upstream.unwrap_or(cfg.upstream_base_url);
    let project_root = resolve_project_root(args.project_root);

    // Bind BEFORE building state so the actual (OS-assigned, for the ephemeral default)
    // port flows into AppState.port and the published rendezvous. Loopback-only unless
    // explicitly acknowledged. The launch nonce lets the hook confirm it adopted the
    // exact proxy instance it spawned (echoed on /healthz).
    bind::loopback_guard(&bind)?;
    let launch_nonce = std::env::var("ZLAUDER_LAUNCH_NONCE").unwrap_or_default();
    let listener = bind::bind_listener(&bind, static_port, &project_root).await?;
    let port = listener
        .local_addr()
        .context("reading the bound port")?
        .port();

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
    // Reserved `Local` (owner-reveal) secret: mask the proxy's OWN admin key so a model
    // that echoes it (e.g. the monitor URL) cannot splice it into a tool argument — yet it
    // is still REVEALED on the display path, so the relayed URL works. Install it
    // SYNCHRONOUSLY before serving and FAIL CLOSED — if the engine rejects the rule we
    // refuse to serve rather than serve with the admin key on the auto-PII unmask path.
    // The background secret resolve (below) re-prepends it, so this is not clobbered.
    engine
        .set_secret_rules(vec![proxy_secrets::admin_key_rule(&admin_key)])
        .context("installing the reserved admin-key (Local) rule")?;
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
    // The background resolve re-installs ALL rules (REPLACE), so it must re-prepend the
    // reserved admin-key rule or it would clobber the synchronous install above.
    let admin_key_for_secrets = admin_key.clone();
    // Seed the monitor's session `Local` scrub set BEFORE serving, so a CROSS-TURN-revealed
    // admin key is re-masked out of the captured reply (the manifest-only capture scrub would
    // miss a `Local` value with no current-turn manifest entry). The clone shares the monitor's
    // inner; the background resolve re-sets it in case the REPLACE adds further Local rules.
    let monitor_for_secrets = state.monitor.clone();
    state
        .monitor
        .set_local_redactions(state.engine.local_redaction_pairs());
    let app = routes::router(state);
    let addr = format!("{bind}:{port}");

    // We bound the port → we are the live proxy for this project. Publish the authoritative
    // rendezvous record (keyed by project identity) BEFORE serving so the CLI never reads a
    // key that doesn't match us; the hook looks us up by project root.
    // Captured for the graceful-shutdown cleanup below before these values move into the record.
    let shutdown_nonce = launch_nonce.clone();
    let shutdown_root = project_root.clone();
    let base_url = format!("http://127.0.0.1:{port}");
    if let Err(e) = zlauder_state::write_rendezvous(&zlauder_state::Rendezvous {
        project_root,
        port,
        admin_key,
        salt: salt_hex,
        base_url,
        pid: std::process::id(),
        bind,
        last_port: port,
        build_id: zlauder_state::BUILD_ID.to_string(),
        started_unix: zlauder_state::now_unix(),
        nonce: launch_nonce,
    }) {
        tracing::warn!("could not write rendezvous record (CLI may not find the proxy): {e}");
    }

    tracing::info!("zlauder-proxy listening on http://{addr} -> {upstream}");

    // Kick off ML in the background; masking is regex-only until `Ready`.
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
            let (status, all_ok) = proxy_secrets::resolve_and_install(
                &secret_specs,
                &engine_for_secrets,
                &registry,
                &admin_key_for_secrets,
            )
            .await;
            // The REPLACE re-installed the Local rule(s); refresh the monitor's scrub set.
            monitor_for_secrets
                .set_local_redactions(engine_for_secrets.local_redaction_pairs());
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

    // Graceful shutdown completed — clear OUR rendezvous so a clean stop leaves no stale
    // record behind (dead pid/port). Guarded by nonce+pid so a successor proxy that already
    // replaced us keeps its own record.
    if let Err(e) = zlauder_state::rendezvous_remove_if_owned(
        &shutdown_root,
        &shutdown_nonce,
        std::process::id(),
    ) {
        tracing::warn!("could not remove rendezvous on shutdown: {e}");
    }
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

/// `--download-model`: cache local weights or probe an HTTP endpoint, then exit.
async fn download_model(mut ml: MlConfig, model_override: Option<String>) -> anyhow::Result<()> {
    if let Some(m) = model_override {
        ml.model = m;
    }
    if ml.backend == zlauder_engine::MlBackend::Http {
        println!(
            "ZlauDeR: [engine.ml] backend = \"http\" — nothing to download; probing \
             the endpoint {} instead.",
            ml.endpoint.as_deref().unwrap_or("(unset)")
        );
    } else {
        println!(
            "ZlauDeR: downloading ML model '{}' for CPU inference. The first run can be \
             large and slow; it caches under the HuggingFace cache (HF_HOME / \
             ~/.cache/huggingface).",
            ml.model
        );
    }
    let model = ml.model.clone();
    let res = tokio::task::spawn_blocking(move || zlauder_engine::ml::download(&ml))
        .await
        .context("download task panicked")?;
    match res {
        Ok(()) => {
            println!(
                "ZlauDeR: model '{model}' ready (cached / endpoint probed). Enable it \
                 with `/zlauder:privacy model on`."
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
