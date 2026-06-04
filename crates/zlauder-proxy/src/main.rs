//! zlauder-proxy — local reverse proxy that masks PII in Claude Code's
//! Anthropic Messages API traffic and unmasks responses on the wire.
//!
//! One proxy per project (the SessionStart hook launches it on a project-derived
//! port). The proxy is the authoritative writer of its state file: after it binds
//! the port it records its real key/salt/pid, so the `zlauder-hooks` CLI always
//! reaches a key that matches the live proxy — even if two sessions race to start.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use zlauder_engine::{EngineConfig, MaskEngine};
use zlauder_proxy::{config, routes, state::AppState};

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
    let port = args.port.unwrap_or(cfg.port);
    let bind = args.bind.unwrap_or(cfg.bind);
    let upstream = args.upstream.unwrap_or(cfg.upstream_base_url);
    let project_root = resolve_project_root(args.project_root);

    let engine = build_engine(cfg.engine)?;
    let (key, salt) = engine.session_handle();
    let admin_key = hex_encode(&key);
    let salt_hex = hex_encode(&salt);
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
    };

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

/// Build the engine, reusing the SessionStart-issued key+salt from the
/// environment when present (so token minting is stable for the whole session).
fn build_engine(cfg: EngineConfig) -> anyhow::Result<MaskEngine> {
    let key = std::env::var("ZLAUDER_SESSION_KEY").ok();
    let salt = std::env::var("ZLAUDER_SESSION_SALT").ok();
    match (key, salt) {
        (Some(k), Some(s)) => {
            let key = decode_hex_array::<32>(&k).context("ZLAUDER_SESSION_KEY (need 64 hex)")?;
            let salt = decode_hex_array::<16>(&s).context("ZLAUDER_SESSION_SALT (need 32 hex)")?;
            MaskEngine::with_session(cfg, key, salt).context("building engine")
        }
        _ => MaskEngine::new(cfg).context("building engine"),
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
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
