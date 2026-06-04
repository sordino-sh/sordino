//! zlauder-proxy — local reverse proxy that masks PII in Claude Code's
//! Anthropic Messages API traffic and unmasks responses on the wire.

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
    /// Path to zlauder.toml.
    #[arg(long, env = "ZLAUDER_CONFIG")]
    config: Option<PathBuf>,
    /// Upstream base URL (overrides config; default https://api.anthropic.com).
    #[arg(long, env = "ZLAUDER_UPSTREAM")]
    upstream: Option<String>,
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

    let engine = build_engine(cfg.engine)?;
    let admin_key = hex_encode(&engine.session_handle().0);
    let http = reqwest::Client::builder()
        .build()
        .context("building HTTP client")?;

    let state = AppState {
        engine: Arc::new(engine),
        http,
        upstream_base: Arc::new(upstream.clone()),
        admin_key: Arc::new(admin_key),
    };

    let app = routes::router(state);
    let addr = format!("{bind}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!("zlauder-proxy listening on http://{addr} -> {upstream}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
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
    anyhow::ensure!(s.len() == N * 2, "expected {} hex chars, got {}", N * 2, s.len());
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
