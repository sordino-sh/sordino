//! zlauder-hooks — Claude Code control-plane integration for zlauder.
//!
//! Subcommands:
//!   session-start  Launch the proxy (if not already running) and emit the
//!                  SessionStart hook JSON that points Claude Code at it.
//!   statusline     One-line status indicator.
//!   reveal <tok>   Audit: decode a token to its plaintext via the running proxy.

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rand::rngs::OsRng;

#[derive(Parser)]
#[command(name = "zlauder-hooks", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// SessionStart hook: ensure the proxy is running, export ANTHROPIC_BASE_URL.
    SessionStart {
        #[arg(long, env = "ZLAUDER_PORT", default_value_t = 8787)]
        port: u16,
        #[arg(long, env = "ZLAUDER_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value = "zlauder-proxy")]
        proxy_bin: String,
    },
    /// Print a one-line status indicator for the Claude Code status line.
    Statusline {
        #[arg(long, env = "ZLAUDER_PORT", default_value_t = 8787)]
        port: u16,
    },
    /// Reveal a masked token's plaintext (local audit).
    Reveal {
        token: String,
        #[arg(long, env = "ZLAUDER_PORT", default_value_t = 8787)]
        port: u16,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::SessionStart {
            port,
            config,
            proxy_bin,
        } => session_start(port, config, proxy_bin),
        Cmd::Statusline { port } => statusline(port),
        Cmd::Reveal { token, port } => reveal(token, port),
    }
}

// ---------------------------------------------------------------------------
// session-start
// ---------------------------------------------------------------------------

fn session_start(port: u16, config: Option<PathBuf>, proxy_bin: String) -> Result<()> {
    // Drain stdin (the SessionStart hook payload) so the pipe doesn't block;
    // we don't currently need any field from it.
    let mut _stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut _stdin);

    let base_url = format!("http://127.0.0.1:{port}");

    if !proxy_healthy(port) {
        // Reuse a previously-issued key+salt for this port if one exists, so a
        // proxy that crashed and is relaunched mid-session keeps minting the SAME
        // tokens — preserving cross-turn consistency and Anthropic's prompt-cache
        // prefix. Only generate fresh bytes for a genuinely new port/state.
        let (key_hex, salt_hex) = match read_state(port) {
            Ok(st) if st.admin_key.len() == 64 && st.salt.len() == 32 => (st.admin_key, st.salt),
            _ => {
                let mut key = [0u8; 32];
                let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut key);
                OsRng.fill_bytes(&mut salt);
                (hex(&key), hex(&salt))
            }
        };

        let dir = state_dir()?;
        let log = fs::File::create(dir.join(format!("proxy-{port}.log")))
            .context("creating proxy log")?;
        let log_err = log.try_clone()?;

        let mut cmd = std::process::Command::new(&proxy_bin);
        cmd.arg("--port")
            .arg(port.to_string())
            .env("ZLAUDER_SESSION_KEY", &key_hex)
            .env("ZLAUDER_SESSION_SALT", &salt_hex)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err));
        if let Some(cfg) = &config {
            cmd.arg("--config").arg(cfg);
        }
        let child = cmd
            .spawn()
            .with_context(|| format!("spawning proxy binary '{proxy_bin}'"))?;

        write_state(port, &key_hex, &salt_hex, &base_url, child.id())?;

        // Give the listener a moment so the first request doesn't race the bind.
        for _ in 0..40 {
            if proxy_healthy(port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // SessionStart hook output. The static `env` in settings.json is the
    // load-bearing path for ANTHROPIC_BASE_URL; the `env` key here is a
    // best-effort override for harness versions that honor it.
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext":
                "zlauder PII masking proxy active. Outbound text is masked before it reaches \
                 the model; responses are unmasked on return. Tokens look like [EMAIL_ADDRESS_xxxx]."
        },
        "env": { "ANTHROPIC_BASE_URL": base_url }
    });
    println!("{out}");
    Ok(())
}

// ---------------------------------------------------------------------------
// statusline
// ---------------------------------------------------------------------------

fn statusline(port: u16) -> Result<()> {
    if proxy_healthy(port) {
        println!("\u{1f6e1} zlauder :{port}");
    } else {
        println!("\u{26a0} zlauder off");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// reveal
// ---------------------------------------------------------------------------

fn reveal(token: String, port: u16) -> Result<()> {
    let state = read_state(port).context("reading session state (is the proxy running?)")?;
    let client = blocking_client();
    let url = format!(
        "http://127.0.0.1:{port}/zlauder/reveal/{}",
        percent_encode(&token)
    );
    let resp = client
        .get(&url)
        .header("x-zlauder-key", &state.admin_key)
        .send()
        .context("calling proxy reveal endpoint")?;
    if resp.status().is_success() {
        println!("{}", resp.text().unwrap_or_default());
        Ok(())
    } else {
        anyhow::bail!("reveal failed: {} ({})", resp.status(), resp.text().unwrap_or_default());
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct ProxyState {
    port: u16,
    admin_key: String,
    /// Hex of the session token salt; reused across proxy restarts on this port
    /// so tokens (and the prompt-cache prefix) stay stable mid-session.
    #[serde(default)]
    salt: String,
    base_url: String,
    pid: u32,
}

fn state_dir() -> Result<PathBuf> {
    let base = std::env::var_os("ZLAUDER_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("zlauder")))
        .unwrap_or_else(|| std::env::temp_dir().join("zlauder"));
    fs::create_dir_all(&base).with_context(|| format!("creating state dir {base:?}"))?;
    set_mode(&base, 0o700);
    Ok(base)
}

fn state_path(port: u16) -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("proxy-{port}.json")))
}

fn write_state(port: u16, admin_key: &str, salt: &str, base_url: &str, pid: u32) -> Result<()> {
    let path = state_path(port)?;
    let st = ProxyState {
        port,
        admin_key: admin_key.to_string(),
        salt: salt.to_string(),
        base_url: base_url.to_string(),
        pid,
    };
    fs::write(&path, serde_json::to_vec_pretty(&st)?)?;
    set_mode(&path, 0o600);
    Ok(())
}

fn read_state(port: u16) -> Result<ProxyState> {
    let path = state_path(port)?;
    let bytes = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .expect("building blocking client")
}

fn proxy_healthy(port: u16) -> bool {
    // Cheap liveness check that doesn't need the full client timeout machinery.
    if TcpListener::bind(("127.0.0.1", port)).is_ok() {
        // Port is free => nothing is listening.
        return false;
    }
    blocking_client()
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Percent-encode everything that isn't an unreserved URL char (so `[` and `]`
/// in tokens survive as a path segment).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        let unreserved =
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &std::path::Path, _mode: u32) {}
