//! zlauder-hooks — Claude Code control-plane integration for zlauder.
//!
//! Subcommands:
//!   init           One-time per-project setup: pick a project port and write
//!                  `.claude/settings.json` + `zlauder.toml` + the `/privacy` command.
//!   session-start  Launch this project's proxy (if not already running) and emit
//!                  the SessionStart hook JSON that points Claude Code at it.
//!   statusline     One-line status indicator (on/off + profile).
//!   config         View or change privacy settings (the `/privacy` slash command).
//!   reveal <tok>   Audit: decode a token to its plaintext via the running proxy.
//!
//! ## Per-project isolation
//!
//! Each project runs its own proxy on a project-derived port (see
//! [`zlauder_state::derive_port`]), so its key, store, and config are isolated.
//! Two `claude` windows in the same project share the one proxy; different projects
//! never interfere. The port is baked into each project's `.claude/settings.json`
//! (as `ANTHROPIC_BASE_URL` + `ZLAUDER_PORT`) by `init`, so the load-bearing path is
//! the static base URL — not a best-effort dynamic env.

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use zlauder_engine::{EngineConfig, Profile};
use zlauder_state::{pick_port, read_state, reserve_port};

#[derive(Parser)]
#[command(name = "zlauder-hooks", version, about)]
struct Cli {
    /// Target proxy port. Defaults to `$ZLAUDER_PORT` (set per project by `init`),
    /// else a port derived from the project path.
    #[arg(long, env = "ZLAUDER_PORT", global = true)]
    port: Option<u16>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// One-time per-project setup (assign a port, write settings + config + command).
    Init {
        /// Project directory to set up (default: current directory).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Overwrite an existing status line / slash command if present.
        #[arg(long)]
        force: bool,
    },
    /// SessionStart hook: ensure this project's proxy is running.
    SessionStart {
        #[arg(long, env = "ZLAUDER_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value = "zlauder-proxy")]
        proxy_bin: String,
    },
    /// Print a one-line status indicator for the Claude Code status line.
    Statusline,
    /// View or change privacy settings (backs the `/privacy` slash command).
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// Reveal a masked token's plaintext (local audit).
    Reveal { token: String },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show the current privacy state (default when no action is given).
    Show,
    /// Turn masking ON.
    On {
        #[arg(long, value_enum, default_value_t = Scope::Session)]
        scope: Scope,
    },
    /// Turn masking OFF (the proxy becomes a transparent passthrough).
    Off {
        #[arg(long, value_enum, default_value_t = Scope::Session)]
        scope: Scope,
    },
    /// Apply a detection profile (sets threshold + categories + default operator).
    Profile {
        #[arg(value_enum)]
        name: ProfileArg,
        #[arg(long, value_enum, default_value_t = Scope::Session)]
        scope: Scope,
    },
    /// Enable or disable one entity category.
    Category {
        /// e.g. secrets, financial, identity, contact, personal.
        name: String,
        #[arg(value_enum)]
        state: OnOff,
        #[arg(long, value_enum, default_value_t = Scope::Session)]
        scope: Scope,
    },
    /// Set the detection score threshold (0.0–1.0; lower = more aggressive).
    Threshold {
        value: f32,
        #[arg(long, value_enum, default_value_t = Scope::Session)]
        scope: Scope,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Scope {
    /// Live on this project's running proxy only; not persisted (lost on restart).
    Session,
    /// Persist to `./zlauder.toml` (committed) and apply now if the proxy is up.
    Project,
    /// Persist to `~/.config/zlauder/config.toml` (all projects) and apply now.
    User,
    /// Persist to `./zlauder.local.toml` (gitignored) and apply now.
    Local,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProfileArg {
    Strict,
    Balanced,
    Minimal,
    DevelopmentSafe,
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Strict => Profile::Strict,
            ProfileArg::Balanced => Profile::Balanced,
            ProfileArg::Minimal => Profile::Minimal,
            ProfileArg::DevelopmentSafe => Profile::DevelopmentSafe,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OnOff {
    On,
    Off,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { dir, force } => init(dir, force),
        Cmd::SessionStart { config, proxy_bin } => session_start(cli.port, config, proxy_bin),
        Cmd::Statusline => statusline(cli.port),
        Cmd::Config { action } => config_cmd(cli.port, action),
        Cmd::Reveal { token } => reveal(cli.port, token),
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn init(dir: Option<PathBuf>, force: bool) -> Result<()> {
    let root_path =
        dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    std::fs::create_dir_all(&root_path).ok();
    let root = canonical(&root_path);
    // Atomically reserve the port (writes a durable reservation record) so a second
    // project that hashes to the same port can SEE this claim before either proxy
    // runs and probe past it — closing the init-time split-brain (review F1/HIGH).
    let port = reserve_port(&root)?;

    // .claude/settings.json
    let claude_dir = root_path.join(".claude");
    std::fs::create_dir_all(&claude_dir).context("creating .claude/")?;
    install_settings(&claude_dir.join("settings.json"), port, force)?;

    // .claude/commands/privacy.md (the /privacy slash command)
    let cmd_dir = claude_dir.join("commands");
    std::fs::create_dir_all(&cmd_dir).context("creating .claude/commands/")?;
    let cmd_path = cmd_dir.join("privacy.md");
    if force || !cmd_path.exists() {
        std::fs::write(&cmd_path, PRIVACY_COMMAND_MD).context("writing privacy command")?;
    }

    // zlauder.toml (project config) — only if absent (don't clobber a tuned one).
    let cfg_path = root_path.join("zlauder.toml");
    if !cfg_path.exists() {
        std::fs::write(&cfg_path, project_config_template(port)).context("writing zlauder.toml")?;
    }

    println!("zlauder initialised for this project.");
    println!("  project : {root}");
    println!("  port    : {port}  (ANTHROPIC_BASE_URL=http://127.0.0.1:{port})");
    println!(
        "  wrote   : .claude/settings.json, .claude/commands/privacy.md{}",
        if cfg_path.exists() {
            ", zlauder.toml"
        } else {
            ""
        }
    );
    println!();
    println!("Make sure `zlauder-proxy` and `zlauder-hooks` are on PATH, then start");
    println!("`claude` from this directory. Use `/privacy` to view or change settings.");
    Ok(())
}

fn install_settings(path: &Path, port: u16, force: bool) -> Result<()> {
    let mut root: serde_json::Map<String, Value> = if path.exists() {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).unwrap_or_default()
    } else {
        serde_json::Map::new()
    };

    // env: base URL (load-bearing) + ZLAUDER_PORT (so the CLI/statusline target us).
    let env = root.entry("env").or_insert_with(|| json!({}));
    if let Some(env) = env.as_object_mut() {
        env.insert(
            "ANTHROPIC_BASE_URL".into(),
            json!(format!("http://127.0.0.1:{port}")),
        );
        env.insert("ZLAUDER_PORT".into(), json!(port.to_string()));
    }

    // hooks.SessionStart: add our launcher if not already present.
    ensure_session_hook(&mut root);

    // statusLine: set if absent (or forced) — don't clobber a custom one silently.
    if force || !root.contains_key("statusLine") {
        root.insert(
            "statusLine".into(),
            json!({"type": "command", "command": "zlauder-hooks statusline"}),
        );
    }

    let text = serde_json::to_string_pretty(&Value::Object(root))?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn ensure_session_hook(root: &mut serde_json::Map<String, Value>) {
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let Some(hooks) = hooks.as_object_mut() else {
        return;
    };
    let list = hooks
        .entry("SessionStart")
        .or_insert_with(|| Value::Array(vec![]));
    let Some(arr) = list.as_array_mut() else {
        return;
    };
    let already = arr.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .map(|hs| {
                hs.iter().any(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c.contains("zlauder-hooks session-start"))
                })
            })
            .unwrap_or(false)
    });
    if !already {
        arr.push(json!({
            "matcher": "*",
            "hooks": [{"type": "command", "command": "zlauder-hooks session-start"}]
        }));
    }
}

// ---------------------------------------------------------------------------
// session-start
// ---------------------------------------------------------------------------

fn session_start(port: Option<u16>, config: Option<PathBuf>, proxy_bin: String) -> Result<()> {
    // Drain stdin (the SessionStart hook payload) so the pipe doesn't block.
    let mut _stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut _stdin);

    let root = canonical(&project_root());
    let port = port.unwrap_or_else(|| pick_port(&root));
    let base_url = format!("http://127.0.0.1:{port}");
    let config = config.or_else(|| {
        let p = Path::new(&root).join("zlauder.toml");
        p.exists().then_some(p)
    });

    if !proxy_healthy(port) {
        // Reuse this port's SALT (and only the salt) iff the existing record is
        // OURS, so a crashed-and-relaunched proxy keeps minting the SAME tokens
        // (prompt-cache prefix stable). We must NOT inherit another project's salt
        // (that would correlate tokens across projects — review F6/C2), nor reuse
        // any key: the proxy mints a fresh encryption key and writes its own state.
        let salt_hex = match read_state(port) {
            Ok(st) if st.project_root == root && st.salt.len() == 32 => st.salt,
            _ => {
                let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut salt);
                hex(&salt)
            }
        };

        let dir = zlauder_state::state_dir()?;
        let log = std::fs::File::create(dir.join(format!("proxy-{port}.log")))
            .context("creating proxy log")?;
        let log_err = log.try_clone()?;

        let mut cmd = std::process::Command::new(&proxy_bin);
        cmd.arg("--port")
            .arg(port.to_string())
            .arg("--project-root")
            .arg(&root)
            .env("ZLAUDER_SESSION_SALT", &salt_hex)
            .env("ZLAUDER_PROJECT_ROOT", &root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err));
        if let Some(cfg) = &config {
            cmd.arg("--config").arg(cfg);
        }
        cmd.spawn()
            .with_context(|| format!("spawning proxy binary '{proxy_bin}'"))?;

        // Wait for the listener so the first request doesn't race the bind.
        for _ in 0..40 {
            if proxy_healthy(port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    } else if let Ok(st) = read_state(port)
        && !st.project_root.is_empty()
        && st.project_root != root
    {
        // A healthy proxy is already on our port but belongs to a DIFFERENT project
        // — a port collision (e.g. a hand-copied settings.json; `init`'s atomic
        // reservation prevents this in the normal flow). Reusing it would mask our
        // traffic under that project's salt/store. Warn loudly; the static
        // ANTHROPIC_BASE_URL still points here, so the fix is to re-init.
        eprintln!(
            "zlauder: WARNING — port {port} is serving a different project ({}). \
             Your traffic would be masked under that project. Run `zlauder-hooks init` \
             in this directory to get a fresh, isolated port.",
            st.project_root
        );
    }

    // SessionStart hook output. The static `env` written by `init` into
    // settings.json is the load-bearing path for ANTHROPIC_BASE_URL; the `env` key
    // here is a best-effort override for harness versions that honor it.
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext":
                "zlauder PII masking proxy active for this project. Outbound text is masked \
                 before it reaches the model; responses are unmasked on return. Tokens look \
                 like [EMAIL_ADDRESS_xxxx]. Configure with the /privacy command."
        },
        "env": { "ANTHROPIC_BASE_URL": base_url, "ZLAUDER_PORT": port.to_string() }
    });
    println!("{out}");
    Ok(())
}

// ---------------------------------------------------------------------------
// statusline
// ---------------------------------------------------------------------------

fn statusline(port: Option<u16>) -> Result<()> {
    let root = canonical(&project_root());
    let port = port.unwrap_or_else(|| pick_port(&root));

    if !proxy_healthy(port) {
        println!("\u{26a0} zlauder off");
        return Ok(());
    }
    // Try the (key-gated) config endpoint for a richer indicator. We only show the
    // shield (🛡) when we have CONFIRMED masking is on; any unconfirmed state (key
    // desync / 403 / stale state / unfamiliar shape) degrades to "❔ unverified" —
    // never a false shield (review finding C5).
    match key_for(port).and_then(|k| admin_get(port, &k)) {
        Ok(snap) => match serde_json::from_value::<Snapshot>(snap) {
            Ok(s) if s.enabled => println!("\u{1f6e1} zlauder :{port} {}", s.config.profile),
            Ok(_) => println!("\u{26a0} zlauder OFF :{port}"),
            Err(_) => println!("\u{2754} zlauder :{port} (unverified)"),
        },
        Err(_) => println!("\u{2754} zlauder :{port} (unverified)"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// config (/privacy)
// ---------------------------------------------------------------------------

fn config_cmd(port: Option<u16>, action: Option<ConfigAction>) -> Result<()> {
    let root = canonical(&project_root());
    let port = port.unwrap_or_else(|| pick_port(&root));

    match action.unwrap_or(ConfigAction::Show) {
        ConfigAction::Show => {
            let snap = live_snapshot(port)
                .context("could not reach this project's proxy (is a `claude` session running?)")?;
            print_status(&snap, port)?;
        }
        ConfigAction::On { scope } => apply_enabled(port, &root, scope, true)?,
        ConfigAction::Off { scope } => apply_enabled(port, &root, scope, false)?,
        ConfigAction::Profile { name, scope } => apply_profile(port, &root, scope, name.into())?,
        ConfigAction::Category { name, state, scope } => {
            apply_category(port, &root, scope, &name, matches!(state, OnOff::On))?
        }
        ConfigAction::Threshold { value, scope } => apply_threshold(port, &root, scope, value)?,
    }
    Ok(())
}

fn apply_enabled(port: u16, root: &str, scope: Scope, on: bool) -> Result<()> {
    if scope == Scope::Session {
        let key =
            key_for(port).context("proxy not running; use --scope project/user to persist")?;
        let snap = admin_post(port, &key, if on { "enable" } else { "disable" })?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["enabled"] = toml_edit::value(on);
    })?;
    finish_file_scope(port, scope, root, if on { "enable" } else { "disable" })
}

fn apply_threshold(port: u16, root: &str, scope: Scope, value: f32) -> Result<()> {
    anyhow::ensure!(
        (0.0..=1.0).contains(&value),
        "threshold must be in 0.0..=1.0"
    );
    if scope == Scope::Session {
        let key =
            key_for(port).context("proxy not running; use --scope project/user to persist")?;
        let mut cfg = admin_get(port, &key)?;
        cfg["config"]["score_threshold"] = json!(value);
        let snap = admin_put(port, &key, &cfg["config"])?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["score_threshold"] = toml_edit::value(f32_to_toml(value));
    })?;
    finish_file_scope(port, scope, root, "reload")
}

/// Widen an `f32` to `f64` via its shortest decimal form, so a value like `0.3`
/// persists as `0.3` in TOML rather than `0.30000001192092896`.
fn f32_to_toml(v: f32) -> f64 {
    format!("{v}").parse().unwrap_or(v as f64)
}

fn apply_profile(port: u16, root: &str, scope: Scope, profile: Profile) -> Result<()> {
    // Authoritative profile defaults come from the engine (no CLI drift).
    let defaults = EngineConfig::for_profile(profile);
    let profile_str = serde_json::to_value(profile)?;
    let threshold = defaults.score_threshold;
    let categories = categories_to_json(&defaults.enabled_categories);
    let operator = serde_json::to_value(defaults.default_operator)?;

    if scope == Scope::Session {
        let key =
            key_for(port).context("proxy not running; use --scope project/user to persist")?;
        let mut cfg = admin_get(port, &key)?;
        cfg["config"]["profile"] = profile_str;
        cfg["config"]["score_threshold"] = json!(threshold);
        cfg["config"]["enabled_categories"] = categories;
        cfg["config"]["default_operator"] = operator;
        let snap = admin_put(port, &key, &cfg["config"])?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    let cats: Vec<String> = categories
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["profile"] = toml_edit::value(profile_str.as_str().unwrap_or("balanced"));
        doc["engine"]["score_threshold"] = toml_edit::value(f32_to_toml(threshold));
        doc["engine"]["enabled_categories"] = toml_edit::value(str_array(&cats));
        // default_operator is a table { kind = "..." }; write its kind.
        if let Some(kind) = operator.get("kind").and_then(Value::as_str) {
            let mut t = toml_edit::InlineTable::new();
            t.insert("kind", kind.into());
            doc["engine"]["default_operator"] = toml_edit::value(t);
        }
    })?;
    finish_file_scope(port, scope, root, "reload")
}

fn apply_category(port: u16, root: &str, scope: Scope, name: &str, on: bool) -> Result<()> {
    let name = name.to_lowercase();
    validate_category(&name)?;

    // Base the toggle on the effective set (live proxy, else the config files —
    // never the balanced default, which would clobber a custom persisted set).
    let mut cats = effective_categories(port, root);
    if on {
        if !cats.contains(&name) {
            cats.push(name.clone());
        }
    } else {
        cats.retain(|c| c != &name);
    }
    cats.sort();
    cats.dedup();

    if scope == Scope::Session {
        let key =
            key_for(port).context("proxy not running; use --scope project/user to persist")?;
        let mut cfg = admin_get(port, &key)?;
        cfg["config"]["enabled_categories"] = json!(cats);
        let snap = admin_put(port, &key, &cfg["config"])?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["enabled_categories"] = toml_edit::value(str_array(&cats));
    })?;
    finish_file_scope(port, scope, root, "reload")
}

/// After editing a scope file: apply it live (if the proxy is up) via `action`, and
/// report where it was persisted. Most edits use `"reload"` (re-read the files);
/// the master switch uses `"enable"`/`"disable"` because `reload` deliberately
/// preserves the live switch (so an unrelated edit can't flip masking — review F3).
fn finish_file_scope(port: u16, scope: Scope, root: &str, action: &str) -> Result<()> {
    let path = scope_path(scope, root);
    let applied = match key_for(port).and_then(|k| admin_post(port, &k, action)) {
        Ok(snap) => {
            print_applied(&snap, port, scope_label(scope))?;
            true
        }
        Err(_) => false,
    };
    if !applied {
        println!(
            "saved to {} ({} scope). The proxy isn't running, so it will apply on the next session.",
            path.display(),
            scope_label(scope)
        );
    } else {
        println!(
            "persisted to {} ({} scope).",
            path.display(),
            scope_label(scope)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// reveal
// ---------------------------------------------------------------------------

fn reveal(port: Option<u16>, token: String) -> Result<()> {
    let root = canonical(&project_root());
    let port = port.unwrap_or_else(|| pick_port(&root));
    let key = key_for(port).context("reading session state (is the proxy running?)")?;
    let url = format!(
        "http://127.0.0.1:{port}/zlauder/reveal/{}",
        percent_encode(&token)
    );
    let resp = blocking_client()
        .get(&url)
        .header("x-zlauder-key", &key)
        .send()
        .context("calling proxy reveal endpoint")?;
    if resp.status().is_success() {
        println!("{}", resp.text().unwrap_or_default());
        Ok(())
    } else {
        bail!(
            "reveal failed: {} ({})",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }
}

// ---------------------------------------------------------------------------
// admin HTTP helpers
// ---------------------------------------------------------------------------

fn key_for(port: u16) -> Result<String> {
    Ok(read_state(port)?.admin_key)
}

fn live_snapshot(port: u16) -> Result<Value> {
    let key = key_for(port)?;
    admin_get(port, &key)
}

fn admin_get(port: u16, key: &str) -> Result<Value> {
    let resp = blocking_client()
        .get(format!("http://127.0.0.1:{port}/zlauder/config"))
        .header("x-zlauder-key", key)
        .send()?;
    json_or_err(resp)
}

fn admin_post(port: u16, key: &str, path: &str) -> Result<Value> {
    let resp = blocking_client()
        .post(format!("http://127.0.0.1:{port}/zlauder/{path}"))
        .header("x-zlauder-key", key)
        .send()?;
    json_or_err(resp)
}

fn admin_put(port: u16, key: &str, config: &Value) -> Result<Value> {
    let resp = blocking_client()
        .put(format!("http://127.0.0.1:{port}/zlauder/config"))
        .header("x-zlauder-key", key)
        .json(config)
        .send()?;
    json_or_err(resp)
}

fn json_or_err(resp: reqwest::blocking::Response) -> Result<Value> {
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if status.is_success() {
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    } else {
        bail!("proxy returned {status}: {text}");
    }
}

// ---------------------------------------------------------------------------
// category helpers
// ---------------------------------------------------------------------------

fn validate_category(name: &str) -> Result<()> {
    // Round-trip through the engine's Category enum (snake_case) for validity.
    if serde_json::from_value::<zlauder_engine::Category>(json!(name)).is_err() {
        bail!("unknown category '{name}'. valid: secrets, financial, identity, contact, personal");
    }
    Ok(())
}

fn category_set_to_vec(cats: &std::collections::HashSet<zlauder_engine::Category>) -> Vec<String> {
    let mut v: Vec<String> = cats
        .iter()
        .filter_map(|c| {
            serde_json::to_value(c)
                .ok()
                .and_then(|j| j.as_str().map(str::to_string))
        })
        .collect();
    v.sort();
    v
}

fn categories_to_json(cats: &std::collections::HashSet<zlauder_engine::Category>) -> Value {
    json!(category_set_to_vec(cats))
}

/// Effective categories to base a toggle on: the authoritative LIVE proxy if
/// reachable, else computed from the config FILES (user < project < local) — NOT
/// the balanced default, which would silently erase a custom persisted set when the
/// proxy happens to be down (review finding F2/C4).
fn effective_categories(port: u16, root: &str) -> Vec<String> {
    if let Ok(snap) = live_snapshot(port)
        && let Some(arr) = snap
            .pointer("/config/enabled_categories")
            .and_then(Value::as_array)
    {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    categories_from_files(root)
}

/// Merge `enabled_categories` across the config files (last layer that sets it
/// wins). If no layer sets it explicitly, fall back to the **balanced default** —
/// matching the proxy's actual deserialization, which uses the serde default and
/// does NOT derive categories from `profile` (that field is informational). Keeping
/// this identical to the proxy means an offline edit produces the same base the live
/// proxy would (review re-pass: a profile-derived fallback diverged from the proxy).
fn categories_from_files(root: &str) -> Vec<String> {
    let layers = [
        zlauder_state::user_config_path(),
        Path::new(root).join("zlauder.toml"),
        Path::new(root).join("zlauder.local.toml"),
    ];
    let mut cats: Option<Vec<String>> = None;
    for p in layers {
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
            continue;
        };
        if let Some(arr) = doc
            .get("engine")
            .and_then(|e| e.get("enabled_categories"))
            .and_then(|v| v.as_array())
        {
            cats = Some(
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
            );
        }
    }
    cats.unwrap_or_else(|| category_set_to_vec(&EngineConfig::default().enabled_categories))
}

// ---------------------------------------------------------------------------
// scope file editing (toml_edit, preserves comments/formatting)
// ---------------------------------------------------------------------------

fn scope_path(scope: Scope, root: &str) -> PathBuf {
    match scope {
        Scope::Project => Path::new(root).join("zlauder.toml"),
        Scope::Local => Path::new(root).join("zlauder.local.toml"),
        Scope::User => zlauder_state::user_config_path(),
        Scope::Session => PathBuf::from("(session)"),
    }
}

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::Session => "session",
        Scope::Project => "project",
        Scope::User => "user",
        Scope::Local => "local",
    }
}

fn edit_scope_file(
    scope: Scope,
    root: &str,
    edits: impl FnOnce(&mut toml_edit::DocumentMut),
) -> Result<()> {
    let path = scope_path(scope, root);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_else(|_| toml_edit::DocumentMut::new());
    if !doc.contains_key("engine") {
        doc["engine"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    edits(&mut doc);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, doc.to_string())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn str_array(items: &[String]) -> toml_edit::Array {
    let mut a = toml_edit::Array::new();
    for s in items {
        a.push(s.as_str());
    }
    a
}

// ---------------------------------------------------------------------------
// status printing
// ---------------------------------------------------------------------------

/// Typed view of the proxy's config snapshot. Required fields (`enabled`,
/// `config.*`) are NOT `default`ed: if the proxy's shape ever drifts, parsing
/// fails loudly rather than silently reporting a wrong/optimistic state — critical
/// for a privacy tool (never claim masking is ON when we can't confirm it).
#[derive(serde::Deserialize)]
struct Snapshot {
    enabled: bool,
    #[serde(default)]
    project_root: String,
    #[serde(default)]
    token_count: u64,
    config: SnapConfig,
}

#[derive(serde::Deserialize)]
struct SnapConfig {
    profile: String,
    score_threshold: f64,
    enabled_categories: Vec<String>,
}

fn parse_snapshot(snap: &Value) -> Result<Snapshot> {
    serde_json::from_value(snap.clone())
        .context("proxy returned an unexpected config-snapshot shape (version mismatch?)")
}

fn print_status(snap: &Value, port: u16) -> Result<()> {
    print_snapshot(&parse_snapshot(snap)?, port);
    Ok(())
}

fn print_applied(snap: &Value, port: u16, scope: &str) -> Result<()> {
    let s = parse_snapshot(snap)?;
    println!(
        "masking is now {} ({scope} scope).",
        if s.enabled { "ON" } else { "OFF" }
    );
    print_snapshot(&s, port);
    Ok(())
}

fn print_snapshot(s: &Snapshot, port: u16) {
    let state = if s.enabled { "ON " } else { "OFF" };
    println!(
        "zlauder privacy — {state}   (profile: {}, port {port})",
        s.config.profile
    );
    if !s.project_root.is_empty() {
        println!("  project    : {}", s.project_root);
    }
    println!("  categories : {}", s.config.enabled_categories.join(", "));
    println!("  threshold  : {:.2}", s.config.score_threshold);
    println!("  tokens this session : {}", s.token_count);
    if !s.enabled {
        println!("  NOTE: masking is OFF — outbound text reaches the model unmasked.");
    }
}

// ---------------------------------------------------------------------------
// misc helpers
// ---------------------------------------------------------------------------

fn project_root() -> PathBuf {
    std::env::var_os("CLAUDE_PROJECT_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn canonical(p: &Path) -> String {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .expect("building blocking client")
}

fn proxy_healthy(port: u16) -> bool {
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
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// templates
// ---------------------------------------------------------------------------

const PRIVACY_COMMAND_MD: &str = include_str!("../../../assets/privacy.md");

fn project_config_template(port: u16) -> String {
    format!(
        r#"# zlauder runtime configuration for this project.
# The SessionStart hook launches the proxy with this file as the project layer.
# `/privacy` (or `zlauder-hooks config`) edits the [engine] table below.

[proxy]
port = {port}
bind = "127.0.0.1"
upstream_base_url = "https://api.anthropic.com"

[engine]
# Master switch. `/privacy off` flips this.
enabled = true
profile = "balanced"
score_threshold = 0.5
language = "en"
default_operator = {{ kind = "token" }}
enabled_categories = ["secrets", "financial", "identity", "contact"]
fail_closed = false

[engine.entity_operators]
CREDIT_CARD = {{ kind = "mask", char = "*", from_end = 4 }}

[engine.allow_list]
exact = ["Anthropic", "Claude", "127.0.0.1"]
exact_ci = ["localhost"]
patterns = ['^\d{{4}}$']
"#
    )
}
