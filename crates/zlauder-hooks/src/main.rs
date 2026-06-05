//! zlauder-hooks — Claude Code control-plane integration for zlauder.
//!
//! Subcommands:
//!   session-start  Launch this project's proxy (if not already running) and emit
//!                  the SessionStart hook JSON that points Claude Code at it. On the
//!                  first launch it atomically reserves the project's derived port.
//!   statusline     One-line status indicator (on/off + profile).
//!   config         View or change privacy settings (backs `/zlauder:privacy`).
//!   reveal <tok>   Audit: decode a token to its plaintext via the running proxy.
//!
//! Per-project setup (writing `ANTHROPIC_BASE_URL` + `ZLAUDER_PORT` and a status
//! line into `.claude/settings.json`) is done by the Claude Code plugin's
//! `/zlauder:enable` command, not by this binary — the plugin is the sole install
//! interface. See `zlauder-plugin/`.
//!
//! ## Per-project isolation
//!
//! Each project runs its own proxy on a project-derived port (see
//! [`zlauder_state::derive_port`]), so its key, store, and config are isolated.
//! Two `claude` windows in the same project share the one proxy; different projects
//! never interfere. The port is baked into each project's `.claude/settings.json`
//! (as `ANTHROPIC_BASE_URL` + `ZLAUDER_PORT`) by `/zlauder:enable`, so the
//! load-bearing path is the static base URL — not a best-effort dynamic env.

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
    /// Target proxy port. Defaults to `$ZLAUDER_PORT` (set per project by
    /// `/zlauder:enable`), else a port derived from the project path.
    #[arg(long, env = "ZLAUDER_PORT", global = true)]
    port: Option<u16>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// SessionStart hook: ensure this project's proxy is running.
    SessionStart {
        #[arg(long, env = "ZLAUDER_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value = "zlauder-proxy")]
        proxy_bin: String,
    },
    /// Print a one-line status indicator for the Claude Code status line.
    Statusline,
    /// View or change privacy settings (backs the `/zlauder:privacy` command).
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
    /// View or toggle the optional ML recognizer (openai/privacy-filter, CPU).
    Ml {
        #[command(subcommand)]
        action: Option<MlAction>,
    },
}

#[derive(Subcommand)]
enum MlAction {
    /// Show the ML model status (default).
    Status,
    /// Turn the ML recognizer ON (the model loads in the background).
    On {
        /// Override the model repo id (persisted only with a file scope).
        #[arg(long)]
        model: Option<String>,
        #[arg(long, value_enum, default_value_t = Scope::Session)]
        scope: Scope,
    },
    /// Turn the ML recognizer OFF (live; drops the model from the detection path).
    Off {
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
        Cmd::SessionStart { config, proxy_bin } => session_start(cli.port, config, proxy_bin),
        Cmd::Statusline => statusline(cli.port),
        Cmd::Config { action } => config_cmd(cli.port, action),
        Cmd::Reveal { token } => reveal(cli.port, token),
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
    // Resolve the port. With an explicit --port/$ZLAUDER_PORT (the normal case once
    // `/zlauder:enable` has baked it into settings.json) we honor it verbatim — the
    // port is already pinned, so there is nothing left to race. With no explicit
    // port (the FIRST launch, e.g. during `/zlauder:enable` before the port is
    // baked) we `reserve_port`, which atomically claims the derived port via an
    // O_EXCL record so a second project hashing to the same port can't bake it too
    // (review finding F1/HIGH — formerly owned by `init`). The proxy overwrites this
    // reservation with its live record on bind.
    let port = match port {
        Some(p) => p,
        None => reserve_port(&root)?,
    };
    let base_url = format!("http://127.0.0.1:{port}");
    let config = config.or_else(|| {
        let p = Path::new(&root).join("zlauder.toml");
        p.exists().then_some(p)
    });

    // A healthy proxy already on our port is normally reused as-is. But the proxy is
    // long-lived (one per project, kept alive across sessions), so a plugin/proxy
    // update does NOT take effect until the old process is recycled. Decide whether
    // to (re)launch: nothing healthy here, or a healthy-but-STALE build of ours.
    let mut needs_launch = !proxy_healthy(port);
    if !needs_launch {
        match read_state(port).ok() {
            // Another project's proxy holds our port — never touch it; warn.
            Some(st) if !st.project_root.is_empty() && st.project_root != root => {
                eprintln!(
                    "zlauder: WARNING — port {port} is serving a different project ({}). \
                     Your traffic would be masked under that project. Run `/zlauder:disable` \
                     then `/zlauder:enable` in this project to get a fresh, isolated port.",
                    st.project_root
                );
            }
            // Ours (or unowned): recycle it if its reported build differs from ours.
            // Guard on known ids so we never churn when either side can't report one
            // (an "unknown" build, or a pre-build-id proxy whose /healthz says "ok"
            // — that "ok" != our SHA, so an older proxy is correctly recycled too).
            st => {
                let ours = zlauder_state::BUILD_ID;
                if ours != "unknown"
                    && let Some(running) = proxy_build_id(port)
                    && running != "unknown"
                    && running != ours
                {
                    eprintln!(
                        "zlauder: proxy on :{port} is build '{running}', current is '{ours}' \
                         — restarting to apply the update."
                    );
                    stop_proxy(port, st.as_ref().map(|s| s.pid).unwrap_or(0));
                    needs_launch = true;
                }
            }
        }
    }

    if needs_launch {
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
        if let Err(e) = cmd.spawn() {
            // A hard spawn failure (e.g. proxy binary missing) must not leave the
            // O_EXCL reservation we may have just written behind to pin this
            // project's derived port forever. Drop it iff it's still our unbound
            // reservation; a live proxy's record (pid != 0) is never touched.
            clear_reservation_if_ours(port, &root);
            return Err(e).with_context(|| format!("spawning proxy binary '{proxy_bin}'"));
        }

        // Wait for the listener so the first request doesn't race the bind.
        for _ in 0..40 {
            if proxy_healthy(port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // SessionStart hook output. The static `env` written by `/zlauder:enable` into
    // settings.json is the load-bearing path for ANTHROPIC_BASE_URL; the `env` key
    // here is a best-effort override for harness versions that honor it.
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext":
                "zlauder PII masking proxy active for this project. Outbound text is masked \
                 before it reaches the model; responses are unmasked on return. Tokens look \
                 like [EMAIL_ADDRESS_xxxx]. Configure with the /zlauder:privacy command."
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
            Ok(s) if s.enabled => {
                println!(
                    "\u{1f6e1} zlauder :{port} {}{}",
                    s.config.profile,
                    ml_indicator(s.ml.as_ref())
                )
            }
            Ok(_) => println!("\u{26a0} zlauder OFF :{port}"),
            Err(_) => println!("\u{2754} zlauder :{port} (unverified)"),
        },
        Err(_) => println!("\u{2754} zlauder :{port} (unverified)"),
    }
    Ok(())
}

/// Compact ML indicator appended to the status line when masking is on: a brain
/// when the model is filtering, an hourglass while it loads (the user's cue that
/// their text is NOT yet filtered through it), a warning if a load failed.
fn ml_indicator(ml: Option<&MlSnap>) -> &'static str {
    match ml.map(|m| m.status.as_str()) {
        Some("ready") => " \u{1f9e0}",      // 🧠 filtering
        Some("loading") => " \u{23f3}ml",   // ⏳ml loading — not filtered yet
        Some("failed") => " \u{26a0}ml",    // ⚠ml load failed
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// config (/zlauder:privacy)
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
        ConfigAction::Ml { action } => ml_cmd(port, &root, action.unwrap_or(MlAction::Status))?,
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// config ml (/zlauder:privacy model …)
// ---------------------------------------------------------------------------

fn ml_cmd(port: u16, root: &str, action: MlAction) -> Result<()> {
    match action {
        MlAction::Status => {
            let snap = live_snapshot(port).context(
                "could not reach this project's proxy (is a `claude` session running?)",
            )?;
            print_ml_line(&parse_snapshot(&snap)?, port);
            Ok(())
        }
        MlAction::On { model, scope } => apply_ml(port, root, scope, true, model),
        MlAction::Off { scope } => apply_ml(port, root, scope, false, None),
    }
}

/// Turn the ML recognizer on/off. Session scope hits the dedicated control
/// endpoint (live, not persisted); file scopes persist `[engine.ml]` then apply
/// live (a `reload` first so a model change is picked up, then the toggle).
fn apply_ml(port: u16, root: &str, scope: Scope, on: bool, model: Option<String>) -> Result<()> {
    let endpoint = if on { "ml/enable" } else { "ml/disable" };

    if scope == Scope::Session {
        let key =
            key_for(port).context("proxy not running; use --scope project/user to persist")?;
        let snap = admin_post(port, &key, endpoint)?;
        print_ml_applied(&snap, port, "session", on);
        return Ok(());
    }

    edit_scope_file(scope, root, |doc| {
        doc["engine"]["ml"]["enabled"] = toml_edit::value(on);
        if let Some(m) = &model {
            doc["engine"]["ml"]["model"] = toml_edit::value(m.as_str());
        }
    })?;

    let path = scope_path(scope, root);
    let applied = match key_for(port) {
        Ok(key) => {
            // For ON, reload first so a `--model` change in the file is loaded into
            // the live config before we flip the toggle (which starts the load).
            if on {
                let _ = admin_post(port, &key, "reload");
            }
            admin_post(port, &key, endpoint).ok()
        }
        Err(_) => None,
    };
    match applied {
        Some(snap) => print_ml_applied(&snap, port, scope_label(scope), on),
        None => println!(
            "saved to {} ({} scope). The proxy isn't running, so ML will apply on the next session.",
            path.display(),
            scope_label(scope)
        ),
    }
    Ok(())
}

fn print_ml_applied(snap: &Value, port: u16, scope: &str, on: bool) {
    if on {
        println!(
            "openai-privacy requested ON ({scope} scope). The model loads in the BACKGROUND — \
             your text is NOT filtered through it until status is `ready`; you can keep working \
             (regex-only) or wait."
        );
    } else {
        println!("openai-privacy turned OFF ({scope} scope).");
    }
    if let Ok(s) = parse_snapshot(snap) {
        print_ml_line(&s, port);
    }
}

/// Print the ML model line(s) of a snapshot.
fn print_ml_line(s: &Snapshot, port: u16) {
    let Some(ml) = &s.ml else {
        println!("openai-privacy: not reported by this proxy (older build?).");
        return;
    };
    println!("openai-privacy (port {port}):");
    println!("  model   : {}", ml.model);
    println!("  desired : {}", if ml.enabled { "on" } else { "off" });
    let status = match ml.status.as_str() {
        "ready" => "ready — filtering active".to_string(),
        "loading" => {
            "loading — NOT filtering through the model yet; wait, or continue regex-only".to_string()
        }
        "failed" => format!(
            "failed{}",
            ml.error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        ),
        "disabled" => "disabled".to_string(),
        other => other.to_string(),
    };
    println!("  status  : {status}");
    if ml.status == "disabled" {
        println!(
            "  tip: run `/zlauder:privacy model download` once, then `/zlauder:privacy model on`."
        );
    }
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
    /// Optional ML runtime block (absent on older proxies).
    #[serde(default)]
    ml: Option<MlSnap>,
}

#[derive(serde::Deserialize)]
struct SnapConfig {
    profile: String,
    score_threshold: f64,
    enabled_categories: Vec<String>,
}

/// The proxy's `ml` runtime block: desired flag + model + live lifecycle.
#[derive(serde::Deserialize)]
struct MlSnap {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    model: String,
    /// `disabled` | `loading` | `ready` | `failed` (see `zlauder_engine::MlStatus`).
    #[serde(default)]
    status: String,
    #[serde(default)]
    error: Option<String>,
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
    if let Some(ml) = &s.ml {
        let ml_state = match ml.status.as_str() {
            "ready" => format!("ON — {} ready (filtering active)", ml.model),
            "loading" => format!(
                "LOADING {} — NOT filtering through it yet (continue regex-only, or wait)",
                ml.model
            ),
            "failed" => format!(
                "FAILED {}{}",
                ml.model,
                ml.error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ),
            _ => "off".to_string(),
        };
        println!("  ml model   : {ml_state}");
    }
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

/// The build id the proxy on `port` reports (its `/healthz` body), if reachable.
/// A pre-build-id proxy returns `"ok"`; an unreachable/erroring proxy returns None.
fn proxy_build_id(port: u16) -> Option<String> {
    blocking_client()
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.text().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Stop the proxy on `port` so a fresh build can take its place. SIGINT to `pid`
/// (the proxy shuts down gracefully on ctrl_c), wait for the listener to drop, then
/// escalate to SIGKILL. The state file — and thus the token salt — is left intact,
/// so the relaunched proxy reuses the same salt and tokens stay prompt-cache stable.
fn stop_proxy(port: u16, pid: u32) {
    let signal = |sig: &str| {
        if pid != 0 {
            let _ = std::process::Command::new("kill")
                .arg(sig)
                .arg(pid.to_string())
                .status();
        }
    };
    signal("-INT");
    for _ in 0..60 {
        // ~3s graceful
        if !proxy_healthy(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    signal("-KILL");
    for _ in 0..40 {
        // ~2s backstop
        if !proxy_healthy(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!(
        "zlauder: WARNING — proxy on :{port} (pid {pid}) did not exit; the new one may fail to bind."
    );
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
// reservation cleanup
// ---------------------------------------------------------------------------

/// Remove the port's state file iff it is still *our* unbound reservation
/// (`pid == 0`, matching project root). Used to undo a `reserve_port` claim when the
/// proxy spawn fails, so a transient launch error can't permanently pin a project's
/// derived port. A live-proxy record (`pid != 0`) or another project's record is
/// never touched.
fn clear_reservation_if_ours(port: u16, root: &str) {
    if let Ok(st) = read_state(port)
        && st.pid == 0
        && st.project_root == root
        && let Ok(path) = zlauder_state::state_path(port)
    {
        let _ = std::fs::remove_file(path);
    }
}
