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

mod transcript;

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
        #[arg(long, default_value_t = default_proxy_bin())]
        proxy_bin: String,
    },
    /// Reserve (O_EXCL) this project's derived proxy port and print it. Used by
    /// `/zlauder:enable` to learn the port to bake into settings.json WITHOUT launching
    /// the proxy or emitting SessionStart output — the proxy launches on the next
    /// SessionStart that is actually routed through it (i.e. after the user restarts).
    ReservePort,
    /// Print a one-line status indicator for the Claude Code status line.
    Statusline,
    /// View or change privacy settings (backs the `/zlauder:privacy` command).
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// PreToolUse hook: resolve allow-listed BROKER secrets into the tool input.
    /// Reads the PreToolUse payload (tool_name + tool_input) on stdin, asks the proxy
    /// to splice allow-listed broker values, and emits `hookSpecificOutput.updatedInput`.
    /// FAIL-CLOSED: on ANY error (no proxy/key, timeout, non-2xx, nothing resolved) it
    /// emits nothing, so the tool runs with the broker TOKEN unresolved — never a leak.
    PreToolUse,
    /// Reveal a masked token's plaintext (local audit).
    Reveal { token: String },
    /// Print the keyed local web monitor URL for this project's proxy.
    Monitor,
    /// View registered-secret status (backs `/zlauder:secrets`). Read-only — secret
    /// VALUES never appear (registration is by reference in `[[secrets]]`).
    Secrets {
        #[command(subcommand)]
        action: Option<SecretsAction>,
    },
    /// Redact burned plaintext values from a Claude Code transcript JSONL file.
    Scrub {
        /// Transcript JSONL file to mutate.
        #[arg(long)]
        transcript: PathBuf,
        /// Plaintext value to redact. Repeat for multiple burned values.
        #[arg(long = "value")]
        values: Vec<String>,
        /// File containing one plaintext value per line.
        #[arg(long)]
        values_file: Option<PathBuf>,
        /// Print the planned mutation but do not write the file.
        #[arg(long)]
        dry_run: bool,
        /// Replacement string for redacted values.
        #[arg(long, default_value = "[REDACTED]")]
        replacement: String,
        /// Keep thinking blocks instead of dropping contaminated thinking.
        #[arg(long)]
        keep_thinking: bool,
    },
    /// Patch this project's .claude/settings.json to route through (or stop routing
    /// through) the zlauder proxy. Backs `/zlauder:enable` and `/zlauder:disable`,
    /// replacing the former shell+jq implementation so the plugin needs no `jq` on PATH
    /// (a hard blocker on Windows). Exit codes are a contract — see `SettingsAction`.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },
}

#[derive(Subcommand)]
enum SettingsAction {
    /// Wire env.ANTHROPIC_BASE_URL + env.ZLAUDER_PORT and take over the statusLine slot
    /// (wrapping any existing line to the sidecar). A missing settings.json is treated as
    /// `{}` (and created). Exit 0 = file changed (caller prints the RESTART banner);
    /// exit 3 = already pointed at this proxy, nothing routing-relevant changed; non-zero
    /// = error (invalid JSON / write failure), message on stderr.
    Enable {
        /// Proxy base URL to bake in, e.g. http://127.0.0.1:18123.
        #[arg(long)]
        url: String,
        /// Port to store as env.ZLAUDER_PORT. Kept as a STRING (matching the historical
        /// jq behavior) and named `--zport` to avoid colliding with the global --port.
        #[arg(long = "zport")]
        zport: String,
        /// The exact statusLine command string to install.
        #[arg(long)]
        statusline: String,
    },
    /// Remove env.ANTHROPIC_BASE_URL + env.ZLAUDER_PORT (and drop an emptied env), then
    /// restore the user's original statusLine from the sidecar (or drop ours if none).
    /// Exit 0 = changed; exit 3 = already disabled / no wiring / no file; non-zero = error.
    Disable,
    /// Print env.ANTHROPIC_BASE_URL from settings.json (else settings.local.json), or
    /// "(unset)". Replaces the optional jq one-liner in privacy.sh's status path. Exit 0.
    RouteUrl,
}

fn default_proxy_bin() -> String {
    if cfg!(windows) {
        "zlauder-proxy.exe".to_string()
    } else {
        "zlauder-proxy".to_string()
    }
}

#[derive(Subcommand)]
enum SecretsAction {
    /// Show the readiness gate + resolved/required counts + any unresolved (default).
    Status,
    /// List each registered secret: name, operator, scheme, resolved — never values.
    List,
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
    /// Secrets-only. Renamed from `development-safe`; the old spelling stays as a
    /// hidden clap alias so existing scripts/docs keep working.
    #[value(name = "secrets-only", alias = "development-safe")]
    SecretsOnly,
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Strict => Profile::Strict,
            ProfileArg::Balanced => Profile::Balanced,
            ProfileArg::Minimal => Profile::Minimal,
            ProfileArg::SecretsOnly => Profile::SecretsOnly,
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
        Cmd::ReservePort => reserve_port_cmd(cli.port),
        Cmd::Statusline => statusline(cli.port),
        Cmd::Config { action } => config_cmd(cli.port, action),
        Cmd::PreToolUse => pre_tool_use(cli.port),
        Cmd::Reveal { token } => reveal(cli.port, token),
        Cmd::Monitor => monitor_cmd(cli.port),
        Cmd::Secrets { action } => secrets_cmd(cli.port, action),
        Cmd::Scrub {
            transcript,
            values,
            values_file,
            dry_run,
            replacement,
            keep_thinking,
        } => scrub_cmd(
            transcript,
            values,
            values_file,
            dry_run,
            replacement,
            keep_thinking,
        ),
        Cmd::Settings { action } => settings_cmd(action),
    }
}

// ---------------------------------------------------------------------------
// settings — patch .claude/settings.json (replaces the former shell+jq path)
// ---------------------------------------------------------------------------

/// Outcome of a settings mutation, mapped to the shell's exit-code contract:
/// `Changed` => exit 0 (caller prints the RESTART banner), `NoOp` => exit 3 (caller
/// prints "already pointed…"/"already disabled…"). Hard errors bubble as `anyhow` (exit 1).
enum SettingsOutcome {
    Changed,
    NoOp,
}

fn settings_cmd(action: SettingsAction) -> Result<()> {
    let outcome = match action {
        SettingsAction::Enable {
            url,
            zport,
            statusline,
        } => settings_enable(&url, &zport, &statusline)?,
        SettingsAction::Disable => settings_disable()?,
        SettingsAction::RouteUrl => {
            print_route_url();
            return Ok(());
        }
    };
    match outcome {
        SettingsOutcome::Changed => Ok(()),
        SettingsOutcome::NoOp => std::process::exit(3),
    }
}

/// A leading UTF-8 BOM is not JSON whitespace, so serde_json rejects it — and it's common
/// in a settings.json saved by a Windows editor. Strip it before parsing on every read.
fn strip_bom(s: &str) -> &str {
    s.strip_prefix('\u{feff}').unwrap_or(s)
}

/// Read+parse a settings.json, treating a missing file as `{}`. A parse failure is a hard
/// error — we must never clobber a file we can't understand.
fn load_settings_or_empty(path: &Path) -> Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(strip_bom(&text)).with_context(|| {
            format!(
                "{} is not valid JSON; refusing to overwrite. Fix it and re-run.",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Mutable handle to `v[key]` as an object, creating an empty one if absent or non-object.
/// `v` must already be an object.
fn ensure_object<'a>(v: &'a mut Value, key: &str) -> &'a mut serde_json::Map<String, Value> {
    let map = v.as_object_mut().expect("settings root is an object");
    if !map.get(key).map(Value::is_object).unwrap_or(false) {
        map.insert(key.to_string(), json!({}));
    }
    map.get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("just inserted an object")
}

/// Atomically write `value` as pretty JSON (2-space, trailing newline — like jq): write a
/// same-dir temp, then rename over the target. `std::fs::rename` is atomic and replaces an
/// existing file on both Unix and Windows (MoveFileEx w/ REPLACE_EXISTING).
fn atomic_write_json(path: &Path, value: &Value) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    let tmp = dir.join(format!(".settings.json.tmp-{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, text.as_bytes()) {
        return Err(e).with_context(|| format!("writing {}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replacing {}", path.display()));
    }
    Ok(())
}

fn settings_enable(url: &str, zport: &str, statusline: &str) -> Result<SettingsOutcome> {
    let proj = project_root();
    let settings_dir = proj.join(".claude");
    let settings_file = settings_dir.join("settings.json");
    std::fs::create_dir_all(&settings_dir)
        .with_context(|| format!("creating {}", settings_dir.display()))?;

    let mut v = load_settings_or_empty(&settings_file)?;
    if !v.is_object() {
        bail!(
            "{} is not a JSON object; refusing to overwrite. Fix it and re-run.",
            settings_file.display()
        );
    }

    // Idempotency: is this project ALREADY pointed at this exact proxy (url + port)?
    let cur_url = v
        .pointer("/env/ANTHROPIC_BASE_URL")
        .and_then(Value::as_str)
        .unwrap_or("");
    let cur_port = v
        .pointer("/env/ZLAUDER_PORT")
        .and_then(Value::as_str)
        .unwrap_or("");
    let already = base_url_matches(cur_url, url) && cur_port == zport;

    // Status-line takeover: snapshot the user's original line (unless it's already ours)
    // to the sidecar that /zlauder:disable restores from and the wrapper reads.
    let sidecar = wrap_sidecar_path(&proj);
    let cur_sl_cmd = v
        .pointer("/statusLine/command")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !is_zlauder_statusline(cur_sl_cmd) {
        match v.get("statusLine") {
            Some(orig) if !orig.is_null() => {
                let compact = serde_json::to_string(orig)?;
                std::fs::write(&sidecar, format!("{compact}\n"))
                    .with_context(|| format!("writing {}", sidecar.display()))?;
                println!(
                    "ZlauDeR: wrapping your existing status line (saved to {}; restored on /zlauder:disable).",
                    sidecar.display()
                );
            }
            // No prior line to wrap: clear any stale sidecar from an earlier setup.
            _ => {
                let _ = std::fs::remove_file(&sidecar);
            }
        }
    }

    // Set the routing env (always) and take over the status-line slot (always).
    let env = ensure_object(&mut v, "env");
    env.insert(
        "ANTHROPIC_BASE_URL".to_string(),
        Value::String(url.to_string()),
    );
    env.insert("ZLAUDER_PORT".to_string(), Value::String(zport.to_string()));
    v["statusLine"] = json!({ "type": "command", "command": statusline });

    atomic_write_json(&settings_file, &v)?;
    Ok(if already {
        SettingsOutcome::NoOp
    } else {
        SettingsOutcome::Changed
    })
}

fn settings_disable() -> Result<SettingsOutcome> {
    let proj = project_root();
    let settings_file = proj.join(".claude").join("settings.json");
    let sidecar = wrap_sidecar_path(&proj);

    let text = match std::fs::read_to_string(&settings_file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SettingsOutcome::NoOp),
        Err(e) => return Err(e).with_context(|| format!("reading {}", settings_file.display())),
    };
    let mut v: Value = serde_json::from_str(strip_bom(&text)).with_context(|| {
        format!(
            "{} is not valid JSON; refusing to edit. Fix it and re-run.",
            settings_file.display()
        )
    })?;

    // Trigger on ANY zlauder wiring — env key OR our status line — so disable is a true
    // inverse even in asymmetric state (e.g. a key left by a partial edit).
    let has_env_wiring = v.pointer("/env/ANTHROPIC_BASE_URL").is_some()
        || v.pointer("/env/ZLAUDER_PORT").is_some();
    let sl_is_ours = is_zlauder_statusline(
        v.pointer("/statusLine/command")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    if !has_env_wiring && !sl_is_ours {
        return Ok(SettingsOutcome::NoOp);
    }

    // The original line to restore (if enable wrapped one). `None` => just drop ours.
    let restore: Option<Value> = std::fs::read_to_string(&sidecar)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(strip_bom(&t)).ok());

    // Delete the keys enable added (and the env object if it ends up empty).
    if let Some(env) = v.get_mut("env").and_then(Value::as_object_mut) {
        env.remove("ANTHROPIC_BASE_URL");
        env.remove("ZLAUDER_PORT");
        if env.is_empty()
            && let Some(root) = v.as_object_mut()
        {
            root.remove("env");
        }
    }
    // Undo the status-line takeover only when the current line is still OURS — a line the
    // user set by hand after enabling is left alone.
    if sl_is_ours {
        match restore {
            Some(orig) => v["statusLine"] = orig,
            None => {
                if let Some(root) = v.as_object_mut() {
                    root.remove("statusLine");
                }
            }
        }
    }

    atomic_write_json(&settings_file, &v)?;
    let _ = std::fs::remove_file(&sidecar);
    Ok(SettingsOutcome::Changed)
}

/// Print env.ANTHROPIC_BASE_URL from settings.json (else settings.local.json), or
/// "(unset)". Replaces privacy.sh's optional jq one-liner. Reads in the same precedence
/// as `project_configures`.
fn print_route_url() {
    let proj = project_root();
    for name in [".claude/settings.json", ".claude/settings.local.json"] {
        if let Ok(text) = std::fs::read_to_string(proj.join(name))
            && let Ok(v) = serde_json::from_str::<Value>(strip_bom(&text))
            && let Some(u) = v
                .pointer("/env/ANTHROPIC_BASE_URL")
                .and_then(Value::as_str)
        {
            println!("{u}");
            return;
        }
    }
    println!("(unset)");
}

// ---------------------------------------------------------------------------
// scrub
// ---------------------------------------------------------------------------

fn scrub_cmd(
    path: PathBuf,
    mut values: Vec<String>,
    values_file: Option<PathBuf>,
    dry_run: bool,
    replacement: String,
    keep_thinking: bool,
) -> Result<()> {
    if let Some(values_file) = values_file {
        let text = std::fs::read_to_string(&values_file)
            .with_context(|| format!("reading {}", values_file.display()))?;
        values.extend(
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string),
        );
    }
    let opts = transcript::ScrubOptions {
        values,
        replacement,
        drop_thinking: !keep_thinking,
    };
    let report = transcript::scrub_file(&path, &opts, dry_run)?;
    if dry_run {
        println!(
            "dry run: would redact {} string occurrence(s), remove {} thinking record(s), relink {} parent pointer(s).",
            report.redactions, report.removed_thinking_records, report.relinked_records
        );
    } else {
        println!(
            "scrubbed {}: redacted {} string occurrence(s), removed {} thinking record(s), relinked {} parent pointer(s). backup: {}",
            path.display(),
            report.redactions,
            report.removed_thinking_records,
            report.relinked_records,
            report
                .backup_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(none)".to_string())
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// session-start
// ---------------------------------------------------------------------------

fn session_start(port: Option<u16>, config: Option<PathBuf>, proxy_bin: String) -> Result<()> {
    // Drain stdin (the SessionStart hook payload) so the pipe doesn't block, and
    // opportunistically extract a stable conversation key for the monitor.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let conversation = conversation_id_from_hook_payload(&stdin);

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

    // Route gate (the load-bearing accuracy check). The SessionStart hook fires in
    // EVERY project, because the plugin is installed globally — but the proxy is only
    // relevant where `/zlauder:enable` wired `ANTHROPIC_BASE_URL` into the project's
    // settings.json AND the user restarted, at which point Claude Code applies it and
    // this hook subprocess inherits it. Announcing "masking active" or launching a
    // proxy when this session is NOT actually pointed at us would be a lie (the exact
    // misleading-status bug). So gate every side effect on the session's real base URL.
    if !session_routed_through(&base_url) {
        // Configured-but-not-applied (enabled, restart pending) gets a nudge; a project
        // that never enabled zlauder stays a silent no-op.
        if project_configures(&root, &base_url) {
            eprintln!(
                "ZlauDeR: this project is configured for masking but ANTHROPIC_BASE_URL is \
                 not {base_url} yet — RESTART Claude Code to route through the proxy. \
                 Traffic is currently NOT masked."
            );
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext":
                            "ZlauDeR is configured for this project but masking is NOT active \
                             this session: Claude Code must be restarted to route through the \
                             local proxy. Until then, outbound text reaches the API provider \
                             UNMASKED — real PII, not tokens. (This is about what the provider \
                             sees; the user always sees their own plaintext locally either way.) \
                             Tell the user to restart Claude Code to activate masking."
                    }
                })
            );
        } else {
            println!("{}", json!({}));
        }
        return Ok(());
    }

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
                    "ZlauDeR: WARNING — port {port} is serving a different project ({}). \
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
                        "ZlauDeR: proxy on :{port} is build '{running}', current is '{ours}' \
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
        // Detach the long-lived proxy from THIS hook process so nothing we own can keep
        // it tethered: the proxy must outlive the session (sibling `claude` windows and
        // later sessions reuse the one per-project proxy), and it must not hold the
        // SessionStart hook's stdout pipe — the one Claude Code reads our hook JSON from —
        // open, or the FIRST `claude` (the one that launches it) stalls waiting for EOF.
        // The stdio handles are already redirected to log files; these flags drop the
        // remaining console/session tether on each platform.
        #[cfg(windows)]
        {
            // No inherited console (DETACHED_PROCESS) => no live handle back to us;
            // CREATE_NEW_PROCESS_GROUP isolates the daemon from our Ctrl-C/console events.
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        }
        #[cfg(unix)]
        {
            // POSIX analogue: setsid() puts the proxy in its OWN session with no
            // controlling terminal, so a terminal SIGHUP (or a process-group kill on
            // session exit) can't reap a daemon meant to persist. pre_exec runs in the
            // forked child before exec; setsid() is async-signal-safe and always succeeds
            // there (the fresh child is never already a process-group leader).
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
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
    let session_base_url = conversation
        .as_deref()
        .map(|c| format!("{base_url}/zlauder/session/{c}"))
        .unwrap_or_else(|| base_url.clone());
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext":
                "ZlauDeR is masking this project: a local proxy swaps PII for deterministic \
                 tokens like [EMAIL_ADDRESS_a1b2] or [API_KEY_a1b2c3] in what you receive, and \
                 restores the real values in your output — text, tool arguments, and files — \
                 before they land.\n\
                 - The user sees their real values locally; only you and the API provider ever \
                 see the tokens. Masking hides data from the provider, NOT the user — never \
                 tell the user their data is hidden, redacted, or that you can't access it.\n\
                 - Tokens are safe to use freely and reveal nothing (you only ever hold the \
                 token; it becomes the real value on the way out). Use the exact token verbatim \
                 wherever the value belongs — prose, config files (writing \
                 \"api_key\": \"[API_KEY_a1b2c3]\" puts the REAL key in the file), shell \
                 commands, tool inputs. Don't refuse, over-redact, or warn about \"exposing\" \
                 PII by using tokens; the tokenization is what makes it safe.\n\
                 Configure masking/routing with /zlauder:privacy (this project only)."
        },
        "env": { "ANTHROPIC_BASE_URL": session_base_url, "ZLAUDER_PORT": port.to_string() }
    });
    println!("{out}");
    Ok(())
}

/// Derive the conversation id the monitor groups turns under (and that the proxy
/// receives via the `/zlauder/session/{conversation}/…` path) from the SessionStart
/// hook payload.
///
/// Precedence (most-stable first): a real session id wins over a transcript-path
/// slug, because the session id is the harness's own durable identifier for the
/// conversation, whereas a transcript path is incidental, machine-specific, and
/// only ever a fallback for harness versions that don't surface a session id:
///   1. `session_id` / `sessionId`
///   2. `conversation_id` / `conversationId`
///   3. `transcript_path` / `transcriptPath`  (the embedded session id, see below)
///
/// Claude Code names transcripts `<…>/<session-uuid>.jsonl`, so when we fall back
/// to a path we slug its **file stem** — the embedded session id — not the whole
/// absolute path. That keeps the transcript-derived id short, portable, and equal
/// to the session id, instead of a long dash-joined slug of someone's home dir.
fn conversation_id_from_hook_payload(stdin: &str) -> Option<String> {
    let value: Value = serde_json::from_str(stdin).ok()?;
    for key in [
        "session_id",
        "sessionId",
        "conversation_id",
        "conversationId",
    ] {
        if let Some(raw) = find_string_key(&value, key) {
            return Some(safe_conversation_id(&raw));
        }
    }
    for key in ["transcript_path", "transcriptPath"] {
        if let Some(raw) = find_string_key(&value, key) {
            return Some(safe_conversation_id(&conversation_id_from_transcript_path(
                &raw,
            )));
        }
    }
    None
}

/// Extract the durable conversation key embedded in a transcript path: its file
/// stem (Claude Code uses `<session-uuid>.jsonl`). Falls back to the raw value
/// when there's no stem to take, so a non-path string still round-trips.
fn conversation_id_from_transcript_path(raw: &str) -> String {
    Path::new(raw)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| raw.to_string())
}

fn find_string_key(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(obj) => {
            if let Some(s) = obj.get(key).and_then(Value::as_str) {
                return Some(s.to_string());
            }
            obj.values().find_map(|v| find_string_key(v, key))
        }
        Value::Array(items) => items.iter().find_map(|v| find_string_key(v, key)),
        _ => None,
    }
}

fn safe_conversation_id(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out = out.trim_matches('-').to_string();
    if out.len() > 80 {
        let mut h = blake3::Hasher::new();
        h.update(raw.as_bytes());
        format!("{}-{}", &out[..40], &h.finalize().to_hex()[..16])
    } else if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

// ---------------------------------------------------------------------------
// reserve-port
// ---------------------------------------------------------------------------

/// Reserve this project's derived proxy port and print it (bare integer on stdout).
/// `/zlauder:enable` calls this to learn the port to bake into settings.json. Unlike
/// `session-start` it never launches the proxy or emits hook JSON — so it works during
/// a first-time enable, where the session is not yet routed through the proxy.
fn reserve_port_cmd(port: Option<u16>) -> Result<()> {
    let root = canonical(&project_root());
    let port = match port {
        Some(p) => p,
        None => reserve_port(&root)?,
    };
    println!("{port}");
    Ok(())
}

// ---------------------------------------------------------------------------
// statusline
// ---------------------------------------------------------------------------

/// How much the zlauder status-line segment shows, chosen by `$ZLAUDER_STATUSLINE`.
/// Defaults to `Compact`. `Off` hides the zlauder segment entirely — when the status
/// line wraps a user's original line (see [`read_wrap_original`]), that original still
/// prints, so `off` means "show only my line, no zlauder chrome", not "blank".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlMode {
    Off,
    Min,
    Compact,
    Verbose,
}

fn sl_mode() -> SlMode {
    match std::env::var("ZLAUDER_STATUSLINE")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("off" | "none" | "hidden" | "0" | "false") => SlMode::Off,
        Some("min" | "minimal" | "compact-min") => SlMode::Min,
        Some("verbose" | "full" | "all") => SlMode::Verbose,
        _ => SlMode::Compact,
    }
}

fn statusline(port: Option<u16>) -> Result<()> {
    let proj = project_root();
    let root = canonical(&proj);
    let port = port.unwrap_or_else(|| pick_port(&root));
    let mode = sl_mode();

    // The zlauder segment (None only in `off` mode). Built first so a slow/absent
    // wrapped command never delays or suppresses our own privacy indicator.
    let segment = match mode {
        SlMode::Off => None,
        _ => Some(render_segment(port, mode)),
    };

    // Seamless wrap: if the user already had a status line when `/zlauder:enable` ran,
    // that original was saved to a sidecar. Run it (forwarding the exact session JSON
    // Claude Code fed us on stdin) and prepend our segment, so the user keeps their
    // line as `🛡 … │ {their line}`. We only touch stdin when there's something to
    // forward — reading it unconditionally would block when run from an interactive
    // shell (e.g. someone testing `zlauder-hooks statusline` by hand).
    let wrapped = read_wrap_original(&proj).and_then(|cmd| {
        let stdin = read_stdin_bytes();
        run_wrapped(&cmd, &stdin)
    });

    let line = compose_line(segment, wrapped);
    if !line.is_empty() {
        println!("{line}");
    }
    Ok(())
}

/// Join the zlauder segment and the wrapped original line with a `│` divider. Either
/// side may be absent: `off` mode drops the segment; an unwrapped/empty original drops
/// the right side. Kept pure (no I/O) so the join rules are unit-testable.
fn compose_line(segment: Option<String>, wrapped: Option<String>) -> String {
    match (segment, wrapped) {
        (Some(seg), Some(w)) if !w.trim().is_empty() => format!("{seg} \u{2502} {w}"),
        (Some(seg), _) => seg,
        (None, Some(w)) => w,
        (None, None) => String::new(),
    }
}

/// Render the zlauder segment for a non-`Off` mode. We only show the shield (🛡) when
/// we have CONFIRMED masking is on; any unconfirmed state (proxy down / key desync /
/// 403 / stale state / unfamiliar shape) degrades to an explicit offline/off/unverified
/// marker — never a false shield (review finding C5).
fn render_segment(port: u16, mode: SlMode) -> String {
    if !proxy_healthy(port) {
        return match mode {
            SlMode::Min => "\u{26a0}".to_string(), // ⚠
            _ => "\u{26a0} ZlauDeR offline".to_string(),
        };
    }
    match key_for(port).and_then(|k| admin_get(port, &k)) {
        Ok(snap) => match serde_json::from_value::<Snapshot>(snap) {
            Ok(s) if s.enabled => render_on(&s, port, mode),
            Ok(_) => match mode {
                SlMode::Min => "\u{26a0}".to_string(),
                _ => format!("\u{26a0} ZlauDeR OFF :{port}"),
            },
            Err(_) => unverified(port, mode),
        },
        Err(_) => unverified(port, mode),
    }
}

fn unverified(port: u16, mode: SlMode) -> String {
    match mode {
        SlMode::Min => "\u{2754}".to_string(), // ❔
        _ => format!("\u{2754} ZlauDeR :{port} (unverified)"),
    }
}

/// The confirmed-on segment. `token_count` is the number of distinct tokens minted
/// this session — i.e. unique PII values caught — so it doubles as the "N PII" count.
fn render_on(s: &Snapshot, port: u16, mode: SlMode) -> String {
    let ml = ml_indicator(s.ml.as_ref());
    match mode {
        SlMode::Off => String::new(),
        SlMode::Min => "\u{1f6e1}".to_string(), // 🛡 only
        SlMode::Compact => format!(
            "\u{1f6e1} :{port} {}{}{}{}",
            s.config.profile,
            ml,
            pii_suffix(s.token_count),
            key_suffix(s.secrets.as_ref())
        ),
        SlMode::Verbose => format!(
            "\u{1f6e1} ON :{port} {} t={:.2}{} {} PII [{}]{}",
            s.config.profile,
            s.config.score_threshold,
            ml,
            s.token_count,
            s.config.enabled_categories.join(","),
            key_suffix(s.secrets.as_ref())
        ),
    }
}

/// `" 7 PII"` once anything has been caught; empty until then (keeps a fresh session's
/// line tight rather than reading `0 PII`).
/// ` 🔑N/M` when registered secrets exist (M>0); `🔑⚠N/M` when the gate is held
/// (a required secret unresolved). Empty when none configured (no visual noise for
/// no-secret projects).
fn key_suffix(secrets: Option<&SecretsSummary>) -> String {
    match secrets {
        Some(s) if s.total > 0 => {
            if s.ready {
                format!(" \u{1f511}{}/{}", s.resolved, s.total)
            } else {
                format!(" \u{1f511}\u{26a0}{}/{}", s.resolved, s.total)
            }
        }
        _ => String::new(),
    }
}

fn pii_suffix(n: u64) -> String {
    if n == 0 {
        String::new()
    } else {
        format!(" {n} PII")
    }
}

/// Compact ML indicator appended to the status line when masking is on: a brain
/// when the model is filtering, an hourglass while it loads (the user's cue that
/// their text is NOT yet filtered through it), a warning if a load failed.
fn ml_indicator(ml: Option<&MlSnap>) -> &'static str {
    match ml.map(|m| m.status.as_str()) {
        Some("ready") => " \u{1f9e0}",    // 🧠 filtering
        Some("loading") => " \u{23f3}ml", // ⏳ml loading — not filtered yet
        Some("failed") => " \u{26a0}ml",  // ⚠ml load failed
        _ => "",
    }
}

/// Path of the sidecar that holds the user's pre-zlauder `statusLine` object, written
/// by `/zlauder:enable` when it took over the slot. Lives beside `settings.json`.
fn wrap_sidecar_path(proj: &Path) -> PathBuf {
    proj.join(".claude").join("zlauder-statusline.json")
}

/// The shell command of the user's original status line, if `/zlauder:enable` wrapped
/// one. Returns `None` when no sidecar exists, it isn't a `command` status line, or —
/// defensively — the stored command is itself a zlauder status line (which would
/// recurse). The sidecar stores the original `statusLine` object verbatim so
/// `/zlauder:disable` can restore it.
fn read_wrap_original(proj: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(wrap_sidecar_path(proj)).ok()?;
    let v: Value = serde_json::from_str(strip_bom(&txt)).ok()?;
    let cmd = v.get("command")?.as_str()?.trim();
    if cmd.is_empty() || is_zlauder_statusline(cmd) {
        return None;
    }
    Some(cmd.to_string())
}

/// Is `cmd` one of OUR status-line commands — `[<path>/]zlauder-hooks[.exe] statusline`?
/// We match `zlauder-hooks statusline` (or the `.exe` form) as a contiguous substring AND
/// require `zlauder-hooks` to be a command BASENAME: at the string start, or right after a
/// path separator (`/` or `\`). enable.sh only ever emits the name bare or after `'<dir>'/`,
/// so real installs always match — but a user line where the token is merely an argument
/// (`echo zlauder-hooks statusline`) or a different binary whose name ends in it
/// (`/usr/local/bin/not-zlauder-hooks statusline`) does NOT, so we never silently eat their
/// status line. This is stricter than the old jq regex `zlauder-hooks(\.exe)? statusline`,
/// which was anchorless and would have over-claimed both. Single source of truth for
/// enable/disable's slot-ownership test and the wrapper's self-reference guard; no regex dep.
fn is_zlauder_statusline(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    for needle in ["zlauder-hooks statusline", "zlauder-hooks.exe statusline"] {
        let mut from = 0;
        while let Some(rel) = cmd[from..].find(needle) {
            let at = from + rel;
            // `zlauder-hooks` must be a basename: string start, or after a path separator.
            // Boundary chars are ASCII, so a UTF-8 continuation byte (>=0x80) correctly fails.
            if at == 0 || matches!(bytes[at - 1], b'/' | b'\\') {
                return true;
            }
            from = at + 1; // `at` indexes an ASCII 'z', so `at + 1` stays on a char boundary.
        }
    }
    false
}

fn read_stdin_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
    buf
}

/// Run the user's wrapped status-line command through the shell (matching how Claude
/// Code itself runs a `command` status line), feeding it the same session JSON on
/// stdin, and return its trimmed stdout. Any failure (spawn error, non-UTF8, empty
/// output) yields `None` so the zlauder segment still stands alone.
fn run_wrapped(cmd: &str, stdin: &[u8]) -> Option<String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // A wrapped status line that hangs (slow git, blocking network, or a child that
    // floods stdout without draining stdin) must not stall our own shield. Claude
    // Code reaps slow status lines too, but we bound it ourselves so `🛡 …` still
    // renders promptly on its own.
    const WRAP_TIMEOUT: Duration = Duration::from_millis(2000);
    // Grace for the child to exit on its own AFTER we already have its output — a
    // command can close/redirect stdout (giving us EOF) yet keep running, so we
    // never wait unbounded for exit; we force-kill the group once this elapses.
    const REAP_GRACE: Duration = Duration::from_millis(200);

    let (sh, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let mut builder = Command::new(sh);
    builder
        .arg(flag)
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Isolate the wrapped command into its own job/group so a timeout can tear down the
    // whole tree, not just the immediate shell — a backgrounded grandchild could otherwise
    // survive holding our stdout pipe open and strand the reader thread. Unix: lead a new
    // process group (kill_group signals it). Windows: a new process group, and kill_group
    // uses `taskkill /T` to reap the tree (cmd.exe + descendants).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        builder.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        builder.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = builder.spawn().ok()?;

    // Forward stdin on its OWN thread. Writing it synchronously here would deadlock
    // when the command floods stdout (filling that pipe) before draining stdin, or
    // never reads stdin and our payload exceeds the ~64KB pipe buffer — and that hang
    // precedes the timeout below, so the timeout could never fire to break it.
    if let Some(mut si) = child.stdin.take() {
        let data = stdin.to_vec();
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
            // `si` drops here, closing the child's stdin so it can finish.
        });
    }
    // Drain stdout on a worker thread so the recv below is the true worst-case bound.
    // `child` stays here so we can kill it if it overruns; the thread owns only the
    // pipe and gets EOF (then exits) once the child dies.
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let buf = match rx.recv_timeout(WRAP_TIMEOUT) {
        Ok(buf) => {
            // Output in hand — but stdout EOF only means the pipe closed, not that the
            // command exited. A wrapped line that closes/redirects stdout and keeps
            // running (`exec >/dev/null; sleep 30`) would hang an unbounded
            // `child.wait()` here long past WRAP_TIMEOUT. Give it a short grace to exit
            // cleanly (try_wait reaps that), then force-kill the group.
            let deadline = Instant::now() + REAP_GRACE;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    _ => {
                        kill_group(&mut child);
                        break;
                    }
                }
            }
            buf
        }
        Err(_) => {
            kill_group(&mut child);
            return None;
        }
    };
    let s = String::from_utf8_lossy(&buf);
    let s = s.trim_end_matches(['\n', '\r']);
    (!s.is_empty()).then(|| s.to_string())
}

/// Kill an overrunning wrapped status-line process AND its descendants, then reap it.
/// `child.kill()` alone terminates only the immediate shell (cmd.exe / sh), so a
/// backgrounded grandchild can survive holding our stdout pipe open and strand the reader
/// thread. Unix signals the whole process group (the child leads its own via
/// `process_group(0)`); Windows uses `taskkill /T` to walk the process tree.
fn kill_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // SAFETY: kill(2) with a negative pid signals the process group led by
        // `child`; a no-op (ESRCH) if the group already exited.
        let pgid = child.id() as i32;
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        // /T = terminate the whole tree (cmd.exe + its children), /F = force.
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
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
            let snap = live_snapshot(port)
                .context("could not reach this project's proxy (is a `claude` session running?)")?;
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
        "loading" => "loading — NOT filtering through the model yet; wait, or continue regex-only"
            .to_string(),
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

/// Apply a detection profile. When the proxy is reachable, this routes through the
/// SHARED `POST /zlauder/profile/{name}?scope=…` endpoint so the UI and CLI can
/// never drift on what a profile means or how it is persisted — the proxy both
/// applies it live AND persists it for a file scope. Only when the proxy is DOWN
/// does the CLI fall back to writing the scope file itself (so a profile can still
/// be persisted offline); the field shape it writes matches the proxy's
/// `persist_profile`, both deriving from `EngineConfig::for_profile`.
fn apply_profile(port: u16, root: &str, scope: Scope, profile: Profile) -> Result<()> {
    let profile_id = serde_json::to_value(profile)?
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "balanced".to_string());

    // Proxy up: the endpoint is the single source of truth for apply + persist.
    if let Ok(key) = key_for(port) {
        let path = format!("profile/{profile_id}?scope={}", scope_label(scope));
        let snap = admin_post(port, &key, &path)?;
        print_applied(&snap, port, scope_label(scope))?;
        if scope != Scope::Session {
            println!(
                "persisted to {} ({} scope).",
                scope_path(scope, root).display(),
                scope_label(scope)
            );
        }
        return Ok(());
    }

    // Proxy down: a session-scope change has nowhere to live.
    if scope == Scope::Session {
        bail!("proxy not running; use --scope project/user/local to persist");
    }

    // Proxy down + file scope: persist offline, matching the proxy's field shape.
    let defaults = EngineConfig::for_profile(profile);
    let threshold = defaults.score_threshold;
    let cats = category_set_to_vec(&defaults.enabled_categories);
    let operator = serde_json::to_value(defaults.default_operator)?;
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["profile"] = toml_edit::value(profile_id.as_str());
        doc["engine"]["score_threshold"] = toml_edit::value(f32_to_toml(threshold));
        doc["engine"]["enabled_categories"] = toml_edit::value(str_array(&cats));
        if let Some(kind) = operator.get("kind").and_then(Value::as_str) {
            let mut t = toml_edit::InlineTable::new();
            t.insert("kind", kind.into());
            doc["engine"]["default_operator"] = toml_edit::value(t);
        }
    })?;
    println!(
        "saved to {} ({} scope). The proxy isn't running, so it will apply on the next session.",
        scope_path(scope, root).display(),
        scope_label(scope)
    );
    Ok(())
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
// monitor
// ---------------------------------------------------------------------------

fn monitor_cmd(port: Option<u16>) -> Result<()> {
    let root = canonical(&project_root());
    let port = port.unwrap_or_else(|| pick_port(&root));
    let key = key_for(port).context("reading session state (is the proxy running?)")?;
    println!("http://127.0.0.1:{port}/zlauder/ui?key={key}");
    Ok(())
}

/// PreToolUse broker resolver (T2). Reads the hook payload from stdin, asks the proxy
/// to resolve allow-listed broker tokens into `tool_input`, and emits `updatedInput`.
/// Every failure path is silent (emit nothing, exit 0) so the tool runs with the
/// broker token unresolved — fail-closed, never a leak.
fn pre_tool_use(port: Option<u16>) -> Result<()> {
    use std::io::Read;
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() || buf.trim().is_empty() {
        return Ok(());
    }
    let payload: Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let tool_name = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
    if tool_name.is_empty() || tool_input.is_null() {
        return Ok(());
    }

    let root = canonical(&project_root());
    let port = port.unwrap_or_else(|| pick_port(&root));
    // No live proxy/key ⇒ emit nothing ⇒ tool runs with the token unresolved.
    let key = match key_for(port) {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };

    let req = json!({ "tool_name": tool_name, "tool_input": tool_input });
    let resp = match blocking_client()
        .post(format!("http://127.0.0.1:{port}/zlauder/broker/resolve"))
        .header("x-zlauder-key", &key)
        .json(&req)
        .send()
    {
        Ok(r) if r.status().is_success() => r,
        // timeout / connection failure / non-2xx ⇒ fail-closed (token unresolved).
        _ => return Ok(()),
    };
    let out: Value = match resp.json() {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    // Nothing resolved ⇒ don't rewrite the input (no-op hook).
    if out.get("resolved").and_then(Value::as_u64).unwrap_or(0) == 0 {
        return Ok(());
    }
    let updated = out.get("tool_input").cloned().unwrap_or(Value::Null);
    if updated.is_null() {
        return Ok(());
    }
    let emit = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated,
        }
    });
    println!("{emit}");
    Ok(())
}

/// `/zlauder:secrets` — read-only view of the registered-secret gate + status. Pulls
/// the value-free `secrets` block from the proxy snapshot. (Registration is by
/// reference in `[[secrets]]`; secret VALUES never transit this command.)
fn secrets_cmd(port: Option<u16>, action: Option<SecretsAction>) -> Result<()> {
    let root = canonical(&project_root());
    let port = port.unwrap_or_else(|| pick_port(&root));
    let snap = live_snapshot(port).context("reading secrets status (is the proxy running?)")?;
    let secrets = snap.get("secrets").cloned().unwrap_or(Value::Null);
    let ready = secrets.get("ready").and_then(Value::as_bool).unwrap_or(true);
    let total = secrets.get("total").and_then(Value::as_u64).unwrap_or(0);
    let resolved = secrets.get("resolved").and_then(Value::as_u64).unwrap_or(0);
    let required = secrets.get("required").and_then(Value::as_u64).unwrap_or(0);
    let empty: Vec<Value> = Vec::new();
    let entries = secrets
        .get("entries")
        .and_then(Value::as_array)
        .unwrap_or(&empty);

    match action.unwrap_or(SecretsAction::Status) {
        SecretsAction::Status => {
            let gate = if ready {
                "open"
            } else {
                "HELD (required secret unresolved — LLM intake 503)"
            };
            println!("secrets: {resolved}/{total} resolved, {required} required — intake {gate}");
            for e in entries {
                if !e.get("resolved").and_then(Value::as_bool).unwrap_or(false) {
                    let name = e.get("name").and_then(Value::as_str).unwrap_or("?");
                    let err = e.get("error").and_then(Value::as_str).unwrap_or("");
                    println!("  ✗ {name}: {err}");
                }
            }
        }
        SecretsAction::List => {
            if entries.is_empty() {
                println!("(no registered secrets)");
            }
            for e in entries {
                let name = e.get("name").and_then(Value::as_str).unwrap_or("?");
                let op = e.get("operator").and_then(Value::as_str).unwrap_or("?");
                let scheme = e.get("scheme").and_then(Value::as_str).unwrap_or("?");
                let ok = e.get("resolved").and_then(Value::as_bool).unwrap_or(false);
                let mark = if ok { "✓" } else { "✗" };
                println!("{mark} {name}  [{op}]  {scheme}");
            }
        }
    }
    Ok(())
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
/// wins). If no layer sets it explicitly, fall back to the **last-set profile's**
/// categories — matching the proxy's deserialization, which (since the load-bearing
/// `profile=` change) SEEDS `enabled_categories` from `profile` when the field is
/// absent. If no layer sets categories OR a profile, fall back to the default
/// (Balanced) categories. Keeping this identical to the proxy means an offline edit
/// produces the same base the live proxy would.
fn categories_from_files(root: &str) -> Vec<String> {
    let layers = [
        zlauder_state::user_config_path(),
        Path::new(root).join("zlauder.toml"),
        Path::new(root).join("zlauder.local.toml"),
    ];
    let mut cats: Option<Vec<String>> = None;
    let mut profile: Option<Profile> = None;
    for p in layers {
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
            continue;
        };
        let engine = doc.get("engine");
        if let Some(arr) = engine
            .and_then(|e| e.get("enabled_categories"))
            .and_then(|v| v.as_array())
        {
            cats = Some(
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
            );
        }
        if let Some(name) = engine
            .and_then(|e| e.get("profile"))
            .and_then(|v| v.as_str())
            && let Ok(p) = serde_json::from_value::<Profile>(json!(name))
        {
            profile = Some(p);
        }
    }
    cats.unwrap_or_else(|| {
        let base = profile
            .map(EngineConfig::for_profile)
            .unwrap_or_default()
            .enabled_categories;
        category_set_to_vec(&base)
    })
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
    /// Optional registered-secret summary (absent on older proxies). Counts only —
    /// never values.
    #[serde(default)]
    secrets: Option<SecretsSummary>,
}

/// The proxy's `secrets` block, counts only.
#[derive(serde::Deserialize)]
struct SecretsSummary {
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    total: u64,
    #[serde(default)]
    resolved: u64,
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
        "ZlauDeR privacy — {state}   (profile: {}, port {port})",
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

/// Does the current session's `ANTHROPIC_BASE_URL` (inherited from Claude Code, which
/// applies it from the project's settings.json at startup) point at OUR proxy
/// endpoint? Ground truth for "is this session actually masked through us?" — far more
/// reliable than the mere presence of the globally-installed plugin. Accepts an exact
/// match or a base-with-path (`{base}/…`) variant.
fn session_routed_through(base_url: &str) -> bool {
    match std::env::var("ANTHROPIC_BASE_URL") {
        Ok(have) => base_url_matches(&have, base_url),
        Err(_) => false,
    }
}

/// Does `have` (an `ANTHROPIC_BASE_URL` value) route through our `want` proxy endpoint?
/// Exact match, or `want` with a trailing path (`{want}/v1`), ignoring a trailing `/`.
fn base_url_matches(have: &str, want: &str) -> bool {
    let have = have.trim_end_matches('/');
    let want = want.trim_end_matches('/');
    have == want || have.starts_with(&format!("{want}/"))
}

/// Does the project's `.claude/settings.json` (or `settings.local.json`) wire
/// `env.ANTHROPIC_BASE_URL` to our proxy `base_url`? True ⇒ `/zlauder:enable` ran here
/// but the routing isn't applied to the live session yet (a restart is pending). Used
/// only to pick a helpful "restart" nudge over silence when we are not routed.
fn project_configures(root: &str, base_url: &str) -> bool {
    for name in [".claude/settings.json", ".claude/settings.local.json"] {
        let path = Path::new(root).join(name);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(strip_bom(&text)) else {
            continue;
        };
        if let Some(url) = v
            .get("env")
            .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
            .and_then(|u| u.as_str())
            && base_url_matches(url, base_url)
        {
            return true;
        }
    }
    false
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

/// Stop the proxy on `port` so a fresh build can take its place. The state file —
/// and thus the token salt — is left intact, so the relaunched proxy reuses the same
/// salt and tokens stay prompt-cache stable.
fn stop_proxy(port: u16, pid: u32) {
    #[cfg(windows)]
    let stop = |force: bool| {
        if pid != 0 {
            let mut cmd = std::process::Command::new("taskkill");
            cmd.arg("/PID").arg(pid.to_string()).arg("/T");
            if force {
                cmd.arg("/F");
            }
            let _ = cmd.status();
        }
    };
    #[cfg(not(windows))]
    let stop = |force: bool| {
        if pid != 0 {
            let sig = if force { "-KILL" } else { "-INT" };
            let _ = std::process::Command::new("kill")
                .arg(sig)
                .arg(pid.to_string())
                .status();
        }
    };
    stop(false);
    for _ in 0..60 {
        // ~3s graceful
        if !proxy_healthy(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    stop(true);
    for _ in 0..40 {
        // ~2s backstop
        if !proxy_healthy(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!(
        "ZlauDeR: WARNING — proxy on :{port} (pid {pid}) did not exit; the new one may fail to bind."
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

#[cfg(test)]
mod conversation_tests {
    use super::{conversation_id_from_hook_payload, conversation_id_from_transcript_path};

    #[test]
    fn prefers_session_id_over_transcript_path() {
        let payload = r#"{
            "session_id": "abc-123",
            "transcript_path": "/home/u/.claude/projects/x/zzz-999.jsonl"
        }"#;
        assert_eq!(
            conversation_id_from_hook_payload(payload).as_deref(),
            Some("abc-123")
        );
    }

    #[test]
    fn falls_back_to_transcript_stem_not_full_path() {
        // No session id: the durable key is the transcript's file stem (the
        // embedded session uuid), NOT a slug of the whole absolute path.
        let payload = r#"{
            "transcript_path": "/home/user/.claude/projects/proj/9f8e-7d6c.jsonl"
        }"#;
        assert_eq!(
            conversation_id_from_hook_payload(payload).as_deref(),
            Some("9f8e-7d6c")
        );
    }

    #[test]
    fn camel_case_session_id_supported() {
        let payload = r#"{"sessionId": "sess_42"}"#;
        assert_eq!(
            conversation_id_from_hook_payload(payload).as_deref(),
            Some("sess_42")
        );
    }

    #[test]
    fn transcript_stem_handles_non_path_value() {
        // A bare value with no path separators round-trips through stem extraction.
        assert_eq!(
            conversation_id_from_transcript_path("just-an-id"),
            "just-an-id"
        );
    }

    #[test]
    fn no_identifier_yields_none() {
        assert_eq!(conversation_id_from_hook_payload(r#"{"foo": "bar"}"#), None);
        assert_eq!(conversation_id_from_hook_payload("not json"), None);
    }
}

#[cfg(test)]
mod statusline_tests {
    use super::{compose_line, pii_suffix, read_wrap_original, wrap_sidecar_path};

    #[test]
    fn compose_joins_segment_and_wrapped_with_divider() {
        assert_eq!(
            compose_line(Some("🛡 :18820 balanced".into()), Some("⎇ main".into())),
            "🛡 :18820 balanced \u{2502} ⎇ main"
        );
    }

    #[test]
    fn compose_drops_empty_or_absent_sides() {
        // Off-mode segment + a real wrapped line => just the wrapped line.
        assert_eq!(compose_line(None, Some("⎇ main".into())), "⎇ main");
        // A segment + a blank wrapped line => just the segment (no trailing divider).
        assert_eq!(
            compose_line(Some("🛡 off".into()), Some("   ".into())),
            "🛡 off"
        );
        assert_eq!(compose_line(Some("🛡 off".into()), None), "🛡 off");
        assert_eq!(compose_line(None, None), "");
    }

    #[test]
    fn pii_suffix_hides_zero() {
        assert_eq!(pii_suffix(0), "");
        assert_eq!(pii_suffix(7), " 7 PII");
    }

    #[test]
    fn read_wrap_original_extracts_command() {
        let dir = std::env::temp_dir().join(format!("zl-sl-{}", std::process::id()));
        let claude = dir.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let path = wrap_sidecar_path(&dir);

        std::fs::write(&path, r#"{"type":"command","command":"echo hi"}"#).unwrap();
        assert_eq!(read_wrap_original(&dir).as_deref(), Some("echo hi"));

        // A sidecar that somehow points back at a zlauder status line is ignored so the
        // wrapper can never recurse into itself.
        std::fs::write(
            &path,
            r#"{"type":"command","command":"/x/zlauder-hooks statusline"}"#,
        )
        .unwrap();
        assert_eq!(read_wrap_original(&dir), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_wrap_original_none_without_sidecar() {
        let dir = std::env::temp_dir().join(format!("zl-sl-absent-{}", std::process::id()));
        assert_eq!(read_wrap_original(&dir), None);
    }

    // The wrap timeout must bound the WORST case, including the pipe-deadlock shape:
    // a command that floods stdout (>64KB pipe buffer) before draining a >64KB stdin.
    // Writing stdin synchronously deadlocked here before the fix; the timeout fired
    // too late because the hang preceded the reader thread.
    #[cfg(unix)]
    #[test]
    fn run_wrapped_bounds_hangs_and_pipe_deadlock() {
        use super::run_wrapped;
        use std::time::{Duration, Instant};

        // 1. A command that never exits is cut off near the timeout, not hung forever.
        let t = Instant::now();
        assert_eq!(run_wrapped("sleep 30", b""), None);
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "hang not bounded: {:?}",
            t.elapsed()
        );

        // 2. The deadlock shape: child floods stdout before draining a 200KB stdin.
        //    With stdin forwarded on its own thread this completes instead of hanging.
        let big = vec![b'x'; 200_000];
        let t2 = Instant::now();
        let _ = run_wrapped("head -c 100000 /dev/zero | tr '\\0' A; cat >/dev/null", &big);
        assert!(
            t2.elapsed() < Duration::from_secs(5),
            "pipe deadlock not fixed: {:?}",
            t2.elapsed()
        );

        // 3. A normal small command still returns its trimmed output.
        assert_eq!(run_wrapped("printf hello", b"").as_deref(), Some("hello"));

        // 4. Closed/redirected stdout while still running: our reader hits EOF
        //    immediately, but the child keeps going. The success (Ok) path must NOT
        //    wait unbounded on child exit — it gives a short grace then kills the
        //    group. Before that fix this hung for the full `sleep 30`.
        let t4 = Instant::now();
        assert_eq!(run_wrapped("exec >/dev/null; sleep 30", b""), None);
        assert!(
            t4.elapsed() < Duration::from_secs(5),
            "closed-stdout child.wait hang: {:?}",
            t4.elapsed()
        );
    }
}

#[cfg(test)]
mod route_tests {
    use super::base_url_matches;

    #[test]
    fn matches_exact_and_trailing_slash() {
        let want = "http://127.0.0.1:18394";
        assert!(base_url_matches("http://127.0.0.1:18394", want));
        assert!(base_url_matches("http://127.0.0.1:18394/", want));
        assert!(base_url_matches(
            "http://127.0.0.1:18394",
            "http://127.0.0.1:18394/"
        ));
    }

    #[test]
    fn matches_base_with_path() {
        let want = "http://127.0.0.1:18394";
        assert!(base_url_matches("http://127.0.0.1:18394/v1", want));
    }

    #[test]
    fn rejects_other_endpoints() {
        let want = "http://127.0.0.1:18394";
        // Different port (another project's proxy, or an unrelated gateway).
        assert!(!base_url_matches("http://127.0.0.1:18395", want));
        // Real Anthropic API (not routed through us).
        assert!(!base_url_matches("https://api.anthropic.com", want));
        // A different host that merely shares the port number as a prefix substring.
        assert!(!base_url_matches("http://127.0.0.1:183940", want));
        assert!(!base_url_matches("", want));
    }
}
