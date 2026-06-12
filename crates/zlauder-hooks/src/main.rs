//! zlauder-hooks — Claude Code control-plane integration for zlauder.
//!
//! Subcommands:
//!   session-start  Launch this project's proxy (if not already running) and emit
//!                  the SessionStart hook JSON that points Claude Code at it. The proxy
//!                  binds an OS-assigned ephemeral port and publishes a per-project
//!                  rendezvous record consumers look up by project root.
//!   statusline     One-line status indicator (on/off + profile).
//!   config         View or change privacy settings (backs `/zlauder:privacy`).
//!   reveal <tok>   Audit: decode a token to its plaintext via the running proxy.
//!
//! Per-project routing (writing `ANTHROPIC_BASE_URL` + `ZLAUDER_PORT` and a status
//! line into `.claude/settings.local.json`, gitignored) is plumbed AUTOMATICALLY by
//! this binary's `session-start` the first time it sees a project (installed = routed),
//! and can also be (re)done explicitly via the plugin's `/zlauder:enable`. The plugin is
//! the sole install interface. See `zlauder-plugin/`.
//!
//! ## Per-project isolation
//!
//! Each project runs its own proxy on an OS-assigned ephemeral port; consumers find it
//! through a project-identity-keyed rendezvous record (see [`zlauder_state::live_port`]),
//! so its key, store, and config are isolated. Two `claude` windows in the same project
//! share the one proxy; different projects never interfere. The bound port is written into
//! each project's `.claude/settings.local.json` (as `ANTHROPIC_BASE_URL` + `ZLAUDER_PORT`)
//! by auto-plumb / `/zlauder:enable`, so the load-bearing path is the static base URL — not
//! a best-effort dynamic env.

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

mod transcript;

#[derive(Parser)]
#[command(name = "zlauder-hooks", version, about)]
struct Cli {
    /// Target proxy port. Defaults to `$ZLAUDER_PORT` (set per project by auto-plumb /
    /// `/zlauder:enable`), else the project's live proxy port resolved from its rendezvous record.
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
    /// Bring this project's proxy up (launch / recycle a stale build) and print the port it
    /// bound on stdout. Used by `/zlauder:enable` to learn the OS-assigned ephemeral port to
    /// write into settings.local.json. (Name retained for the shell contract; behaviorally a
    /// bare-port variant of `ensure-up`.)
    ReservePort {
        #[arg(long, env = "ZLAUDER_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = default_proxy_bin())]
        proxy_bin: String,
    },
    /// Ensure this project's proxy is running (launch or recycle a stale build) and, with
    /// `--print-url`, print its base URL. A standalone way to warm the proxy ahead of time,
    /// and the primitive a future zero-state launcher could exec Claude Code through (passing
    /// the URL via `--settings`, so no persistent settings write is needed).
    EnsureUp {
        #[arg(long, env = "ZLAUDER_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = default_proxy_bin())]
        proxy_bin: String,
        /// Print the proxy base URL on stdout (for the launcher's `--settings` injection).
        #[arg(long)]
        print_url: bool,
    },
    /// Preflight self-check: probe loopback reachability, localhost IPv4/IPv6, this project's
    /// proxy health, the state dir, and (Windows, static port) excluded ranges. Prints a
    /// pass/fail table (or `--json`) and exits non-zero on any FAIL. Backs `/zlauder:doctor`.
    Doctor {
        /// Emit machine-readable JSON instead of the human table.
        #[arg(long)]
        json: bool,
    },
    /// Verify this session is BOTH masking and routed (two distinct verdicts).
    Verify {
        /// Emit machine-readable JSON instead of the human table.
        #[arg(long)]
        json: bool,
    },
    /// UserPromptSubmit hook: the fail-CLOSED first-session intake gate. Blocks an unrouted
    /// (would-be UNMASKED) prompt until the route goes live, so the common first session can't
    /// silently direct-leak. Backs the plugin's user-prompt-submit.sh.
    UserPromptSubmit,
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
    /// Patch this project's .claude/settings.local.json (gitignored) to route through (or
    /// stop routing through) the zlauder proxy. Backs auto-plumb, `/zlauder:enable`, and
    /// `/zlauder:disable`, replacing the former shell+jq implementation so the plugin needs no `jq` on PATH
    /// (a hard blocker on Windows). Exit codes are a contract — see `SettingsAction`.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },
}

#[derive(Subcommand)]
enum SettingsAction {
    /// Wire env.ANTHROPIC_BASE_URL + env.ZLAUDER_PORT and take over the statusLine slot
    /// (wrapping any existing line to the sidecar). A missing settings.local.json is treated
    /// as `{}` (and created). Exit 0 = file changed (caller announces masking activates after a
    /// one-time restart — Claude Code reads a freshly-written route reliably only at startup);
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
    Disable {
        /// Sweep EVERY plumbed project (for a clean pre-uninstall), not just the current one:
        /// strip routing from each and clear its registry entry. Always exits 0 (the single-
        /// project exit-3 "already disabled" contract does not apply to a multi-project sweep).
        #[arg(long)]
        all: bool,
    },
    /// Print env.ANTHROPIC_BASE_URL from settings.local.json (the write target; else
    /// settings.json) — local-first, the EFFECTIVE route — or "(unset)". Replaces the
    /// optional jq one-liner in privacy.sh's status path. Exit 0.
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
        /// e.g. secrets, financial, identity, contact, network, personal.
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
    /// Set the operator for ONE entity type — finer-grained than a whole category.
    /// e.g. `entity URL off` (pass URLs through), `entity URL_CREDENTIAL redact`.
    Entity {
        /// Canonical entity type, e.g. URL, EMAIL_ADDRESS, URL_CREDENTIAL, US_SSN, IP_ADDRESS.
        name: String,
        /// on (mask with the default token) | off (pass through) | token | redact | hash |
        /// keep | mask | clear (remove the override; file scope only). `on`/`off` work
        /// regardless of the entity's category.
        op: String,
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
        Cmd::ReservePort { config, proxy_bin } => reserve_port_cmd(config, proxy_bin),
        Cmd::EnsureUp {
            config,
            proxy_bin,
            print_url,
        } => ensure_up_cmd(config, proxy_bin, print_url),
        Cmd::Doctor { json } => doctor(json),
        Cmd::Verify { json } => verify(json),
        Cmd::UserPromptSubmit => user_prompt_submit(),
        Cmd::Statusline => statusline(cli.port),
        Cmd::Config { action } => config_cmd(action),
        Cmd::PreToolUse => pre_tool_use(),
        Cmd::Reveal { token } => reveal(token),
        Cmd::Monitor => monitor_cmd(),
        Cmd::Secrets { action } => secrets_cmd(action),
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
// settings — patch .claude/settings.local.json (replaces the former shell+jq path)
// ---------------------------------------------------------------------------

/// Outcome of a settings mutation, mapped to the shell's exit-code contract:
/// `Changed` => exit 0 (caller announces the routing change takes effect after a one-time
/// restart of Claude Code), `NoOp` => exit 3 (caller prints "already pointed…"/
/// "already disabled…"). Hard errors bubble as `anyhow` (exit 1).
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
        } => {
            // Clear any prior opt-out FIRST and REQUIRE it to persist, THEN write the route — so a
            // SUCCESSFUL enable can never leave this project in (route baked + registry=Optout).
            // That preserves the invariant SessionStart's self-heal relies on: such a state can
            // then ONLY mean "a prior /zlauder:disable's strip didn't land" (safe to strip). If we
            // wrote the route first and the registry write then failed, the next session would
            // silently strip the route we just enabled — UNMASKING against the user's fresh intent.
            zlauder_state::registry_set(
                &canonical(&project_root()),
                zlauder_state::PlumbState::Plumbed,
            )?;
            settings_enable(&url, &zport, &statusline)?
        }
        SettingsAction::Disable { all } => {
            if all {
                // Multi-project sweep: no exit-3 contract, no per-project opt-out (entries are
                // removed). Returns Ok regardless of how many projects were swept.
                settings_disable_all()?;
                return Ok(());
            }
            let outcome = settings_disable()?;
            // Opt the project out so SessionStart never AUTO-re-plumbs it (a later explicit
            // /zlauder:enable clears the opt-out). Best-effort.
            let _ = zlauder_state::registry_set(
                &canonical(&project_root()),
                zlauder_state::PlumbState::Optout,
            );
            outcome
        }
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

// --- model-gating permission rules (F0: the Approval Kernel seal) -------------------
//
// ZlauDeR writes these into the project's settings.local.json on enable and removes them on
// disable. They constrain ONLY the model's own tool calls — the Claude Code harness runs
// hooks and `!`-prefixed slash-command bash OUTSIDE the permission system, so the plugin's
// own CLI keeps working while the model is denied the loosen path:
//   - deny the model's Bash on our CLIs (it must drive privacy via the slash commands);
//   - force an `ask` prompt on a model Edit/Write of zlauder.toml / zlauder.local.toml
//     (mode-independent — `ask` overrides acceptEdits AND bypassPermissions).
// Both the bare-name form (CLI on PATH) and an absolute/relative `*/zlauder-hooks` form, since
// the binary commonly lives off-PATH (`target/release/`, the plugin bin dir) and CC's Bash
// matcher keys on the command as written. This is best-effort defense-in-depth: a shell-capable
// model can still reach the proxy another way (e.g. read the 0600 key + curl), and CC prompts on
// shell redirection by default — the seal blocks the casual + prompt-injection paths, it is not
// a sandbox. The proxy only re-reads config on a key-gated reload or a restart, and the status
// line shows `⚠ OFF` if masking is ever disabled.
const DENY_RULES: &[&str] = &[
    "Bash(zlauder-hooks:*)",
    "Bash(zlauder-proxy:*)",
    "Bash(*/zlauder-hooks:*)",
    "Bash(*/zlauder-proxy:*)",
];
const ASK_RULES: &[&str] = &["Edit(/zlauder.toml)", "Edit(/zlauder.local.toml)"];

/// The `(permissions.<key>, our-rules)` pairs we own.
fn permission_rule_sets() -> [(&'static str, &'static [&'static str]); 2] {
    [("deny", DENY_RULES), ("ask", ASK_RULES)]
}

/// Merge our rules into `v["permissions"]`, appending only entries not already present
/// (dedup by exact string) so a user's own permissions are preserved. `v` must be an object.
/// Refuses (rather than clobbers) a malformed non-array `deny`/`ask` value — that is invalid
/// per Claude Code's schema, and overwriting it would destroy the user's content.
fn merge_permission_rules(v: &mut Value) -> Result<()> {
    let perms = ensure_object(v, "permissions");
    for (key, wanted) in permission_rule_sets() {
        let arr = perms.entry(key.to_string()).or_insert_with(|| json!([]));
        let a = arr.as_array_mut().ok_or_else(|| {
            anyhow::anyhow!(
                "settings.local.json permissions.{key} is not a JSON array; refusing to \
                 overwrite it. Fix it and re-run /zlauder:enable."
            )
        })?;
        for w in wanted {
            if !a.iter().any(|x| x.as_str() == Some(*w)) {
                a.push(Value::String((*w).to_string()));
            }
        }
    }
    Ok(())
}

/// Every one of our rules is already present (so a re-enable is a true NoOp).
fn permission_rules_present(v: &Value) -> bool {
    permission_rule_sets().iter().all(|(key, wanted)| {
        v.pointer(&format!("/permissions/{key}"))
            .and_then(Value::as_array)
            .map(|a| wanted.iter().all(|w| a.iter().any(|x| x.as_str() == Some(*w))))
            .unwrap_or(false)
    })
}

/// ANY of our rules is present (so disable still cleans a file carrying only our rules,
/// after the env/statusLine takeover was already removed by hand).
fn any_permission_rule_present(v: &Value) -> bool {
    permission_rule_sets().iter().any(|(key, wanted)| {
        v.pointer(&format!("/permissions/{key}"))
            .and_then(Value::as_array)
            .map(|a| wanted.iter().any(|w| a.iter().any(|x| x.as_str() == Some(*w))))
            .unwrap_or(false)
    })
}

/// Remove ONLY our rules from `v["permissions"]`, preserving any user entries; drop an array
/// that empties and the `permissions` object if it empties. Returns whether anything changed.
fn remove_permission_rules(v: &mut Value) -> bool {
    let mut changed = false;
    let mut perms_empty = false;
    if let Some(perms) = v.get_mut("permissions").and_then(Value::as_object_mut) {
        for (key, ours) in permission_rule_sets() {
            if let Some(arr) = perms.get_mut(key).and_then(Value::as_array_mut) {
                let before = arr.len();
                arr.retain(|x| !ours.iter().any(|o| x.as_str() == Some(*o)));
                changed |= arr.len() != before;
                if arr.is_empty() {
                    perms.remove(key);
                }
            }
        }
        perms_empty = perms.is_empty();
    }
    if perms_empty
        && let Some(root) = v.as_object_mut()
    {
        root.remove("permissions");
    }
    changed
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

/// The status-line command zlauder bakes into settings: an ABSOLUTE path to THIS binary's
/// dir so it resolves in the user's bare shell (which won't have the plugin bin dir on
/// PATH). Mirrors enable.sh's format — single-quote only the dir so an install path with
/// spaces survives Claude Code's argv splitting, and keep `<exe> statusline` contiguous and
/// preceded by `/` for the `is_zlauder_statusline` ownership check. Used by SessionStart
/// auto-plumb; the explicit /zlauder:enable path computes its own from the resolved bin dir.
fn statusline_command() -> String {
    match std::env::current_exe().ok().and_then(|p| {
        Some((
            p.parent()?.to_string_lossy().into_owned(),
            p.file_name()?.to_string_lossy().into_owned(),
        ))
    }) {
        Some((dir, name)) => format!("'{dir}'/{name} statusline"),
        None => "zlauder-hooks statusline".to_string(),
    }
}

fn settings_enable(url: &str, zport: &str, statusline: &str) -> Result<SettingsOutcome> {
    let proj = project_root();
    let settings_dir = proj.join(".claude");
    std::fs::create_dir_all(&settings_dir)
        .with_context(|| format!("creating {}", settings_dir.display()))?;
    // ENFORCE the "never committed" property the docs promise rather than trust an external
    // convention: write a `.claude/.gitignore` so the per-machine loopback route in
    // settings.local.json can't be `git add`-ed and strand a teammate on a dead pointer.
    ensure_local_gitignored(&settings_dir);
    // Route via settings.local.json (gitignored), NOT settings.json (committed): a baked
    // `http://127.0.0.1:<ephemeral-port>` is machine/path-specific, so committing it would
    // strand a teammate who pulls the repo on a dead pointer (the ~3-minute ConnectionRefused
    // hang). settings.local.json is loaded for routing exactly like settings.json but never
    // travels.
    let local_file = settings_dir.join("settings.local.json");
    let committed_file = settings_dir.join("settings.json");
    let sidecar = wrap_sidecar_path(&proj);

    let local_v = load_settings_or_empty(&local_file)?;
    if !local_v.is_object() {
        bail!(
            "{} is not a JSON object; refusing to overwrite. Fix it and re-run.",
            local_file.display()
        );
    }
    // The line we wrap (the user's ORIGINAL status line) is the highest-precedence NON-OURS
    // statusLine across the two files (local overrides committed, matching Claude Code).
    // Resolve it from the pre-migration state so an old committed install's line isn't lost.
    let committed_v = load_settings_or_empty(&committed_file)?;
    let original_line = effective_user_statusline(&local_v, &committed_v);

    // Idempotency: is THIS project (local) ALREADY pointed at this exact proxy (url + port)?
    let cur_url = local_v
        .pointer("/env/ANTHROPIC_BASE_URL")
        .and_then(Value::as_str)
        .unwrap_or("");
    let cur_port = local_v
        .pointer("/env/ZLAUDER_PORT")
        .and_then(Value::as_str)
        .unwrap_or("");
    // NoOp only when the route AND the model-gating permission rules are already present;
    // a route-present-but-rules-missing install (e.g. pre-F0) is an upgrade → Changed.
    let already =
        base_url_matches(cur_url, url) && cur_port == zport && permission_rules_present(&local_v);

    // Status-line takeover: snapshot the user's original line to the sidecar that
    // /zlauder:disable restores from. NEVER delete the sidecar here — an OLD install routed
    // via committed settings.json keeps its original ONLY in the sidecar (the new write
    // target, local, is empty), so deleting it would lose the user's line on disable. When
    // there is no original to wrap we leave the (absent) sidecar alone; a re-enable whose
    // effective line is already ours returns `None` and keeps the existing sidecar intact.
    if let Some(orig) = &original_line {
        let compact = serde_json::to_string(orig)?;
        std::fs::write(&sidecar, format!("{compact}\n"))
            .with_context(|| format!("writing {}", sidecar.display()))?;
        // Diagnostics go to STDERR: settings_enable is also called from the SessionStart hook
        // (auto-plumb), whose STDOUT must be only the hook JSON. The CLI doesn't capture
        // stdout, so the user still sees these on stderr.
        eprintln!(
            "ZlauDeR: wrapping your existing status line (saved to {}; restored on /zlauder:disable).",
            sidecar.display()
        );
    }

    // Migrate an OLD install that baked routing/our status line into the COMMITTED
    // settings.json: strip OUR env wiring + OUR status line out of it so there is exactly
    // ONE takeover (in local) and the committed file is never the viral dead-pointer. Pass
    // `None` so migration only REMOVES our keys — it never restores into committed; the
    // original is preserved in the sidecar and restored into local by /zlauder:disable.
    if strip_routing_from(&committed_file, None)?.0 {
        // STDERR (see note above): keeps the SessionStart hook's stdout pure JSON.
        eprintln!(
            "ZlauDeR: migrated routing out of {} into {} (no longer committed).",
            committed_file.display(),
            local_file.display()
        );
    }

    // Set the routing env (always) and take over the status-line slot (always) in local.
    let mut v = local_v;
    let env = ensure_object(&mut v, "env");
    env.insert(
        "ANTHROPIC_BASE_URL".to_string(),
        Value::String(url.to_string()),
    );
    env.insert("ZLAUDER_PORT".to_string(), Value::String(zport.to_string()));
    v["statusLine"] = json!({ "type": "command", "command": statusline });
    // Seal the Approval Kernel: deny the model's Bash on our CLIs + force an `ask` on its
    // edits of zlauder.toml/zlauder.local.toml. Merge (never clobber) the user's own rules.
    merge_permission_rules(&mut v)?;

    atomic_write_json(&local_file, &v)?;
    Ok(if already {
        SettingsOutcome::NoOp
    } else {
        SettingsOutcome::Changed
    })
}

/// Best-effort: ensure git won't track the machine-local files this binary writes into
/// `.claude/` — `settings.local.json` (which holds the per-machine loopback
/// `ANTHROPIC_BASE_URL`) and the `zlauder-statusline.json` sidecar. We write a
/// `.claude/.gitignore` so the route can't be `git add`-ed into version control and strand a
/// teammate on a dead pointer. Idempotent (only appends entries that are missing; never
/// clobbers existing `.gitignore` content) and non-fatal — routing works regardless, so a
/// failure here only warns on stderr.
fn ensure_local_gitignored(settings_dir: &Path) {
    let gitignore = settings_dir.join(".gitignore");
    let wanted = ["settings.local.json", "zlauder-statusline.json"];
    let existing = match std::fs::read_to_string(&gitignore) {
        Ok(s) => s,
        // No file yet → start empty and create it below.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        // The file EXISTS but we can't read it as text (non-UTF-8, perms, a directory, …).
        // Treating it as empty would clobber the user's real .gitignore on the write below, so
        // bail instead — best-effort, warn on stderr only.
        Err(e) => {
            eprintln!(
                "ZlauDeR: could not read {} to confirm settings.local.json is ignored: {e}. \
                 Ensure `.claude/settings.local.json` is gitignored so the per-machine proxy \
                 URL isn't committed.",
                gitignore.display()
            );
            return;
        }
    };
    let present: std::collections::HashSet<&str> = existing.lines().map(str::trim).collect();
    let missing: Vec<&str> = wanted
        .iter()
        .copied()
        .filter(|e| !present.contains(e))
        .collect();
    if missing.is_empty() {
        return;
    }
    let mut out = existing;
    if out.is_empty() {
        out.push_str(
            "# ZlauDeR machine-local routing/state — never commit (per-machine proxy URL)\n",
        );
    } else if !out.ends_with('\n') {
        out.push('\n');
    }
    for e in &missing {
        out.push_str(e);
        out.push('\n');
    }
    if let Err(e) = std::fs::write(&gitignore, out) {
        eprintln!(
            "ZlauDeR: could not write {} to ignore settings.local.json: {e}. Add \
             `.claude/settings.local.json` to your .gitignore so the per-machine proxy URL \
             isn't committed.",
            gitignore.display()
        );
    }
}

#[cfg(test)]
mod gitignore_tests {
    use super::ensure_local_gitignored;

    #[test]
    fn writes_idempotently_and_preserves_user_content() {
        let dir = std::env::temp_dir().join(format!("zl-gi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gi = dir.join(".gitignore");

        // 1. Fresh dir (no .gitignore): creates it, ignoring both machine-local files.
        ensure_local_gitignored(&dir);
        let c1 = std::fs::read_to_string(&gi).unwrap();
        assert!(c1.lines().any(|l| l.trim() == "settings.local.json"), "{c1:?}");
        assert!(c1.lines().any(|l| l.trim() == "zlauder-statusline.json"), "{c1:?}");

        // 2. Idempotent: a second call is a byte-for-byte no-op (no duplicate entries).
        ensure_local_gitignored(&dir);
        let c2 = std::fs::read_to_string(&gi).unwrap();
        assert_eq!(c1, c2, "second call must not change the file");
        assert_eq!(c2.matches("settings.local.json").count(), 1);

        // 3. Pre-existing user content is preserved; only the missing entry is appended.
        std::fs::write(&gi, "node_modules\nsettings.local.json\n").unwrap();
        ensure_local_gitignored(&dir);
        let c3 = std::fs::read_to_string(&gi).unwrap();
        assert!(c3.starts_with("node_modules\n"), "{c3:?}");
        assert_eq!(c3.matches("settings.local.json").count(), 1, "no dup: {c3:?}");
        assert!(c3.lines().any(|l| l.trim() == "zlauder-statusline.json"), "{c3:?}");

        // 4. Existing content WITHOUT a trailing newline gets a separator, not concatenation.
        std::fs::write(&gi, "node_modules").unwrap();
        ensure_local_gitignored(&dir);
        let c4 = std::fs::read_to_string(&gi).unwrap();
        assert!(c4.starts_with("node_modules\n"), "must not append onto the last line: {c4:?}");
        assert!(c4.lines().any(|l| l.trim() == "settings.local.json"), "{c4:?}");

        // 5. A .gitignore we can't read as UTF-8 is NEVER clobbered (read-failure ≠ empty).
        let raw: &[u8] = b"node_modules\n\xff\xfe settings.local.json not-utf8\n";
        std::fs::write(&gi, raw).unwrap();
        ensure_local_gitignored(&dir);
        assert_eq!(
            std::fs::read(&gi).unwrap(),
            raw,
            "must not overwrite a .gitignore that failed to read"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod permission_rule_tests {
    use super::{
        ASK_RULES, DENY_RULES, any_permission_rule_present, merge_permission_rules,
        permission_rules_present, remove_permission_rules,
    };
    use serde_json::{Value, json};

    fn arr(v: &Value, key: &str) -> Vec<String> {
        v.pointer(&format!("/permissions/{key}"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }
    fn want(rules: &[&str]) -> Vec<String> {
        rules.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn merge_writes_both_rule_sets_into_empty_object() {
        let mut v = json!({});
        merge_permission_rules(&mut v).unwrap();
        assert_eq!(arr(&v, "deny"), want(DENY_RULES));
        assert_eq!(arr(&v, "ask"), want(ASK_RULES));
        assert!(permission_rules_present(&v));
        assert!(any_permission_rule_present(&v));
    }

    #[test]
    fn merge_preserves_user_entries_and_is_idempotent() {
        let mut v = json!({ "permissions": { "deny": ["Bash(rm:*)"], "allow": ["Read(*)"] } });
        merge_permission_rules(&mut v).unwrap();
        merge_permission_rules(&mut v).unwrap(); // re-run must not duplicate
        let deny = arr(&v, "deny");
        assert!(deny.contains(&"Bash(rm:*)".to_string()), "user entry kept: {deny:?}");
        for r in DENY_RULES {
            assert_eq!(
                deny.iter().filter(|x| x.as_str() == *r).count(),
                1,
                "no dup of {r}: {deny:?}"
            );
        }
        assert_eq!(arr(&v, "ask"), want(ASK_RULES));
        // An unrelated permissions key is untouched.
        assert_eq!(arr(&v, "allow"), want(&["Read(*)"]));
    }

    #[test]
    fn remove_strips_only_ours_and_drops_emptied_containers() {
        let mut v = json!({});
        merge_permission_rules(&mut v).unwrap();
        assert!(remove_permission_rules(&mut v));
        // Both arrays were exactly ours → emptied → dropped → permissions object dropped.
        assert!(v.get("permissions").is_none(), "empty permissions dropped: {v}");
        assert!(!any_permission_rule_present(&v));
    }

    #[test]
    fn remove_preserves_user_entries() {
        let mut v = json!({ "permissions": { "deny": ["Bash(rm:*)"], "allow": ["Read(*)"] } });
        merge_permission_rules(&mut v).unwrap();
        remove_permission_rules(&mut v);
        assert_eq!(arr(&v, "deny"), want(&["Bash(rm:*)"]), "our deny gone, user's kept");
        assert_eq!(arr(&v, "allow"), want(&["Read(*)"]));
        assert!(v.pointer("/permissions/ask").is_none(), "ask was all ours → dropped: {v}");
    }

    #[test]
    fn enable_then_disable_round_trips() {
        let original = json!({ "permissions": { "deny": ["Bash(rm:*)"] }, "env": { "FOO": "bar" } });
        let mut v = original.clone();
        merge_permission_rules(&mut v).unwrap();
        remove_permission_rules(&mut v);
        assert_eq!(v, original, "merge + remove must restore the original exactly");
    }

    #[test]
    fn partial_rules_are_not_present_the_upgrade_signal() {
        // A pre-F0 install: route present but only some/zero of our rules.
        let mut v = json!({ "permissions": { "deny": DENY_RULES } }); // ask missing
        assert!(!permission_rules_present(&v), "missing ask ⇒ not fully present (⇒ Changed)");
        assert!(any_permission_rule_present(&v));
        merge_permission_rules(&mut v).unwrap();
        assert!(permission_rules_present(&v));
    }

    #[test]
    fn merge_refuses_a_non_array_permission_field() {
        // A malformed (schema-invalid) permissions.deny must be REFUSED, never clobbered.
        let mut v = json!({ "permissions": { "deny": "oops-not-an-array" } });
        assert!(merge_permission_rules(&mut v).is_err(), "must refuse: {v}");
        assert_eq!(
            v.pointer("/permissions/deny").and_then(Value::as_str),
            Some("oops-not-an-array"),
            "the user's value must be left intact"
        );
    }
}

/// The user's ORIGINAL status line: the highest-precedence NON-zlauder `statusLine` across
/// local (which wins) then committed, or `None` if the effective current line is already
/// OUR takeover (its original lives in the sidecar) or neither file has a line. Used by
/// enable to decide what to snapshot for /zlauder:disable to restore.
fn effective_user_statusline(local_v: &Value, committed_v: &Value) -> Option<Value> {
    for v in [local_v, committed_v] {
        let cmd = v
            .pointer("/statusLine/command")
            .and_then(Value::as_str)
            .unwrap_or("");
        if is_zlauder_statusline(cmd) {
            // Highest-precedence present line is already OUR takeover — the original is in
            // the sidecar, not here. A lower-precedence file can't be the effective line.
            return None;
        }
        if let Some(orig) = v.get("statusLine").filter(|o| !o.is_null()) {
            return Some(orig.clone());
        }
    }
    None
}

fn settings_disable() -> Result<SettingsOutcome> {
    settings_disable_at(&project_root())
}

/// Sweep EVERY plumbed project (for a clean pre-uninstall): strip routing from each project's
/// settings and drop its registry entry, so removing the plugin can't leave a stale
/// `ANTHROPIC_BASE_URL` pointing at a dead proxy in any project (the ~3-min ConnectionRefused
/// hang). Prints a per-project summary; never uses the single-project exit-3 contract.
fn settings_disable_all() -> Result<()> {
    // The post-2b7fc96 registry is the primary record of plumbed projects, but it can MISS a
    // route: one baked by an older build (pre-registry), or whose entry was lost to a partial
    // failure. So ALSO scan Claude Code's session logs for project roots and union them in —
    // but strip ONLY a discovered root that ACTUALLY carries our route (project_baked_route),
    // so a non-zlauder project surfaced by the scan is never touched. Registry roots are swept
    // unconditionally (settings_disable_at is an idempotent no-op when the route is already
    // gone, and registry_remove then clears the stale entry).
    let mut roots = zlauder_state::registry_plumbed_roots();
    let mut seen: std::collections::HashSet<String> = roots.iter().cloned().collect();
    for r in discover_session_cwds() {
        if !seen.contains(&r) && project_baked_route(&r).is_some() {
            seen.insert(r.clone());
            roots.push(r);
        }
    }
    if roots.is_empty() {
        println!("ZlauDeR: no plumbed projects to disable — nothing to sweep.");
        return Ok(());
    }
    let mut done = 0usize;
    for root in &roots {
        match settings_disable_at(Path::new(root)) {
            Ok(_) => {
                // Drop the registry entry entirely (not Optout): the plugin is being removed,
                // so there is nothing left to auto-re-plumb against.
                let _ = zlauder_state::registry_remove(root);
                done += 1;
                println!("ZlauDeR: removed routing from {root}");
            }
            Err(e) => {
                eprintln!("ZlauDeR: could not disable {root}: {e} — left as-is.");
            }
        }
    }
    let failed = roots.len() - done;
    if failed == 0 {
        println!(
            "ZlauDeR: swept all {done} plumbed project(s). Routing removed — you can uninstall \
             the plugin safely now."
        );
    } else {
        println!(
            "ZlauDeR: swept {done}/{} plumbed project(s); {failed} could NOT be cleaned (see the \
             warnings above). Do NOT uninstall yet — re-run /zlauder:disable --all (or remove the \
             routing by hand) so no project is left pointing at a dead proxy.",
            roots.len()
        );
    }
    Ok(())
}

/// Claude Code's per-user data dir (`$CLAUDE_CONFIG_DIR`, else `$HOME/.claude`). Its
/// `projects/<encoded-root>/*.jsonl` session logs each carry the project's real `cwd`.
fn claude_config_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Some(PathBuf::from(d));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude"))
}

/// Best-effort discovery of project roots from Claude Code's session logs, for the `--all`
/// sweep to catch routes the registry doesn't list. The `projects/<encoded>` dir NAME is lossy
/// (both `/` and `.` map to `-`), so we read the EXACT `cwd` out of a `*.jsonl` instead. Never
/// fails the sweep: an unreadable/absent projects dir just yields an empty list (registry-only).
fn discover_session_cwds() -> Vec<String> {
    let Some(projects) = claude_config_dir().map(|d| d.join("projects")) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&projects) else {
        return Vec::new();
    };
    let mut roots = std::collections::BTreeSet::new();
    for dir in entries.filter_map(|e| e.ok()).map(|e| e.path()) {
        if !dir.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        // One session log with a cwd is enough — every log in a project dir shares the same one.
        for f in files.filter_map(|e| e.ok()).map(|e| e.path()) {
            if f.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            if let Some(cwd) = first_cwd_in_jsonl(&f) {
                roots.insert(canonical(Path::new(&cwd)));
                break;
            }
        }
    }
    roots.into_iter().collect()
}

/// Pull the first top-level `cwd` out of a JSONL session log. Each scanned line is parsed as
/// JSON (robust to whitespace around the colon, escaped characters in the path, and a stray
/// `cwd`-looking substring inside some other field — a raw substring scan got all three wrong).
/// Per-line reads are byte-capped so a pathological multi-hundred-MB single record can't blow up
/// the teardown sweep, and ONLY a line that actually ended in `\n` is parsed — a capped-or-EOF
/// partial line is skipped, never parsed, so a truncated record can never yield a wrong `cwd`.
/// The real `cwd` appears in the first session records, well within the line budget.
fn first_cwd_in_jsonl(path: &Path) -> Option<String> {
    use std::io::{BufRead, BufReader, Read};
    const MAX_LINE: u64 = 256 * 1024;
    let file = std::fs::File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    for _ in 0..200 {
        let mut buf = Vec::new();
        // Read at most MAX_LINE bytes of the next line: bounds memory on a giant record.
        let n = match (&mut reader).take(MAX_LINE).read_until(b'\n', &mut buf) {
            Ok(0) => break,                          // EOF
            Ok(n) => n,
            Err(_) => break,
        };
        // A buffer with no trailing '\n' that ALSO filled the cap (`n >= MAX_LINE`) is the HEAD of
        // a record longer than the cap: drain the rest of it (O(1) memory) so the next iteration
        // resumes at a true record boundary, never parsing a mid-record fragment. A short read
        // without a newline (`n < MAX_LINE`) instead means EOF — a final record the writer left
        // unterminated — which IS complete and should be parsed.
        if buf.last() != Some(&b'\n') && n as u64 >= MAX_LINE {
            if !drain_to_newline(&mut reader) {
                break; // EOF reached while draining ⇒ no further complete record
            }
            continue;
        }
        if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&buf)
            && let Some(cwd) = map.get("cwd").and_then(Value::as_str)
            && !cwd.is_empty()
        {
            return Some(cwd.to_string());
        }
    }
    None
}

/// Consume and DISCARD bytes from `reader` up to and including the next `\n`, reading straight
/// from the `BufRead` buffer (no growing allocation) so a multi-hundred-MB record is drained in
/// O(1) extra memory. Returns false if EOF is hit before any newline (no further whole record).
fn drain_to_newline<R: std::io::BufRead>(reader: &mut R) -> bool {
    loop {
        let (found, used) = match reader.fill_buf() {
            Ok(b) if b.is_empty() => return false, // EOF
            Ok(b) => match b.iter().position(|&c| c == b'\n') {
                Some(i) => (true, i + 1),
                None => (false, b.len()),
            },
            Err(_) => return false,
        };
        reader.consume(used);
        if found {
            return true;
        }
    }
}

/// Strip zlauder routing from one project's settings (both `settings.local.json` and the
/// committed `settings.json`) and restore any wrapped status line. The single-project
/// `/zlauder:disable` (current dir) and the `--all` sweep both go through here.
fn settings_disable_at(proj: &Path) -> Result<SettingsOutcome> {
    let sidecar = wrap_sidecar_path(proj);

    // The original status line to restore (if enable wrapped one). `None` => just drop ours.
    let mut restore: Option<Value> = std::fs::read_to_string(&sidecar)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(strip_bom(&t)).ok());

    // Strip our wiring from BOTH the local (current write target) and the committed
    // settings.json (older versions wrote there) so disable is a true inverse no matter
    // where the routing landed. The saved original is restored into the FIRST (highest-
    // precedence) file that still holds OUR status line, then CONSUMED — so it is never
    // written into both files (a hand-set line, and the file we already restored, are left
    // alone on the second pass).
    let mut changed = false;
    for name in ["settings.local.json", "settings.json"] {
        let (did, restored_here) =
            strip_routing_from(&proj.join(".claude").join(name), restore.as_ref())?;
        changed |= did;
        if restored_here {
            restore = None;
        }
    }

    if !changed {
        return Ok(SettingsOutcome::NoOp);
    }
    let _ = std::fs::remove_file(&sidecar);
    Ok(SettingsOutcome::Changed)
}

/// Remove zlauder's routing env (and our status-line takeover) from one settings file.
/// Returns `(changed, restored)`: `changed` is true iff the file existed and carried wiring
/// we removed; `restored` is true iff we wrote `restore` back into this file's status-line
/// slot (so the caller can consume the original and not write it twice). A missing file, or
/// one with no zlauder wiring, is a no-op (`(false, false)`). The original status line is
/// restored from `restore` only when this file's current line is OURS; `None` drops ours.
/// A hand-set line is left untouched.
fn strip_routing_from(settings_file: &Path, restore: Option<&Value>) -> Result<(bool, bool)> {
    let text = match std::fs::read_to_string(settings_file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((false, false)),
        Err(e) => return Err(e).with_context(|| format!("reading {}", settings_file.display())),
    };
    let mut v: Value = serde_json::from_str(strip_bom(&text)).with_context(|| {
        format!(
            "{} is not valid JSON; refusing to edit. Fix it and re-run.",
            settings_file.display()
        )
    })?;

    // Ownership matters: `ZLAUDER_PORT` is OUR private co-key (no user sets it), so it is
    // always ours to remove. `ANTHROPIC_BASE_URL`, however, may be the USER's own (e.g. a
    // corporate gateway) — we only remove it when its VALUE is provably ours (a loopback URL
    // whose port matches our co-baked `ZLAUDER_PORT`). This keeps disable/migration from deleting a user's own
    // base URL that was merely shadowed by our local route. We still trigger on ANY of our
    // wiring (ours-env or our status line) so disable is a true inverse in asymmetric state.
    // The co-baked ZLAUDER_PORT identifies OUR (ephemeral) loopback URL even though its port
    // isn't derivable. Tolerate a string or numeric JSON value.
    let baked_zport = v
        .pointer("/env/ZLAUDER_PORT")
        .and_then(|z| {
            z.as_str()
                .and_then(|s| s.parse::<u16>().ok())
                .or_else(|| z.as_u64().and_then(|n| u16::try_from(n).ok()))
        });
    let abu_is_ours = v
        .pointer("/env/ANTHROPIC_BASE_URL")
        .and_then(Value::as_str)
        .map(|u| is_zlauder_base_url(u, baked_zport))
        .unwrap_or(false);
    let zport_present = v.pointer("/env/ZLAUDER_PORT").is_some();
    let has_env_wiring = abu_is_ours || zport_present;
    let sl_is_ours = is_zlauder_statusline(
        v.pointer("/statusLine/command")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    // Also trigger when only our permission rules remain (env/statusLine hand-removed) so
    // disable stays a true inverse and never leaves the model-gating rules orphaned.
    let has_perms_wiring = any_permission_rule_present(&v);
    if !has_env_wiring && !sl_is_ours && !has_perms_wiring {
        return Ok((false, false));
    }

    // Delete only OUR env keys (and the env object if it ends up empty). A user's own
    // non-loopback ANTHROPIC_BASE_URL is left untouched.
    if let Some(env) = v.get_mut("env").and_then(Value::as_object_mut) {
        env.remove("ZLAUDER_PORT");
        if abu_is_ours {
            env.remove("ANTHROPIC_BASE_URL");
        }
        if env.is_empty()
            && let Some(root) = v.as_object_mut()
        {
            root.remove("env");
        }
    }
    // Undo the status-line takeover only when the current line is still OURS — a line the
    // user set by hand after enabling is left alone.
    let mut restored = false;
    if sl_is_ours {
        match restore {
            Some(orig) => {
                v["statusLine"] = orig.clone();
                restored = true;
            }
            None => {
                if let Some(root) = v.as_object_mut() {
                    root.remove("statusLine");
                }
            }
        }
    }

    // Strip our model-gating permission rules too (preserving any user permissions), so
    // disable is a true inverse of enable's merge.
    remove_permission_rules(&mut v);

    atomic_write_json(settings_file, &v)?;
    Ok((true, restored))
}

/// Is `url` a base URL WE would have written — a path-less loopback authority whose port
/// matches the co-baked `ZLAUDER_PORT` (`co_key`)? Lets migration/disable tell OUR
/// `ANTHROPIC_BASE_URL` apart from a user's own (a corporate gateway, a different local
/// proxy), so we never delete an env var that isn't ours. The port is OS-assigned (not
/// derivable), so the co-baked `ZLAUDER_PORT` is the only durable ownership signal.
fn is_zlauder_base_url(url: &str, co_key: Option<u16>) -> bool {
    let Some(authority) = url.trim().trim_end_matches('/').strip_prefix("http://") else {
        return false;
    };
    // Reject any path/query (a real proxy URL we bake into settings.json is a bare
    // host:port; a user URL with a path is theirs).
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    if (host != "127.0.0.1" && host != "localhost") || port.contains('/') {
        return false;
    }
    let Ok(p) = port.parse::<u16>() else {
        return false;
    };
    // Ours iff the loopback port matches the co-baked ZLAUDER_PORT. A bare loopback URL that
    // doesn't match is a user's own (a corporate gateway, a different local proxy) and is
    // left untouched.
    co_key == Some(p)
}

#[cfg(test)]
mod base_url_ownership_tests {
    use super::is_zlauder_base_url;

    #[test]
    fn ours_is_ephemeral_loopback_matching_co_key() {
        // An OS-assigned ephemeral port is ours ONLY when it matches the co-baked ZLAUDER_PORT.
        assert!(is_zlauder_base_url("http://127.0.0.1:41234", Some(41234)));
        assert!(is_zlauder_base_url("http://localhost:53999/", Some(53999)));
        // Same ephemeral URL but a MISMATCHED / absent co-key is NOT claimed as ours.
        assert!(!is_zlauder_base_url("http://127.0.0.1:41234", Some(40000)));
        assert!(!is_zlauder_base_url("http://127.0.0.1:41234", None));
    }

    #[test]
    fn not_ours_user_gateway_or_mismatched_port() {
        // A user's own base URL must NOT be claimed as ours (else disable/migration would
        // delete their committed env var) -- even with a stale co-key present.
        assert!(!is_zlauder_base_url("http://nothost:5000", Some(41234))); // non-loopback host
        assert!(!is_zlauder_base_url("http://127.0.0.1:4000", None)); // user's local proxy, no co-key
        assert!(!is_zlauder_base_url("http://127.0.0.1:18123/v1", Some(18123))); // has a path -> theirs
        assert!(!is_zlauder_base_url("http://127.0.0.1", None)); // no port
        // A loopback port that doesn't match the co-key is not ours.
        assert!(!is_zlauder_base_url("http://127.0.0.1:18123", Some(41234)));
    }
}

/// Print env.ANTHROPIC_BASE_URL from settings.local.json (the write target; else
/// settings.json), or "(unset)". Reads local-first so it reports the EFFECTIVE route
/// (local overrides committed in Claude Code), never a stale committed URL. Same precedence
/// as `project_configures`. Replaces privacy.sh's optional jq one-liner.
fn print_route_url() {
    let proj = project_root();
    for name in [".claude/settings.local.json", ".claude/settings.json"] {
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
// doctor — preflight self-check (/zlauder:doctor)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ProbeStatus {
    Pass,
    Warn,
    Fail,
    Skip,
    Info,
}

impl ProbeStatus {
    fn label(self) -> &'static str {
        match self {
            ProbeStatus::Pass => "PASS",
            ProbeStatus::Warn => "WARN",
            ProbeStatus::Fail => "FAIL",
            ProbeStatus::Skip => "SKIP",
            ProbeStatus::Info => "INFO",
        }
    }
}

struct Probe {
    name: &'static str,
    status: ProbeStatus,
    detail: String,
    remediation: Option<String>,
}

fn probe(name: &'static str, status: ProbeStatus, detail: String, remediation: Option<&str>) -> Probe {
    Probe {
        name,
        status,
        detail,
        remediation: remediation.map(str::to_string),
    }
}

/// `/zlauder:doctor`: run the preflight probes, print a table (or `--json`), exit non-zero on
/// any FAIL. Catches the firewall/loopback/port footguns the masking flow depends on.
fn doctor(json: bool) -> Result<()> {
    let root = canonical(&project_root());
    let probes = vec![
        probe_loopback_self_connect(),
        probe_localhost_resolution(),
        probe_ephemeral_bind(),
        probe_state_dir(),
        probe_project_proxy(&root),
        probe_windows_excluded_range(),
    ];
    let any_fail = probes.iter().any(|p| p.status == ProbeStatus::Fail);

    if json {
        let arr: Vec<Value> = probes
            .iter()
            .map(|p| {
                json!({
                    "name": p.name,
                    "status": p.status.label(),
                    "detail": p.detail,
                    "remediation": p.remediation,
                })
            })
            .collect();
        println!("{}", json!({ "ok": !any_fail, "probes": arr }));
    } else {
        println!(
            "ZlauDeR doctor — {}",
            if any_fail {
                "PROBLEMS FOUND"
            } else {
                "all checks passed"
            }
        );
        for p in &probes {
            println!("  [{}] {} — {}", p.status.label(), p.name, p.detail);
        }
        for p in probes
            .iter()
            .filter(|p| matches!(p.status, ProbeStatus::Fail | ProbeStatus::Warn))
        {
            if let Some(r) = &p.remediation {
                println!("        → {r}");
            }
        }
    }
    if any_fail {
        std::process::exit(1);
    }
    Ok(())
}

/// `/zlauder:verify` — proves THIS session both MASKS and ROUTES, as two DISTINCT verdicts.
/// A green engine is NOT a routed session: Leg 1 (engine masks) is a key-gated canary echo via
/// /zlauder/diag/mask; Leg 2 (session routed) is whether $ANTHROPIC_BASE_URL points at this
/// project's proxy. A green engine + red session reads ✗ overall — the exact bug verify exists
/// to surface (masking is on, but this session bypasses it and sends UNMASKED).
fn verify(json: bool) -> Result<()> {
    let root = canonical(&project_root());
    let legs = vec![verify_engine_masks(&root), verify_session_routed(&root)];
    let any_fail = legs.iter().any(|p| p.status == ProbeStatus::Fail);
    if json {
        let arr: Vec<Value> = legs
            .iter()
            .map(|p| {
                json!({
                    "name": p.name,
                    "status": p.status.label(),
                    "detail": p.detail,
                    "remediation": p.remediation,
                })
            })
            .collect();
        println!("{}", json!({ "ok": !any_fail, "legs": arr }));
    } else {
        println!(
            "ZlauDeR verify — {}",
            if any_fail {
                "NOT fully active"
            } else {
                "active (masking ON + this session routed)"
            }
        );
        for p in &legs {
            println!("  [{}] {} — {}", p.status.label(), p.name, p.detail);
        }
        for p in legs
            .iter()
            .filter(|p| matches!(p.status, ProbeStatus::Fail | ProbeStatus::Warn))
        {
            if let Some(r) = &p.remediation {
                println!("        → {r}");
            }
        }
    }
    if any_fail {
        std::process::exit(1);
    }
    Ok(())
}

/// Verify Leg 1: does the proxy actually MASK? A key-gated /zlauder/diag/mask canary echo —
/// distinct from "is this session routed" (Leg 2).
fn verify_engine_masks(root: &str) -> Probe {
    let name = "engine masks (key-gated canary)";
    let (port, key) = match (resolve_live_port(root), key_for(root)) {
        (Ok(p), Ok(k)) => (p, k),
        _ => {
            return probe(
                name,
                ProbeStatus::Fail,
                "proxy not reachable — cannot run the masking canary".to_string(),
                Some("open a session in this project (it auto-starts the proxy), or /zlauder:doctor"),
            );
        }
    };
    let canary = "verify.canary@example.com";
    let resp = blocking_client()
        .post(format!("http://127.0.0.1:{port}/zlauder/diag/mask"))
        .header("x-zlauder-key", &key)
        .json(&json!({ "text": format!("contact {canary} please") }))
        .send();
    match resp {
        Ok(r) if r.status().is_success() => {
            let out: Value = r.json().unwrap_or(Value::Null);
            let changed = out.get("changed").and_then(Value::as_bool).unwrap_or(false);
            let masked = out.get("masked").and_then(Value::as_str).unwrap_or("");
            if changed && !masked.contains(canary) {
                probe(
                    name,
                    ProbeStatus::Pass,
                    "the proxy tokenized a canary value (masking is ON)".to_string(),
                    None,
                )
            } else {
                probe(
                    name,
                    ProbeStatus::Fail,
                    "the canary came back UNMASKED — masking is OFF (transparent pass-through)"
                        .to_string(),
                    Some("turn masking on: /zlauder:privacy on"),
                )
            }
        }
        _ => probe(
            name,
            ProbeStatus::Fail,
            "the diag/mask canary call failed".to_string(),
            Some("check proxy health with /zlauder:doctor"),
        ),
    }
}

/// Verify Leg 2: does THIS session ROUTE through the proxy? `$ANTHROPIC_BASE_URL` == our proxy.
/// A correctly-plumbed-but-pre-restart session legitimately reports NOT routed (matching the
/// statusline ⟳ "restart to mask" state) — phrase it honestly, never falsely "verified".
fn verify_session_routed(root: &str) -> Probe {
    let name = "this session is routed through the proxy";
    let routed = match resolve_live_port(root) {
        Ok(p) => session_routed_through(&format!("http://127.0.0.1:{p}")),
        // No live proxy ⇒ nothing to route to ⇒ not routed. (Comparing against a
        // `:0` sentinel would, in the degenerate case of ANTHROPIC_BASE_URL literally
        // being `http://127.0.0.1:0`, false-pass — so short-circuit instead.)
        Err(_) => false,
    };
    if routed {
        probe(
            name,
            ProbeStatus::Pass,
            "ANTHROPIC_BASE_URL points at this project's proxy".to_string(),
            None,
        )
    } else {
        let abu = std::env::var("ANTHROPIC_BASE_URL").unwrap_or_default();
        let detail = if abu.is_empty() {
            "ANTHROPIC_BASE_URL is unset — this session sends DIRECT to the API, UNMASKED"
                .to_string()
        } else {
            format!(
                "ANTHROPIC_BASE_URL ({abu}) does NOT route through this project's proxy — this \
                 session is UNMASKED"
            )
        };
        probe(
            name,
            ProbeStatus::Fail,
            detail,
            Some("restart Claude Code once to apply the route (written but not live this session), or /zlauder:enable"),
        )
    }
}

/// The foundation: can we connect to 127.0.0.1 over a fresh loopback socket at all?
fn probe_loopback_self_connect() -> Probe {
    let name = "loopback 127.0.0.1 reachable";
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            return probe(
                name,
                ProbeStatus::Fail,
                format!("could not bind 127.0.0.1:0 ({e})"),
                Some("the loopback interface may be down or firewalled"),
            );
        }
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => {
            return probe(
                name,
                ProbeStatus::Fail,
                format!("bound listener has no local address ({e})"),
                Some("the loopback interface may be misconfigured"),
            );
        }
    };
    // The kernel completes the TCP handshake into the listener's backlog WITHOUT an accept(),
    // so a successful connect proves loopback works — and there is no accept thread that could
    // hang if the connect is firewalled (the exact case this probe must survive).
    let ok = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok();
    if ok {
        probe(
            name,
            ProbeStatus::Pass,
            "self-connect over 127.0.0.1 succeeded".into(),
            None,
        )
    } else {
        probe(
            name,
            ProbeStatus::Fail,
            "could not connect to 127.0.0.1 on this machine".into(),
            Some(
                "a local firewall/AV is blocking loopback. Linux: ensure `INPUT -i lo -j ACCEPT`; \
                 macOS: check custom pf rules on lo0; Windows: a security product may intercept \
                 127.0.0.1.",
            ),
        )
    }
}
/// Does the NAME "localhost" resolve to IPv4 first? ZlauDeR always uses the literal 127.0.0.1
/// on the wire, so a "localhost"→`::1` host is only a WARN, not a failure.
fn probe_localhost_resolution() -> Probe {
    use std::net::ToSocketAddrs;
    let name = "localhost resolves to IPv4";
    match ("localhost", 0u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(a) if a.ip().is_ipv4() => probe(
            name,
            ProbeStatus::Pass,
            format!("localhost → {} (IPv4)", a.ip()),
            None,
        ),
        Some(a) => probe(
            name,
            ProbeStatus::Warn,
            format!("localhost → {} (IPv6) first", a.ip()),
            Some(
                "harmless — ZlauDeR uses the literal 127.0.0.1, not the name. Do NOT set \
                 ANTHROPIC_BASE_URL to use \"localhost\".",
            ),
        ),
        None => probe(
            name,
            ProbeStatus::Warn,
            "could not resolve localhost".into(),
            Some("non-fatal — ZlauDeR uses 127.0.0.1 directly"),
        ),
    }
}

/// Does an OS-assigned ephemeral bind yield a concrete port? (The default port mode.)
fn probe_ephemeral_bind() -> Probe {
    let name = "ephemeral bind (127.0.0.1:0)";
    match std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()) {
        Ok(a) if a.port() != 0 => probe(
            name,
            ProbeStatus::Pass,
            format!("OS assigned port {}", a.port()),
            None,
        ),
        Ok(_) => probe(
            name,
            ProbeStatus::Fail,
            "bind :0 returned port 0".into(),
            Some("pin a static `[proxy] port` in zlauder.toml"),
        ),
        Err(e) => probe(
            name,
            ProbeStatus::Fail,
            format!("could not bind :0 ({e})"),
            Some("pin a static `[proxy] port` in zlauder.toml"),
        ),
    }
}

/// Is the state dir creatable + writable (and 0600-capable on Unix)?
fn probe_state_dir() -> Probe {
    let name = "state dir writable";
    let dir = match zlauder_state::state_dir() {
        Ok(d) => d,
        Err(e) => {
            return probe(
                name,
                ProbeStatus::Fail,
                format!("cannot create the state dir ({e})"),
                Some("set $ZLAUDER_STATE_DIR to a writable directory"),
            );
        }
    };
    let test = dir.join(format!(".doctor-{}", std::process::id()));
    if let Err(e) = std::fs::write(&test, b"x") {
        return probe(
            name,
            ProbeStatus::Fail,
            format!("cannot write under {} ({e})", dir.display()),
            Some("set $ZLAUDER_STATE_DIR to a writable directory"),
        );
    }
    let _ = std::fs::remove_file(&test);
    #[cfg(unix)]
    let detail = format!("{} (0600 enforced)", dir.display());
    #[cfg(not(unix))]
    let detail = format!(
        "{} (per-user; 0600 not enforced on Windows — expected)",
        dir.display()
    );
    probe(name, ProbeStatus::Pass, detail, None)
}

/// This project's proxy: healthy (nonce matches), unreachable-though-recorded (firewall/AV),
/// foreign-on-our-port, or not running.
fn probe_project_proxy(root: &str) -> Probe {
    let name = "this project's proxy";
    match zlauder_state::live_port(root) {
        Some((port, rec)) => match proxy_identity(port) {
            Some((build, nonce)) if !rec.nonce.is_empty() && nonce == rec.nonce => probe(
                name,
                ProbeStatus::Pass,
                format!("healthy on :{port} (build {build})"),
                None,
            ),
            Some((build, _)) => probe(
                name,
                ProbeStatus::Warn,
                format!("a proxy answers on :{port} (build {build}) but its nonce ≠ our record"),
                Some("a stale/foreign server may hold the port; start a fresh `claude` session"),
            ),
            None => probe(
                name,
                ProbeStatus::Fail,
                format!(
                    "our proxy (pid {}) is recorded on :{port} but /healthz is unreachable",
                    rec.pid
                ),
                Some(
                    "a local security/AV product or a hardened loopback firewall may be \
                     intercepting 127.0.0.1",
                ),
            ),
        },
        None => probe(
            name,
            ProbeStatus::Info,
            "no proxy running for this project".into(),
            Some("start a `claude` session here, or run /zlauder:enable"),
        ),
    }
}

/// Windows + static port only: reserved/excluded ranges. The ephemeral default avoids them by
/// construction, so this is advisory.
fn probe_windows_excluded_range() -> Probe {
    let name = "windows excluded port range";
    #[cfg(not(windows))]
    {
        probe(name, ProbeStatus::Skip, "not Windows".into(), None)
    }
    #[cfg(windows)]
    {
        probe(
            name,
            ProbeStatus::Skip,
            "ephemeral default avoids reserved ranges; applies only to a static `[proxy] port`"
                .into(),
            Some(
                "if a static port fails, run `netsh interface ipv4 show excludedportrange \
                 protocol=tcp` and pick a port outside the listed blocks",
            ),
        )
    }
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

fn session_start(port_arg: Option<u16>, config: Option<PathBuf>, proxy_bin: String) -> Result<()> {
    // Drain stdin (the SessionStart hook payload) so the pipe doesn't block, and
    // opportunistically extract a stable conversation key for the monitor.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let conversation = conversation_id_from_hook_payload(&stdin);

    let root = canonical(&project_root());
    // Is THIS session routed through OUR proxy? The SessionStart hook fires in every project
    // (the plugin is installed globally), but we only act where Claude Code has applied our
    // route to the live session — at which point this hook subprocess inherits it. The route
    // is `ANTHROPIC_BASE_URL` + the co-baked `ZLAUDER_PORT` (= the baked port); when they
    // agree on a loopback proxy, `port_arg` (=$ZLAUDER_PORT) is that port and we're routed to
    // it. The proxy is the sole authority on its (ephemeral) port, so there is no derived port
    // to guess — an unrouted session simply has no matching ZLAUDER_PORT in its env.
    // Announcing "masking active" when this session is NOT pointed at us would be a lie (the
    // misleading-status bug), so gate every side effect on this real, env-derived route.
    let routed_port =
        port_arg.filter(|p| session_routed_through(&format!("http://127.0.0.1:{p}")));

    if routed_port.is_none() {
        // Port-agnostic "is this project plumbed through us": an ephemeral baked port can't be
        // re-derived, so read it back from settings.local.json (a loopback ANTHROPIC_BASE_URL
        // whose port matches the co-baked ZLAUDER_PORT). Ignores a user's own unrelated base URL.
        let configured = project_baked_route(&root).is_some();
        let opted_out =
            zlauder_state::registry_get(&root) == Some(zlauder_state::PlumbState::Optout);
        // Global escape hatch: ZLAUDER_NO_AUTO_ENABLE disables auto-plumb everywhere.
        let auto_enable = std::env::var_os("ZLAUDER_NO_AUTO_ENABLE").is_none();

        if !configured && !opted_out && auto_enable {
            // AUTO-PLUMB (first sight of this project): launch the proxy NOW to learn its
            // OS-assigned ephemeral port, then bake THAT route into settings.local.json
            // (gitignored) and record it Plumbed. We launch EAGERLY — so a one-time restart
            // activates masking instantly with no first-message ConnectionRefused hang — but
            // make NO claim of masking THIS session: Claude Code applies a route written during
            // SessionStart only unreliably (~1/5), so the SURE activation is a restart, which
            // the statusline surfaces as "⟳ ZlauDeR: restart to mask".
            let bake_port = match ensure_up(&root, config.clone(), &proxy_bin) {
                Ok(EnsureOutcome::Ours { port }) => port,
                Ok(EnsureOutcome::Failed { diag }) => {
                    // Proxy didn't come up — make NO masking claim; reason on stderr, stdout a
                    // silent valid no-op (don't exit non-zero with empty stdout).
                    eprintln!(
                        "ZlauDeR: could not auto-enable masking — {diag} Run /zlauder:enable to retry."
                    );
                    println!("{}", json!({}));
                    return Ok(());
                }
                Err(e) => {
                    eprintln!(
                        "ZlauDeR: could not auto-enable masking for this project: {e}. \
                         Run /zlauder:enable to retry."
                    );
                    println!("{}", json!({}));
                    return Ok(());
                }
            };
            let bake_url = format!("http://127.0.0.1:{bake_port}");
            match settings_enable(&bake_url, &bake_port.to_string(), &statusline_command()) {
                Ok(_) => {
                    let _ =
                        zlauder_state::registry_set(&root, zlauder_state::PlumbState::Plumbed);
                    // First sight of this project: the route is now baked into
                    // settings.local.json. Claude Code applies a route WRITTEN during this
                    // SessionStart to the current session only unreliably; every session after
                    // the first reads it at startup, which always works. So the sure activation
                    // is a one-time restart — surfaced to the human on the statusline
                    // ("⟳ ZlauDeR: restart to mask") and recommended here. We do NOT launch the
                    // proxy this session: a restart (or the next routed session) brings it up via
                    // the routed branch's ensure_up, so it isn't left running unused.
                    eprintln!(
                        "ZlauDeR: auto-enabled PII masking for this project (wrote \
                         .claude/settings.local.json). RESTART Claude Code once to activate it — the \
                         statusline shows '⟳ ZlauDeR: restart to mask' until it's live, then 🛡. Until \
                         then ZlauDeR blocks this session's messages so nothing sends unmasked (set \
                         ZLAUDER_NO_INTAKE_GATE=1 to send anyway). Control it with /zlauder:privacy; \
                         remove it with /zlauder:disable. (ZLAUDER_NO_AUTO_ENABLE=1 opts out globally.)"
                    );
                    println!(
                        "{}",
                        json!({
                            "hookSpecificOutput": {
                                "hookEventName": "SessionStart",
                                "additionalContext":
                                    "ZlauDeR just auto-enabled PII masking for this project (route written to \
                                     .claude/settings.local.json). Masking is NOT active in THIS session yet — \
                                     the sure activation is a one-time restart of Claude Code, after which it \
                                     stays on automatically. Until then ZlauDeR's intake gate BLOCKS this \
                                     session's messages so nothing reaches the API provider unmasked (unless the \
                                     user set ZLAUDER_NO_INTAKE_GATE=1, in which case outbound text may reach the \
                                     API provider UNMASKED — real PII, not tokens). This is only about what the \
                                     provider sees; the user always sees their own plaintext locally. If the user \
                                     asks why masking isn't on yet, tell them to restart Claude Code once. Never \
                                     tell the user their data is hidden in this session. The user controls masking \
                                     with /zlauder:privacy and removes it with /zlauder:disable."
                            }
                        })
                    );
                }
                Err(e) => {
                    // Could not write settings — make NO masking claim. stdout stays a silent,
                    // valid no-op; the reason goes to stderr. We deliberately leave the running
                    // proxy and its rendezvous record in place: it is this project's own proxy,
                    // and tearing it down could strand a concurrent same-project sibling already
                    // using it. The project is left un-plumbed and retried next session.
                    eprintln!(
                        "ZlauDeR: could not auto-enable masking for this project: {e}. \
                         Run /zlauder:enable to retry."
                    );
                    println!("{}", json!({}));
                }
            }
            return Ok(());
        }

        if opted_out && configured {
            // SELF-HEAL: opted out here, yet a route is STILL baked into settings.local.json (a
            // prior /zlauder:disable's strip didn't fully land, or the file was restored). Left
            // alone, this session routes to a proxy the user disabled — a hang if it's down.
            // Strip the stale route so this and future sessions stop routing; opt-out means no
            // masking intent, so reverting to a direct (unmasked) connection is exactly right
            // (this is the only safe strip — we NEVER strip a route a project still intends).
            let _ = settings_disable_at(Path::new(&root));
            eprintln!(
                "ZlauDeR: this project is opted out, but a stale route was still baked into \
                 .claude/settings.local.json — removed it so the session won't route to a \
                 disabled proxy. Re-enable masking any time with /zlauder:enable."
            );
            println!("{}", json!({}));
            return Ok(());
        }

        if configured {
            // Plumbed earlier but this live session isn't routed yet (typically the very first
            // message after enable/auto-plumb). Claude Code reads a freshly-written route
            // reliably only at startup, so the SURE activation is a one-time restart — and the
            // UserPromptSubmit intake gate BLOCKS this session's prompts until then, so nothing
            // egresses unmasked first. Stay a route-less no-op for now; the proxy launches on
            // the session that actually routes.
            eprintln!(
                "ZlauDeR: this project is configured but THIS session isn't routed yet. Restart \
                 Claude Code once to activate masking (the statusline shows '⟳ ZlauDeR: restart to \
                 mask' until it's live). Until then ZlauDeR blocks this session's messages so \
                 nothing sends unmasked (set ZLAUDER_NO_INTAKE_GATE=1 to send anyway)."
            );
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext":
                            "ZlauDeR is configured for this project but masking is NOT active in THIS \
                             session yet — the sure activation is a one-time restart of Claude Code. \
                             Until then ZlauDeR's intake gate BLOCKS this session's messages so nothing \
                             reaches the API provider unmasked (unless the user set ZLAUDER_NO_INTAKE_GATE=1, \
                             in which case outbound text may reach the provider UNMASKED — real PII, not \
                             tokens). This is only about what the provider sees; the user always sees their \
                             own plaintext. If the user asks why masking isn't on, tell them to restart \
                             Claude Code once. Control with /zlauder:privacy."
                    }
                })
            );
            return Ok(());
        }

        // Opted out (the user ran /zlauder:disable here), or auto-enable disabled, and not
        // configured: stay a silent no-op.
        println!("{}", json!({}));
        return Ok(());
    }

    // Routed through us: bring this project's proxy up and learn the port it actually bound.
    let routed_port = routed_port.expect("routed_port is Some on this branch");
    let port = match ensure_up(&root, config, &proxy_bin)? {
        EnsureOutcome::Ours { port } => port,
        EnsureOutcome::Failed { diag } => {
            // The route is baked + applied, but no proxy of ours is reachable — requests this
            // session fail/hang (fail-CLOSED, never unmasked). Make NO masking claim and point
            // at the diagnosis.
            eprintln!("ZlauDeR: {diag}");
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext":
                            "ZlauDeR is configured for this project but its local proxy is NOT \
                             currently reachable, so masking is NOT active for THIS session and \
                             requests may fail or hang. This is only about what the provider sees; \
                             the user always sees their own plaintext. Never tell the user their \
                             data is hidden in this session. Run /zlauder:doctor to diagnose."
                    }
                })
            );
            return Ok(());
        }
    };

    if port != routed_port {
        // THE STALE-PORT WINDOW (e2e-surfaced, documented limitation). This session was ROUTED
        // at Claude Code STARTUP to `routed_port`, but our live proxy is now on a DIFFERENT
        // port `port` — the project's sticky port was taken by another process while our proxy
        // was down (proxy death + an exact ephemeral-port steal — narrow, not hit in normal
        // relaunch which reuses the sticky port). Claude Code cannot re-route a live session,
        // so THIS session's API traffic is going to `routed_port`, which is NOT our proxy: it
        // will HANG if that port is an unresponsive black hole, or reach a FOREIGN local
        // process UNMASKED if it accepts. We cannot stop this session's in-flight call, so we
        // (a) reconcile the baked route so the NEXT session is correct, and (b) probe the stale
        // port and warn as LOUDLY and specifically as possible — telling the user to abort +
        // restart NOW. Fail-CLOSED: we never strip the route (that would egress to the user's
        // real upstream unmasked). A full fix needs Claude Code mid-session re-routing.
        let reconciled = settings_enable(
            &format!("http://127.0.0.1:{port}"),
            &port.to_string(),
            &statusline_command(),
        )
        .is_ok();
        let (human, model) =
            stale_route_messages(routed_port, port, classify_stale_route(routed_port), reconciled);
        eprintln!("ZlauDeR: {human}");
        println!(
            "{}",
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": model
                }
            })
        );
        return Ok(());
    }

    // port == routed_port: this session's traffic flows through our live proxy. Announce.
    let base_url = format!("http://127.0.0.1:{port}");
    // SessionStart hook output. The static `env` written into settings.local.json (by
    // auto-plumb or `/zlauder:enable`) is the load-bearing path for ANTHROPIC_BASE_URL;
    // the `env` key here is a best-effort override for harness versions that honor it.
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

/// `UserPromptSubmit` hook — the fail-CLOSED first-session INTAKE GATE. Claude Code applies a
/// freshly-written `settings.local.json` route to the CURRENT session only unreliably, so the
/// common first session after auto-plumb/`enable` is PLUMBED but NOT routed: its prompt would
/// reach the API provider UNMASKED (real PII, not tokens). This hook runs BEFORE the prompt is
/// sent and, in exactly that state, returns `decision:"block"` so the prompt never egresses —
/// turning the statusline's "⟳ restart to mask" nudge into an ENFORCED restart and closing the
/// first-session direct-leak. Every other state is a silent ALLOW (emit nothing): not plumbed,
/// already routed, opted out, or the `ZLAUDER_NO_INTAKE_GATE` escape hatch.
///
/// The decision uses only fast LOCAL reads (the baked route + `$ANTHROPIC_BASE_URL`) — no
/// network. This matters BECAUSE a UserPromptSubmit hook that hangs (30s timeout) or crashes
/// FAILS OPEN (the prompt proceeds unmasked); only an explicit block decision is fail-closed.
/// Every read on this path is non-panicking by construction: `project_root` (env/cwd with a
/// fallback), `canonical` (`canonicalize` with an `unwrap_or_else` fallback), `registry_get` /
/// `project_baked_route` (fallible `fs::read` + `serde` that degrade to `None`), and
/// `session_routed_through` (env + string compare) — none `unwrap`/`expect`/index, so no panic
/// path precedes the block emission. A missing binary likewise fails open at the shell wrapper,
/// which is correct: no zlauder installed ⇒ no masking promise ⇒ nothing to gate.
fn user_prompt_submit() -> Result<()> {
    // Drain the hook payload so the pipe never blocks; its contents aren't needed.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);

    let root = canonical(&project_root());
    // Gather the routing facts with fast LOCAL reads only (registry file, settings.local.json,
    // $ANTHROPIC_BASE_URL) — nothing that hits the network or can hang.
    let opted_out =
        zlauder_state::registry_get(&root) == Some(zlauder_state::PlumbState::Optout);
    let baked_port = project_baked_route(&root);
    // Routed iff this session's $ANTHROPIC_BASE_URL points at the baked proxy port. If the proxy
    // is down, a routed session still fails-closed AT the proxy (never unmasked), so "routed"
    // is the right allow condition.
    let routed = baked_port
        .is_some_and(|p| session_routed_through(&format!("http://127.0.0.1:{p}")));
    // VALUE-aware, unlike the presence-based ZLAUDER_NO_AUTO_ENABLE: this disables a fail-CLOSED
    // SECURITY control, so a user who sets `=0` meaning "off" must NOT accidentally turn the gate
    // off — only an explicitly truthy value opens the hatch.
    let escape_hatch = std::env::var("ZLAUDER_NO_INTAKE_GATE")
        .map(|v| is_truthy_flag(&v))
        .unwrap_or(false);

    if !intake_should_block(opted_out, baked_port.is_some(), routed, escape_hatch) {
        return Ok(()); // allow: emit nothing
    }

    // PLUMBED but THIS session is NOT routed: the prompt would reach the API UNMASKED. Block it
    // (exit 0 + `decision:"block"` is the fail-closed contract; the reason is shown to the user).
    let reason = "ZlauDeR PII masking is enabled for this project, but THIS Claude Code session \
                  is not yet routed through the masking proxy — so your message would reach the \
                  API provider UNMASKED (real PII, not tokens). Restart Claude Code once to \
                  activate masking; every session after the first picks it up automatically. \
                  (Only what the provider sees is affected — you always see your own plaintext. \
                  To send this session WITHOUT masking, set ZLAUDER_NO_INTAKE_GATE=1 in your \
                  environment and try again.)";
    println!("{}", json!({ "decision": "block", "reason": reason }));
    Ok(())
}

/// Fail-CLOSED intake-gate decision (pure — for testing). BLOCK iff this project is plumbed
/// through us AND this session is NOT routed to it, and neither the opt-out nor the
/// `ZLAUDER_NO_INTAKE_GATE` escape hatch applies. Every other state is an ALLOW: not plumbed
/// (no masking intent), already routed (masking active / fails-closed at the proxy), opted out,
/// or escape-hatched.
fn intake_should_block(opted_out: bool, plumbed: bool, routed: bool, escape_hatch: bool) -> bool {
    !escape_hatch && !opted_out && plumbed && !routed
}

/// Truthy-flag parse for an env value (pure — for testing). Only an explicitly affirmative value
/// counts; `0`, `false`, `""`, or junk read as false. Used so the intake-gate escape hatch can't
/// be flipped off by a `=0` a user meant as "keep it on".
fn is_truthy_flag(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Outcome of bringing this project's proxy up. The proxy is project-keyed (a record
/// keyed by `blake3(root)`), so a foreign project can no longer be mistaken for ours —
/// the only failure mode left is "we could not bring a proxy of OURS up" (spawn/bind
/// failure, a static-port conflict that exits without publishing, or a launch that never
/// went healthy). The hook surfaces `diag` and makes NO masking claim in that case.
enum EnsureOutcome {
    /// A healthy proxy of our build is serving on `port` for THIS project.
    Ours { port: u16 },
    /// No proxy of ours came up; `diag` is a human, actionable reason.
    Failed { diag: String },
}

/// Ensure this project's proxy is running and is OUR current build, then return the port
/// it bound. The proxy is the sole authority on its port (an OS-assigned ephemeral port by
/// default, or a static `[proxy] port`); we LEARN the bound port from the project-keyed
/// rendezvous after launch. A healthy proxy of our build is adopted as-is; a stale build
/// (e.g. after a plugin update) is recycled; nothing live means a fresh launch under the
/// per-project launch lock. `config` defaults to the project's `zlauder.toml` when present.
fn ensure_up(root: &str, config: Option<PathBuf>, proxy_bin: &str) -> Result<EnsureOutcome> {
    let config = config.or_else(|| {
        let p = Path::new(root).join("zlauder.toml");
        p.exists().then_some(p)
    });

    // Adopt an already-running proxy for this project ONLY if a live `/healthz` echoes the
    // nonce recorded in OUR rendezvous — proof it is the exact proxy instance that published
    // the record, not a foreign 200-server that grabbed the port after a PID-reuse + port-
    // steal. Without the nonce check, such a server would be adopted and this project's
    // traffic would route UNMASKED through a non-zlauder process — the worst "looks fine but
    // isn't" failure. `live_port` is project-keyed + pid-prefiltered; the nonce match is the
    // authoritative identity. A stale BUILD (our instance, older code) is recycled so a
    // plugin update takes effect. A hook-launched proxy always carries a nonce, so an empty
    // `rec.nonce` (a manual/legacy proxy) is deliberately NOT adopted — we relaunch ours.
    if let Some((port, rec)) = zlauder_state::live_port(root)
        && !rec.nonce.is_empty()
        && let Some((build, live_nonce)) = proxy_identity(port)
        && live_nonce == rec.nonce
    {
        let ours = zlauder_state::BUILD_ID;
        let stale = ours != "unknown" && build != "unknown" && build != ours;
        if !stale {
            return Ok(EnsureOutcome::Ours { port });
        }
        eprintln!(
            "ZlauDeR: proxy on :{port} is an older build — restarting to apply the update."
        );
        stop_proxy(port, rec.pid);
        // fall through to a fresh launch
    }

    launch_proxy(root, config.as_deref(), proxy_bin)
}

/// Spawn the proxy as the single launcher for this project (the rendezvous launch lock),
/// then wait for it to publish a healthy, nonce-matching record. A loser of the launch
/// race does not spawn — it waits for the winner's proxy to come live. The lock is held
/// until the proxy has published (or we give up), so a sibling can never double-launch.
fn launch_proxy(root: &str, config: Option<&Path>, proxy_bin: &str) -> Result<EnsureOutcome> {
    let nonce = rand_hex16();
    // Salt reuse: keep this project's salt across a relaunch (tokens + prompt-cache prefix
    // stable) ONLY from a VALIDATED (owner-only, our-root) rendezvous record. Never inherit
    // another project's salt; the proxy mints a fresh encryption key regardless.
    let salt_hex = match zlauder_state::read_rendezvous(root) {
        Some(rec) if rec.salt.len() == 32 => rec.salt,
        _ => rand_hex16(),
    };

    let _lock = match zlauder_state::try_launch_lock(root, std::process::id(), &nonce)? {
        Some(g) => g,
        // Another launcher holds the lock — it's bringing the proxy up. Wait for ANY live,
        // healthy proxy for this project (we don't know the winner's nonce, but the
        // project-keyed lookup + health is enough to adopt the one it publishes).
        None => return Ok(wait_for_live(root, None)),
    };

    let dir = zlauder_state::state_dir()?;
    // Per-project log (keyed by project hash — we no longer know the port up front).
    let log_path = dir.join(format!("proxy-{}.log", zlauder_state::project_key(root)));
    let log = std::fs::File::create(&log_path).context("creating proxy log")?;
    let log_err = log.try_clone()?;

    let mut cmd = std::process::Command::new(proxy_bin);
    cmd.arg("--project-root")
        .arg(root)
        .env("ZLAUDER_SESSION_SALT", &salt_hex)
        .env("ZLAUDER_LAUNCH_NONCE", &nonce)
        .env("ZLAUDER_PROJECT_ROOT", root)
        // CRITICAL: strip an inherited ZLAUDER_PORT. In a routed session our own env carries
        // ZLAUDER_PORT (the baked port, an informational hint for the CLI/statusline), but the
        // proxy reads `--port`/ZLAUDER_PORT as a STATIC PIN. Leaking it would hard-pin the
        // baked port and defeat the ephemeral/sticky bind (and its :0 fallback). The proxy
        // gets its port from `[proxy] port` (static) or its own rendezvous last_port (sticky)
        // — never from the hook's ambient env.
        .env_remove("ZLAUDER_PORT")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }
    // Detach the long-lived proxy from THIS process so nothing we own keeps it tethered: it
    // must outlive the session (sibling windows / later sessions reuse the one per-project
    // proxy) and must not hold the SessionStart stdout pipe open (else the launching `claude`
    // stalls waiting for EOF). stdio is already redirected to the log; these flags drop the
    // remaining console/session tether per platform.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    if let Err(e) = cmd.spawn() {
        // Spawn failed (missing binary, or a transient EAGAIN/ENOMEM under fork pressure).
        // Release the lock and report — nothing was published, so no record to clean up.
        return Ok(EnsureOutcome::Failed {
            diag: format!("could not spawn the proxy binary '{proxy_bin}': {e}"),
        });
    }

    // Hold the lock across the wait: only release once the proxy has published a healthy
    // record carrying OUR nonce (so we adopt the exact instance we spawned, never a stale /
    // static-conflict / foreign record), or once we give up.
    Ok(wait_for_live(root, Some(&nonce)))
}

/// Poll this project's rendezvous until a healthy proxy is live, up to ~5s (generous for a
/// cold/loaded first launch — the proxy publishes its record BEFORE serving, so `/healthz`
/// answers as soon as it serves). The live `/healthz` must echo the nonce in the PUBLISHED
/// record — proof the serving process is the one that published it, not a foreign server on
/// the same port. When `expect_nonce` is set (we spawned it), the record must additionally
/// carry OUR nonce, so a concurrent unrelated publish can't be mistaken for our spawn.
fn wait_for_live(root: &str, expect_nonce: Option<&str>) -> EnsureOutcome {
    for _ in 0..100 {
        if let Some((port, rec)) = zlauder_state::live_port(root)
            && !rec.nonce.is_empty()
            && let Some((_build, live_nonce)) = proxy_identity(port)
            && live_nonce == rec.nonce
        {
            let ours = match expect_nonce {
                Some(n) => rec.nonce == n,
                None => true,
            };
            if ours {
                return EnsureOutcome::Ours { port };
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    EnsureOutcome::Failed {
        diag: launch_failure_diag(root),
    }
}

/// 16 random bytes, hex-encoded (a salt or a launch nonce).
fn rand_hex16() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}

/// One `/healthz` round-trip: `(build_id_body, nonce_header)` if the proxy answers 2xx.
/// The body is the proxy's build id (for stale-build recycling); the `x-zlauder-nonce`
/// header is this launch's nonce (empty if absent). `None` if unreachable / non-2xx.
fn proxy_identity(port: u16) -> Option<(String, String)> {
    let resp = blocking_client()
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let nonce = resp
        .headers()
        .get("x-zlauder-nonce")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let build = resp.text().ok()?.trim().to_string();
    Some((build, nonce))
}

/// A human, actionable reason a launch never went healthy — the auto-diagnosis the hook
/// surfaces (and `/zlauder:doctor` expands). Distinguishes "running but unreachable over
/// loopback" (a local firewall/AV intercepting 127.0.0.1) from "never bound / crashed"
/// (read the proxy log tail for the classified bind error or panic).
fn launch_failure_diag(root: &str) -> String {
    if let Some((port, rec)) = zlauder_state::live_port(root) {
        return format!(
            "the proxy (pid {}) appears to be running but is unreachable over 127.0.0.1:{port} \
             — a local security/AV product or a hardened loopback firewall may be intercepting \
             127.0.0.1. Run /zlauder:doctor.",
            rec.pid
        );
    }
    match read_proxy_log_tail(root, 12) {
        Some(tail) if !tail.trim().is_empty() => {
            format!("the proxy did not start or exited. Last log lines:\n{tail}")
        }
        _ => format!(
            "the proxy did not start (no log output). Check that the zlauder-proxy binary \
             exists and is executable, then run /zlauder:doctor."
        ),
    }
}

/// The last `n` lines of this project's proxy log (`proxy-<project_key>.log`), if any.
fn read_proxy_log_tail(root: &str, n: usize) -> Option<String> {
    let path = zlauder_state::state_dir()
        .ok()?
        .join(format!("proxy-{}.log", zlauder_state::project_key(root)));
    let text = std::fs::read_to_string(path).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    Some(lines[start..].join("\n"))
}

/// What is sitting on a stale routed port that is NOT our proxy — drives how loud/specific
/// the stale-route warning is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StaleRoute {
    /// Nothing is listening — the session's requests fail fast (no hang, no leak).
    Refused,
    /// Something accepts the connection but never answers HTTP — the session HANGS.
    Unresponsive,
    /// A foreign HTTP server answers — the session's traffic reaches it UNMASKED.
    ForeignResponder,
}

/// Probe a stale routed port (one this session is pointed at but that is NOT our live proxy)
/// to classify the danger. A short connect + a short-timeout `/healthz` keeps the SessionStart
/// delay bounded even against a black hole.
fn classify_stale_route(port: u16) -> StaleRoute {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
        Err(_) => StaleRoute::Refused,
        Ok(probe) => {
            // Close the probe connection BEFORE the HTTP check — holding it open would tie up a
            // single-threaded server and make a real responder look unresponsive.
            drop(probe);
            // Accepts connections. A real HTTP server answers quickly; an accept-but-silent
            // black hole does not (the case that hangs the session).
            let answered = reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(600))
                .build()
                .ok()
                .and_then(|c| c.get(format!("http://127.0.0.1:{port}/healthz")).send().ok())
                .is_some();
            if answered {
                StaleRoute::ForeignResponder
            } else {
                StaleRoute::Unresponsive
            }
        }
    }
}

/// The (human-on-stderr, model-in-additionalContext) warnings for a session stuck on a stale
/// routed port. Both tell the user to abort + restart; the model copy forbids any masking
/// claim. `new_port` is where our live proxy actually is now.
fn stale_route_messages(
    routed_port: u16,
    new_port: u16,
    danger: StaleRoute,
    reconciled: bool,
) -> (String, String) {
    let tail = if reconciled {
        format!("The route is repointed to the new proxy on :{new_port} for your NEXT session.")
    } else {
        "The route could NOT be updated — run /zlauder:enable.".to_string()
    };
    match danger {
        StaleRoute::Unresponsive => (
            format!(
                "THIS session may HANG (or leak) — it is routed to :{routed_port}, now held by an \
                 unresponsive or non-HTTP process (not the zlauder proxy). Press Ctrl-C and restart \
                 Claude Code now. {tail}"
            ),
            format!(
                "ZlauDeR: THIS session is routed to a non-zlauder local port (:{routed_port}) that \
                 does not answer as our proxy — its API requests will HANG, or reach a foreign \
                 process UNMASKED. Either way it is NOT masked. Tell the user to press Ctrl-C and \
                 restart Claude Code now. Never claim masking is active. {tail}"
            ),
        ),
        StaleRoute::ForeignResponder => (
            format!(
                "DANGER: THIS session's traffic is going UNMASKED to a DIFFERENT local process on \
                 :{routed_port} (not the zlauder proxy). Press Ctrl-C and restart Claude Code NOW. \
                 {tail}"
            ),
            format!(
                "ZlauDeR: THIS session is NOT masked — its traffic is reaching a DIFFERENT local \
                 process on :{routed_port}, UNMASKED (real PII, not tokens). Tell the user to press \
                 Ctrl-C and restart Claude Code immediately. Never claim masking is active or that \
                 the user's data is hidden in this session. {tail}"
            ),
        ),
        StaleRoute::Refused => (
            format!(
                "THIS session isn't masked — its proxy port :{routed_port} is gone, so requests \
                 fail. Restart Claude Code to use the new proxy. {tail}"
            ),
            format!(
                "ZlauDeR: THIS session is NOT masked — its proxy port (:{routed_port}) is no longer \
                 listening, so requests fail. Tell the user to restart Claude Code. Never claim \
                 masking is active. {tail}"
            ),
        ),
    }
}

/// `ensure-up` subcommand: ensure this project's proxy is running (the shared
/// [`ensure_up`] primitive) and, with `--print-url`, print its base URL on stdout. Unlike
/// `session-start`, it does NOT gate on the session already being routed — it brings the
/// proxy up unconditionally, so it can warm the proxy ahead of time, or back a future
/// zero-state launcher that exec's Claude Code with `--settings` injecting that URL.
fn ensure_up_cmd(config: Option<PathBuf>, proxy_bin: String, print_url: bool) -> Result<()> {
    let root = canonical(&project_root());
    match ensure_up(&root, config, &proxy_bin)? {
        EnsureOutcome::Ours { port } => {
            if print_url {
                println!("http://127.0.0.1:{port}");
            }
            Ok(())
        }
        // No proxy of ours came up. Do NOT print a URL — a launcher consuming
        // `ensure-up --print-url` must fall through to an UNROUTED session rather than route
        // through a phantom port. Fail loud with the diagnosis.
        EnsureOutcome::Failed { diag } => {
            bail!("could not bring this project's proxy up: {diag}")
        }
    }
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

/// Bring this project's proxy up (binding an OS-assigned ephemeral port if it isn't already
/// running) and print the port it bound (bare integer on stdout).
/// `/zlauder:enable` calls this to learn the port to write into settings.local.json. Unlike
/// `session-start` it emits NO hook JSON — only the bare port — so /zlauder:enable can call it
/// during a first-time enable, where the session is not yet routed through the proxy.
fn reserve_port_cmd(config: Option<PathBuf>, proxy_bin: String) -> Result<()> {
    let root = canonical(&project_root());
    match ensure_up(&root, config, &proxy_bin)? {
        EnsureOutcome::Ours { port } => {
            println!("{port}");
            Ok(())
        }
        EnsureOutcome::Failed { diag } => {
            bail!("could not bring this project's proxy up: {diag}")
        }
    }
}

// ---------------------------------------------------------------------------
// statusline
// ---------------------------------------------------------------------------

/// How much the zlauder status-line segment shows, chosen by `$ZLAUDER_STATUSLINE`.
/// Defaults to `Compact`. `Off` hides the zlauder segment entirely — when the status
/// line wraps a user's original line (see [`read_wrap_original`]), that original still
/// prints, so `off` means "show only my line, no zlauder chrome", not "blank".
/// `ShieldOnly` is the opposite bias: render the 🛡 ONLY when masking is CONFIRMED and
/// render NOTHING in every other state (down / off / unverified / restart-to-mask) — for
/// users who want a quiet line that appears solely as a positive masking indicator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlMode {
    Off,
    /// Show 🛡 ONLY when masking is CONFIRMED; render nothing in every other state.
    ShieldOnly,
    Min,
    Compact,
    Verbose,
}

fn sl_mode() -> SlMode {
    sl_mode_from(std::env::var("ZLAUDER_STATUSLINE").ok().as_deref())
}

/// Pure `$ZLAUDER_STATUSLINE` → mode mapping (kept separate from `sl_mode` so it's
/// unit-testable without mutating the process environment). Case- and space-insensitive;
/// anything unrecognized falls back to `Compact`.
fn sl_mode_from(raw: Option<&str>) -> SlMode {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("off" | "none" | "hidden" | "0" | "false") => SlMode::Off,
        Some("shield" | "shield-only" | "shieldonly" | "quiet") => SlMode::ShieldOnly,
        Some("min" | "minimal" | "compact-min") => SlMode::Min,
        Some("verbose" | "full" | "all") => SlMode::Verbose,
        _ => SlMode::Compact,
    }
}

fn statusline(port: Option<u16>) -> Result<()> {
    let proj = project_root();
    let root = canonical(&proj);
    // The session's routed port (`$ZLAUDER_PORT`, set in-session) when present; else a
    // best-effort fall back to OUR live proxy's port for a manual run. `None` ⇒ no proxy
    // known ⇒ the segment renders the honest not-masking/restart state.
    let port = port.or_else(|| resolve_live_port(&root).ok());
    let mode = sl_mode();

    // The zlauder segment (None only in `off` mode). Built first so a slow/absent
    // wrapped command never delays or suppresses our own privacy indicator.
    let segment = match mode {
        SlMode::Off => None,
        _ => Some(render_segment(port, &root, mode)),
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
    // A blank segment (ShieldOnly renders `Some("")` in every unconfirmed state) is treated
    // as absent, so it degrades to the wrapped-only / empty arms below instead of emitting a
    // stray leading `│` divider against a non-empty wrapped line.
    let segment = segment.filter(|s| !s.trim().is_empty());
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
fn render_segment(port: Option<u16>, root: &str, mode: SlMode) -> String {
    // Ground truth for THIS session: does its ANTHROPIC_BASE_URL (inherited from Claude
    // Code) actually point at our proxy on `port`? That reflects the route ACTUALLY applied to
    // this session, not merely what settings.local.json says — Claude Code applies a route
    // written during SessionStart to the current session only unreliably. If we're not routed
    // (no known port, or the env route doesn't point at `port`), traffic is NOT masked through
    // us right now, so say so honestly rather than render a health-based shield that would lie.
    let routed = port
        .map(|p| session_routed_through(&format!("http://127.0.0.1:{p}")))
        .unwrap_or(false);
    if !routed {
        // GROUND TRUTH, not the persistent plumbed registry: is a route actually baked into
        // THIS project's settings.local.json — i.e. one a restart WILL apply? The registry
        // flag persists per-user and survives an out-of-band route removal (the user hand-
        // deletes env.ANTHROPIC_BASE_URL/ZLAUDER_PORT, or a gitignored settings.local.json is
        // simply absent on a fresh clone while the registry still says Plumbed). Keying
        // "restart to mask" on that stale flag is a LIE — a restart finds no route to apply —
        // and the intake gate stands down in the same state (not plumbed on disk), so traffic
        // would egress UNMASKED while the line promises masking. project_baked_route makes the
        // claim falsifiable and aligns render_segment with SessionStart/intake/--all, which
        // all already read the on-disk route.
        return match project_baked_route(root) {
            // A route IS baked but hasn't been applied to THIS session yet — the first-run
            // live-reload window. A one-time restart applies it reliably (every session after
            // the first reads the route at startup, which always works).
            Some(_) => match mode {
                SlMode::ShieldOnly => String::new(),
                SlMode::Min => "\u{27f3}".to_string(), // ⟳
                _ => "\u{27f3} ZlauDeR: restart to mask".to_string(),
            },
            // No route baked here — this session is NOT masked through us, and a restart
            // won't change that (opted out, never plumbed, or the route was removed).
            None => match mode {
                SlMode::ShieldOnly => String::new(),
                SlMode::Min => "\u{2717}".to_string(), // ✗
                _ => "\u{2717} ZlauDeR not masking".to_string(),
            },
        };
    }
    let port = port.expect("routed implies a Some port");
    // Routed: this session's traffic flows through `port`. Reflect its health + masking.
    if !proxy_healthy(port) {
        // The route is live but the proxy isn't answering — requests fail/hang
        // (ConnectionRefused). Distinct from "not routed through us at all".
        return match mode {
            SlMode::ShieldOnly => String::new(),
            SlMode::Min => "\u{26a0}".to_string(), // ⚠
            _ => format!("\u{26a0} ZlauDeR routed, proxy down :{port}"),
        };
    }
    // Is the proxy the session is routed to actually OURS? `live_identity` verifies the process
    // on our rendezvous port echoes our nonce over /healthz (closing the PID-reuse/port-steal
    // hole); we then require the session's routed `port` to BE that verified proxy. Any mismatch
    // — stale record, stolen ephemeral port, foreign server answering — degrades to unverified,
    // never a false shield (finding C5).
    let Some((_, key)) = live_identity(root).filter(|(lp, _)| *lp == port) else {
        return unverified(port, mode);
    };
    match admin_get(port, &key) {
        Ok(snap) => match serde_json::from_value::<Snapshot>(snap) {
            Ok(s) if s.enabled => render_on(&s, port, mode),
            Ok(_) => match mode {
                SlMode::ShieldOnly => String::new(),
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
        SlMode::ShieldOnly => String::new(),
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
        // ShieldOnly's whole purpose: the bare 🛡, and ONLY here (confirmed-masking). Every
        // other render path returns an empty string for ShieldOnly.
        SlMode::ShieldOnly => "\u{1f6e1}".to_string(),
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

/// Compact ML indicator appended to the status line when masking is on.
fn ml_indicator(ml: Option<&MlSnap>) -> &'static str {
    match ml.map(|m| (m.status.as_str(), m.last_runtime_error.is_some())) {
        Some(("ready", false)) => " \u{1f9e0}",   // 🧠 filtering
        Some(("ready", true)) => " \u{26a0}\u{1f9e0}", // ⚠🧠 loaded but endpoint failing
        Some(("loading", _)) => " \u{23f3}ml",    // ⏳ml loading — not filtered yet
        Some(("failed", _)) => " \u{26a0}ml",     // ⚠ml load failed
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

fn config_cmd(action: Option<ConfigAction>) -> Result<()> {
    let root = canonical(&project_root());
    // Best-effort live port. The mutating `--scope project|user|local` actions PERSIST to the
    // config file even when the proxy is DOWN (the apply_* helpers degrade to "applies on the
    // next session" — they gate every live admin call on key_for(root)), so they must NOT
    // hard-require a live proxy. When the proxy is up the real port flows through; when down,
    // `0` is a sentinel that never reaches a live admin call. Only `Show` and `--scope session`
    // genuinely need a live proxy, and they surface the resolver's error themselves.
    let port = resolve_live_port(&root).unwrap_or(0);

    match action.unwrap_or(ConfigAction::Show) {
        ConfigAction::Show => {
            let port = resolve_live_port(&root)?;
            let snap = live_snapshot(port, &root)
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
        ConfigAction::Entity { name, op, scope } => apply_entity(port, &root, scope, &name, &op)?,
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
            let snap = live_snapshot(port, root)
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
            key_for(root).context("proxy not running; use --scope project/user to persist")?;
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
    let applied = match key_for(root) {
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
    let http = ml.backend.as_deref() == Some("http");
    println!("openai-privacy (port {port}):");
    println!("  model   : {}", ml.model);
    if http {
        println!(
            "  backend : http -> {}",
            ml.endpoint.as_deref().unwrap_or("(endpoint unset!)")
        );
    }
    println!(
        "  desired : {}{}",
        if ml.enabled { "on" } else { "off" },
        if ml.enabled && ml.required {
            " (required — refuses requests while not ready)"
        } else {
            ""
        }
    );
    let not_ready_consequence = if ml.required {
        "requests are being REFUSED (required = true)"
    } else {
        "masking is regex-only"
    };
    let status = match ml.status.as_str() {
        "ready" => "ready — filtering active".to_string(),
        "loading" => {
            format!("loading — NOT filtering through the model yet; {not_ready_consequence}")
        }
        "failed" => format!(
            "failed — {not_ready_consequence}{}",
            ml.error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        ),
        "disabled" => "disabled".to_string(),
        other => other.to_string(),
    };
    println!("  status  : {status}");
    if ml.status == "ready"
        && let Some(e) = ml.last_runtime_error.as_deref()
    {
        // Loaded recognizer failed at request time; requests are refused while
        // status stays `ready` so the operator sees the runtime failure.
        println!(
            "  \u{26a0} endpoint failing at request time ({} failure(s); requests refused): {e}",
            ml.runtime_failures
        );
    }
    if ml.status == "disabled" {
        println!(
            "  tip: run `/zlauder:privacy model download` once, then `/zlauder:privacy model on`."
        );
    }
    if ml.status == "failed" {
        if http {
            println!(
                "  tip: check the endpoint URL / that the server is up / auth_token_env — \
                 the load probes the endpoint; then retry `/zlauder:privacy model on`."
            );
        } else {
            println!(
                "  tip: check disk space / network, re-run `/zlauder:privacy model download`, \
                 then `/zlauder:privacy model on`."
            );
        }
    }
}

fn apply_enabled(port: u16, root: &str, scope: Scope, on: bool) -> Result<()> {
    if scope == Scope::Session {
        let key =
            key_for(root).context("proxy not running; use --scope project/user to persist")?;
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
            key_for(root).context("proxy not running; use --scope project/user to persist")?;
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
    if let Ok(key) = key_for(root) {
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
            key_for(root).context("proxy not running; use --scope project/user to persist")?;
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

/// Per-entity operator override (`config entity <TYPE> <op>`) — the finer-grained
/// sibling of `apply_category`. Writes `entity_operators[<TYPE>]`, which both GATES the
/// type (`entity_enabled` is true for any keyed type) and sets how it masks — so
/// `on`/`off` work regardless of the type's category (e.g. enable URL masking without
/// turning the whole Network category on). `clear` removes an override (file scope only).
fn apply_entity(port: u16, root: &str, scope: Scope, name: &str, op: &str) -> Result<()> {
    let (name, builtin) = resolve_entity_type(name);
    if !builtin {
        // Not a typo we can prove here — could be a declared `[[custom_replacements]]`
        // type. Pass it through verbatim; at session scope the proxy's PUT validation
        // makes the final call (rejecting a true typo against canonical + declared
        // custom types), and a file-scope write is a no-op until such a rule exists.
        eprintln!(
            "note: '{name}' is not a built-in entity type; it applies only if it matches a declared [[custom_replacements]] entity_type."
        );
    }

    if op.eq_ignore_ascii_case("clear") {
        return clear_entity(port, root, scope, &name);
    }

    let (op_json, op_toml) = entity_operator_value(op)?;

    // Footgun guard (not a block — zlauder's everything-configurable contract): setting a
    // SECRETS-category entity to pass-through reintroduces a credential-exposure path.
    if matches!(op.to_lowercase().as_str(), "off" | "keep")
        && zlauder_engine::Category::Secrets
            .entity_types()
            .contains(&name.as_str())
    {
        eprintln!(
            "WARNING: '{name}' is a Secrets-category entity; '{op}' lets matching values reach the upstream model — this weakens a default-on protection."
        );
    }

    if scope == Scope::Session {
        let key =
            key_for(root).context("proxy not running; use --scope project/user to persist")?;
        // Minimal MERGE patch (not the whole fetched config): the control-plane PUT
        // recurses into `entity_operators`, so this overlays exactly the one key —
        // race-safe (a concurrent edit to another key isn't clobbered by stale GET data)
        // and the proxy validates this delta's key (rejecting a typo).
        let patch = json!({ "entity_operators": { name.clone(): op_json } });
        let snap = admin_put(port, &key, &patch)?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, move |doc| {
        doc["engine"]["entity_operators"][name.as_str()] = toml_edit::value(op_toml);
    })?;
    finish_file_scope(port, scope, root, "reload")
}

/// Remove a per-entity override. Only meaningful at a FILE scope: the live session merge
/// is additive (it cannot delete a key), and a `reload` would reset ALL session state,
/// so a session-only override is cleared by reload/restart, not surgically here.
fn clear_entity(port: u16, root: &str, scope: Scope, name: &str) -> Result<()> {
    if scope == Scope::Session {
        bail!(
            "clearing an override needs a file scope (--scope project/user/local); the live session merge cannot remove a key (a session-only override is dropped on the next reload/restart)"
        );
    }
    let name = name.to_string();
    edit_scope_file(scope, root, move |doc| {
        if let Some(tbl) = doc["engine"]["entity_operators"].as_table_like_mut() {
            tbl.remove(&name);
        }
    })?;
    finish_file_scope(port, scope, root, "reload")
}

/// Resolve a user-supplied entity type to its stored form + whether it is a recognized
/// BUILT-IN (a canonical category member, or the deliberately-uncategorized `DATE_TIME`/
/// `DOMAIN` opt-ins). Built-ins accept an upper-cased convenience (`url` → `URL`); any
/// other input is returned VERBATIM (case-preserved, so a mixed-case custom type isn't
/// mangled) with `false` so the caller can warn / defer to the proxy.
fn resolve_entity_type(name: &str) -> (String, bool) {
    let known = zlauder_engine::Category::canonical_entity_types();
    let is_builtin = |n: &str| known.contains(n) || n == "DATE_TIME" || n == "DOMAIN";
    if is_builtin(name) {
        return (name.to_string(), true);
    }
    let upper = name.to_uppercase();
    if is_builtin(&upper) {
        return (upper, true);
    }
    (name.to_string(), false)
}

/// Parse an entity operator argument into its (JSON for the live PUT, TOML inline table
/// for a file scope) forms. `on` masks with the default reversible token; `off`/`keep`
/// detect-but-pass-through. `broker`/`local` are rejected — those are the registered-
/// secret channel, never a per-entity detection override.
fn entity_operator_value(op: &str) -> Result<(Value, toml_edit::InlineTable)> {
    let (kind, is_mask) = match op.to_lowercase().as_str() {
        "on" | "token" => ("token", false),
        "off" | "keep" => ("keep", false),
        "redact" => ("redact", false),
        "hash" => ("hash", false),
        "mask" => ("mask", true),
        "broker" | "local" => {
            bail!("operator '{op}' is reserved for registered secrets, not a per-entity override")
        }
        other => bail!(
            "unknown operator '{other}'. valid: on, off, token, redact, hash, keep, mask"
        ),
    };
    let mut j = serde_json::Map::new();
    j.insert("kind".into(), json!(kind));
    let mut t = toml_edit::InlineTable::new();
    t.insert("kind", kind.into());
    if is_mask {
        // Default Mask shape (last 4 visible), matching the `[engine.entity_operators]`
        // example; a custom char/from_end is set in TOML directly.
        j.insert("char".into(), json!("*"));
        j.insert("from_end".into(), json!(4));
        t.insert("char", "*".into());
        t.insert("from_end", toml_edit::Value::from(4));
    }
    Ok((Value::Object(j), t))
}

/// After editing a scope file: apply it live (if the proxy is up) via `action`, and
/// report where it was persisted. Most edits use `"reload"` (re-read the files);
/// the master switch uses `"enable"`/`"disable"` because `reload` deliberately
/// preserves the live switch (so an unrelated edit can't flip masking — review F3).
fn finish_file_scope(port: u16, scope: Scope, root: &str, action: &str) -> Result<()> {
    let path = scope_path(scope, root);
    let applied = match key_for(root).and_then(|k| admin_post(port, &k, action)) {
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

#[cfg(test)]
mod entity_tests {
    use super::{entity_operator_value, resolve_entity_type};

    #[test]
    fn resolve_entity_type_marks_builtins_and_passes_custom_verbatim() {
        // canonical category members (incl. the new ones) resolve as built-in, as-is.
        for ok in ["URL", "IP_ADDRESS", "EMAIL_ADDRESS", "US_SSN", "URL_CREDENTIAL"] {
            assert_eq!(resolve_entity_type(ok), (ok.to_string(), true));
        }
        // deliberately-uncategorized opt-ins are recognized built-in keys.
        assert_eq!(resolve_entity_type("DATE_TIME").1, true);
        assert_eq!(resolve_entity_type("DOMAIN").1, true);
        // lowercase convenience upper-cases a built-in.
        assert_eq!(resolve_entity_type("url"), ("URL".to_string(), true));
        // a mixed-case custom type is passed through VERBATIM (not mangled), flagged
        // non-built-in so the caller warns / the proxy validates.
        assert_eq!(
            resolve_entity_type("ProjectCode"),
            ("ProjectCode".to_string(), false)
        );
        // typos resolve as non-built-in (the proxy PUT makes the final call).
        for bad in ["EMIAL", "URLS", "IBAN"] {
            assert_eq!(resolve_entity_type(bad).1, false, "{bad} should be non-builtin");
        }
    }

    #[test]
    fn clear_removes_entity_operator_key_from_toml() {
        let mut doc = "[engine.entity_operators]\nURL = { kind = \"keep\" }\nUS_SSN = { kind = \"redact\" }\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        // Mirror clear_entity's removal.
        if let Some(tbl) = doc["engine"]["entity_operators"].as_table_like_mut() {
            tbl.remove("URL");
        }
        let out = doc.to_string();
        assert!(!out.contains("URL ="), "URL override should be gone: {out}");
        assert!(out.contains("US_SSN"), "other overrides must survive: {out}");
    }

    #[test]
    fn entity_operator_value_maps_on_off_and_named() {
        let kind = |op: &str| {
            entity_operator_value(op)
                .unwrap()
                .0
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        };
        assert_eq!(kind("on"), "token");
        assert_eq!(kind("off"), "keep");
        assert_eq!(kind("token"), "token");
        assert_eq!(kind("redact"), "redact");
        assert_eq!(kind("hash"), "hash");
        assert_eq!(kind("keep"), "keep");
        // case-insensitive
        assert_eq!(kind("OFF"), "keep");

        // mask carries the default char/from_end in BOTH the JSON and TOML forms.
        let (j, t) = entity_operator_value("mask").unwrap();
        assert_eq!(j.get("kind").and_then(|v| v.as_str()), Some("mask"));
        assert_eq!(j.get("char").and_then(|v| v.as_str()), Some("*"));
        assert_eq!(j.get("from_end").and_then(|v| v.as_i64()), Some(4));
        assert_eq!(t.get("kind").and_then(|v| v.as_str()), Some("mask"));
        assert!(t.get("char").is_some() && t.get("from_end").is_some());

        // secrets-channel operators and garbage are rejected.
        for bad in ["broker", "local", "bogus", ""] {
            assert!(entity_operator_value(bad).is_err(), "{bad} should be rejected");
        }
    }

    // The file-scope path writes `doc["engine"]["entity_operators"][TYPE]` — a 3-level
    // nesting. Prove it auto-vivifies under the `engine` table `edit_scope_file`
    // guarantees, renders, and re-parses to the expected operator shape.
    #[test]
    fn entity_operator_toml_nests_and_reparses() {
        let (_j, t) = entity_operator_value("off").unwrap();
        let mut doc = toml_edit::DocumentMut::new();
        doc["engine"] = toml_edit::Item::Table(toml_edit::Table::new());
        doc["engine"]["entity_operators"]["URL"] = toml_edit::value(t);
        let rendered = doc.to_string();
        let reparsed = rendered
            .parse::<toml_edit::DocumentMut>()
            .expect("rendered entity_operators must be valid TOML");
        assert_eq!(
            reparsed["engine"]["entity_operators"]["URL"]["kind"].as_str(),
            Some("keep"),
            "rendered toml: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// reveal
// ---------------------------------------------------------------------------

fn reveal(token: String) -> Result<()> {
    let root = canonical(&project_root());
    let (port, key) = live_identity(&root)
        .context("could not reach this project's proxy — is a `claude` session running here?")?;
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

fn monitor_cmd() -> Result<()> {
    let root = canonical(&project_root());
    let (port, key) = live_identity(&root)
        .context("could not reach this project's proxy — is a `claude` session running here?")?;
    println!("http://127.0.0.1:{port}/zlauder/ui?key={key}");
    Ok(())
}

/// PreToolUse broker resolver (T2). Reads the hook payload from stdin, asks the proxy
/// to resolve allow-listed broker tokens into `tool_input`, and emits `updatedInput`.
/// Every failure path is silent (emit nothing, exit 0) so the tool runs with the
/// broker token unresolved — fail-closed, never a leak.
fn pre_tool_use() -> Result<()> {
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
    // No live, identity-verified proxy ⇒ emit nothing ⇒ tool runs with the token unresolved
    // (fail-closed). One identity round-trip (not two) keeps this per-tool-call hook cheap.
    let Some((port, key)) = live_identity(&root) else {
        return Ok(());
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
    let resolved = out.get("resolved").and_then(Value::as_u64).unwrap_or(0);
    let denials = out.get("denied").and_then(Value::as_array);
    let updated = out.get("tool_input").cloned().unwrap_or(Value::Null);

    let mut hook = serde_json::Map::new();
    hook.insert("hookEventName".into(), json!("PreToolUse"));
    if resolved > 0 && !updated.is_null() {
        hook.insert("updatedInput".into(), updated);
    }
    // Surface (value-free) WHY any allow-listed broker token stayed masked, so the model can
    // tell the user which [[broker.allow]] rule to add. The token is left UNRESOLVED either
    // way (fail-closed) — this only explains; it never reveals the secret's value.
    if let Some(d) = denials.filter(|d| !d.is_empty()) {
        hook.insert("additionalContext".into(), json!(broker_denial_note(d)));
    }
    if hook.len() == 1 {
        return Ok(()); // nothing resolved and nothing denied → no-op
    }
    println!("{}", json!({ "hookSpecificOutput": Value::Object(hook) }));
    Ok(())
}

/// A value-free note (never the resolved secret) explaining which registered broker tokens
/// stayed masked for a tool call and why, for the model to relay to the user. Inputs are the
/// `denied` entries from /zlauder/broker/resolve (pointer + reason category only).
fn broker_denial_note(denials: &[Value]) -> String {
    let mut lines = vec![
        "ZlauDeR kept one or more registered broker secrets MASKED for this tool call (the \
         tool ran with the [TOKEN] in place, not the real value):"
            .to_string(),
    ];
    for d in denials {
        let ptr = d.get("pointer").and_then(Value::as_str).unwrap_or("?");
        let reason = d.get("reason").and_then(Value::as_str).unwrap_or("denied");
        lines.push(format!("  - {ptr}: {reason}"));
    }
    lines.push(
        "To allow it, the USER adds a matching [[broker.allow]] rule (secret + tool + param + \
         dest host) to zlauder.toml and restarts. You can suggest the exact rule, but only the \
         user can apply it — and you never see the secret's value."
            .to_string(),
    );
    lines.join("\n")
}

/// `/zlauder:secrets` — read-only view of the registered-secret gate + status. Pulls
/// the value-free `secrets` block from the proxy snapshot. (Registration is by
/// reference in `[[secrets]]`; secret VALUES never transit this command.)
fn secrets_cmd(action: Option<SecretsAction>) -> Result<()> {
    let root = canonical(&project_root());
    let port = resolve_live_port(&root)?;
    let snap = live_snapshot(port, &root).context("reading secrets status (is the proxy running?)")?;
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

/// This project's live, IDENTITY-VERIFIED proxy: its `(port, admin_key)` from the PROJECT-keyed
/// rendezvous, returned ONLY after a `/healthz` round-trip confirms the serving process echoes
/// the nonce in OUR record. Resolving by project (never an ambient/shared port) scopes the CLI
/// to OUR proxy; the nonce match proves the process on that port is the exact instance that
/// published the record — not a foreign server that grabbed a recycled ephemeral port after a
/// PID-reuse + port-steal. `None` if there is no live, verified proxy. (A hook-launched proxy
/// always carries a nonce, so an empty-nonce manual/legacy record is not trusted.) This mirrors
/// the adoption check in [`ensure_up`]/[`wait_for_live`] — every control-plane consumer routes
/// through it so none can hand the admin key or hook payload to an unverified port.
fn live_identity(root: &str) -> Option<(u16, String)> {
    let (port, rec) = zlauder_state::live_port(root)?;
    if rec.nonce.is_empty() {
        return None;
    }
    let (_build, live_nonce) = proxy_identity(port)?;
    (live_nonce == rec.nonce).then_some((port, rec.admin_key))
}

/// This project's live proxy port (identity-verified; see [`live_identity`]).
fn resolve_live_port(root: &str) -> Result<u16> {
    live_identity(root).map(|(p, _)| p).context(
        "could not find this project's proxy — is a `claude` session running in this \
         project? (start one, or run /zlauder:enable)",
    )
}

/// This project's proxy admin key (identity-verified; see [`live_identity`]). Reading it only
/// from the instance that proves our nonce is what keeps a consumer from ever handing the key
/// to a different/foreign process on a colliding or recycled port.
fn key_for(root: &str) -> Result<String> {
    live_identity(root)
        .map(|(_, k)| k)
        .context("could not read this project's proxy key — is a `claude` session running here?")
}

fn live_snapshot(port: u16, root: &str) -> Result<Value> {
    admin_get(port, &key_for(root)?)
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
        bail!(
            "unknown category '{name}'. valid: secrets, financial, identity, contact, network, personal"
        );
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
    if let Ok(snap) = live_snapshot(port, root)
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
    /// `local` | `http` (absent on older proxies ⇒ local).
    #[serde(default)]
    backend: Option<String>,
    /// The remote endpoint when `backend = "http"`.
    #[serde(default)]
    endpoint: Option<String>,
    /// Strict fail-closed mode: not-Ready ML refuses requests.
    #[serde(default)]
    required: bool,
    /// `disabled` | `loading` | `ready` | `failed` (see `zlauder_engine::MlStatus`).
    #[serde(default)]
    status: String,
    #[serde(default)]
    error: Option<String>,
    /// Post-`Ready` recognizer failure; requests are refused while status stays `ready`.
    #[serde(default)]
    last_runtime_error: Option<String>,
    #[serde(default)]
    runtime_failures: u64,
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
/// applies the route from the project's settings.local.json / settings.json) point at OUR
/// proxy endpoint? Ground truth for "is this session actually masked through us?" — far more
/// reliable than the mere presence of the globally-installed plugin. Accepts an exact match
/// or a base-with-path (`{base}/…`) variant.
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

/// The proxy port this project has baked into `settings.local.json` (or `settings.json`) IF
/// it carries OUR route — a loopback `env.ANTHROPIC_BASE_URL` whose port matches the
/// co-baked `env.ZLAUDER_PORT`. Port-agnostic "is this project plumbed through us" (an
/// ephemeral baked port can't be re-derived), and the co-key match ignores a user's own
/// unrelated base URL.
fn project_baked_route(root: &str) -> Option<u16> {
    for name in [".claude/settings.local.json", ".claude/settings.json"] {
        let path = Path::new(root).join(name);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(strip_bom(&text)) else {
            continue;
        };
        let Some(env) = v.get("env") else { continue };
        let url = env.get("ANTHROPIC_BASE_URL").and_then(|u| u.as_str());
        let zport = env
            .get("ZLAUDER_PORT")
            .and_then(|p| p.as_str())
            .and_then(|s| s.parse::<u16>().ok());
        if let (Some(url), Some(zp)) = (url, zport)
            && loopback_url_port(url) == Some(zp)
        {
            return Some(zp);
        }
    }
    None
}

/// Parse a path-less loopback URL (`http://127.0.0.1:PORT`) → `PORT`. `None` for anything
/// else (a non-loopback host, a URL with a path/query, a non-numeric port).
fn loopback_url_port(url: &str) -> Option<u16> {
    let authority = url.trim().trim_end_matches('/').strip_prefix("http://")?;
    let (host, port) = authority.rsplit_once(':')?;
    if (host != "127.0.0.1" && host != "localhost") || port.contains('/') {
        return None;
    }
    port.parse::<u16>().ok()
}

#[cfg(test)]
mod route_gate_tests {
    use super::*;

    #[test]
    fn loopback_url_port_parses_only_bare_loopback() {
        assert_eq!(loopback_url_port("http://127.0.0.1:41234"), Some(41234));
        assert_eq!(loopback_url_port("http://localhost:8080/"), Some(8080));
        // A path/query is a user URL, not our bare host:port.
        assert_eq!(loopback_url_port("http://127.0.0.1:41234/v1"), None);
        // Non-loopback host, non-http scheme, non-numeric port → None.
        assert_eq!(loopback_url_port("http://192.168.1.5:80"), None);
        assert_eq!(loopback_url_port("https://api.anthropic.com"), None);
        assert_eq!(loopback_url_port("http://127.0.0.1:notaport"), None);
    }

    #[test]
    fn stale_route_messages_are_loud_and_actionable() {
        // Every variant says NOT masked + restart, and (model copy) explicitly forbids a
        // masking claim — never a silent false "active".
        for danger in [StaleRoute::Refused, StaleRoute::Unresponsive, StaleRoute::ForeignResponder] {
            let (_human, model) = stale_route_messages(40000, 40001, danger, true);
            assert!(model.contains("NOT masked"), "{danger:?}: {model}");
            assert!(model.to_lowercase().contains("restart"), "{danger:?}: {model}");
            assert!(model.contains("Never claim masking is active"), "{danger:?}: {model}");
        }
        // The two dangerous variants tell the user to abort NOW.
        let (h, _) = stale_route_messages(40000, 40001, StaleRoute::ForeignResponder, true);
        assert!(h.contains("Ctrl-C") && h.contains("UNMASKED"), "{h}");
        let (h, _) = stale_route_messages(40000, 40001, StaleRoute::Unresponsive, true);
        assert!(h.contains("Ctrl-C") && h.contains("HANG"), "{h}");
    }

    #[test]
    fn classify_stale_route_refused_when_nothing_listens() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        }; // listener dropped → port free → nothing listening
        assert_eq!(classify_stale_route(port), StaleRoute::Refused);
    }

    #[test]
    fn classify_stale_route_detects_responder_and_blackhole() {
        use std::io::{Read, Write};
        // A foreign HTTP responder. NOTE classify_stale_route makes TWO connections (a
        // connect_timeout probe, then the reqwest GET), so the server must loop over
        // connections — handling only one leaves the GET unanswered and looks unresponsive.
        let responder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let rport = responder.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in responder.incoming().flatten() {
                let mut s = conn;
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = s.flush();
            }
        });
        // A black hole: accept every connection but never respond (hold them open).
        let blackhole = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bport = blackhole.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for conn in blackhole.incoming().flatten() {
                held.push(conn); // hold open; never write
            }
        });
        assert_eq!(classify_stale_route(rport), StaleRoute::ForeignResponder);
        assert_eq!(classify_stale_route(bport), StaleRoute::Unresponsive);
    }

    #[test]
    fn project_baked_route_needs_loopback_url_with_matching_zport() {
        let dir = std::env::temp_dir().join(format!("zlauder-baked-{}", std::process::id()));
        let claude = dir.join(".claude");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&claude).unwrap();
        let root = dir.to_string_lossy().into_owned();
        let settings = claude.join("settings.local.json");

        // No settings → None.
        assert_eq!(project_baked_route(&root), None);

        // Our route: loopback URL whose port matches the co-baked ZLAUDER_PORT.
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","ZLAUDER_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(project_baked_route(&root), Some(41999));

        // A user's own base URL (no/with mismatched ZLAUDER_PORT) is NOT ours.
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://gw.corp.example/v1","ZLAUDER_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(project_baked_route(&root), None);

        // URL/port disagreement (stale ZLAUDER_PORT) → not trusted.
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","ZLAUDER_PORT":"40000"}}"#,
        )
        .unwrap();
        assert_eq!(project_baked_route(&root), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Q4: the not-routed statusline state is keyed on the ON-DISK baked route (ground
    /// truth), not a persistent Plumbed registry flag. `port == None` ⇒ not routed ⇒ this
    /// hits the not-routed branch directly, so the check is hermetic (no proxy/env/registry).
    #[test]
    fn render_segment_not_routed_keys_on_baked_route() {
        let dir = std::env::temp_dir().join(format!("zlauder-rseg-q4-{}", std::process::id()));
        let claude = dir.join(".claude");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&claude).unwrap();
        let root = dir.to_string_lossy().into_owned();
        let settings = claude.join("settings.local.json");

        // No route baked on disk → honest "not masking", NEVER a false "restart to mask"
        // (a restart would find no route to apply). Holds even if a Plumbed registry entry
        // existed for this root — the fix makes render_segment registry-independent.
        assert_eq!(
            render_segment(None, &root, SlMode::Compact),
            "\u{2717} ZlauDeR not masking"
        );

        // A route baked into settings.local.json → honest "restart to mask": a restart WILL
        // read and apply it (the legit first-run live-reload window).
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","ZLAUDER_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(
            render_segment(None, &root, SlMode::Compact),
            "\u{27f3} ZlauDeR: restart to mask"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C4: ShieldOnly renders NOTHING in every non-masking state (the inverse of Min, which
    /// always renders a glyph) — so the line appears solely as a positive masking indicator.
    #[test]
    fn shield_only_is_empty_in_non_masking_states() {
        let dir = std::env::temp_dir().join(format!("zlauder-rseg-sh-{}", std::process::id()));
        let claude = dir.join(".claude");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&claude).unwrap();
        let root = dir.to_string_lossy().into_owned();
        let settings = claude.join("settings.local.json");

        // Not routed, no baked route (Compact would show "✗ not masking") → empty.
        assert_eq!(render_segment(None, &root, SlMode::ShieldOnly), "");
        // Not routed, route baked (Compact would show "⟳ restart to mask") → still empty.
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","ZLAUDER_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(render_segment(None, &root, SlMode::ShieldOnly), "");
        // The unverified state (identity mismatch / parse failure) → empty under ShieldOnly.
        assert_eq!(unverified(41999, SlMode::ShieldOnly), "");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C4: `$ZLAUDER_STATUSLINE` aliases map to ShieldOnly, and the ONE state it renders
    /// non-empty is confirmed masking — a bare 🛡 (identical to Min's shield, via render_on).
    #[test]
    fn shield_only_parsing_and_confirmed_render() {
        for s in ["shield", "Shield-Only", " SHIELDONLY ", "quiet"] {
            assert_eq!(sl_mode_from(Some(s)), SlMode::ShieldOnly, "alias {s:?}");
        }
        assert_eq!(sl_mode_from(Some("min")), SlMode::Min);
        assert_eq!(sl_mode_from(Some("off")), SlMode::Off);
        assert_eq!(sl_mode_from(None), SlMode::Compact);

        let snap: Snapshot = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "config": {"profile": "balanced", "score_threshold": 0.5, "enabled_categories": ["contact"]}
        }))
        .unwrap();
        assert_eq!(render_on(&snap, 18820, SlMode::ShieldOnly), "\u{1f6e1}");
        // Compact carries port/profile chrome, so it is NOT the bare shield.
        assert_ne!(render_on(&snap, 18820, SlMode::Compact), "\u{1f6e1}");
    }

    #[test]
    fn intake_gate_blocks_only_plumbed_unrouted_no_escape() {
        // The one BLOCK state: plumbed, not routed, not opted out, no escape hatch.
        assert!(intake_should_block(false, true, false, false));

        // Allowed: already routed this session (masking active / fails-closed at the proxy).
        assert!(!intake_should_block(false, true, true, false));
        // Allowed: not plumbed through us (no masking intent — never gate a foreign project).
        assert!(!intake_should_block(false, false, false, false));
        // Allowed: opted out (sending direct is exactly what opt-out means).
        assert!(!intake_should_block(true, true, false, false));
        // Allowed: the ZLAUDER_NO_INTAKE_GATE escape hatch overrides everything.
        assert!(!intake_should_block(false, true, false, true));
        // Escape hatch wins even over the block state with all other flags set to block.
        assert!(!intake_should_block(false, true, false, true));
    }

    #[test]
    fn first_cwd_in_jsonl_extracts_exact_path_or_none() {
        let dir = std::env::temp_dir().join(format!("zlauder-cwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A summary-only first line (no cwd), then a record carrying the real cwd.
        let log = dir.join("session.jsonl");
        std::fs::write(
            &log,
            "{\"type\":\"summary\",\"leafUuid\":\"x\"}\n\
             {\"type\":\"user\",\"cwd\":\"/home/u/My Project\",\"message\":{}}\n",
        )
        .unwrap();
        assert_eq!(
            first_cwd_in_jsonl(&log),
            Some("/home/u/My Project".to_string())
        );

        // No cwd anywhere → None (never a bogus root for the sweep to act on).
        let nocwd = dir.join("nocwd.jsonl");
        std::fs::write(&nocwd, "{\"type\":\"summary\"}\n{\"type\":\"x\"}\n").unwrap();
        assert_eq!(first_cwd_in_jsonl(&nocwd), None);

        // Whitespace around the colon (pretty-printed key) is tolerated (a raw substring scan for
        // `"cwd":"` would have missed this and skipped a real project).
        let spaced = dir.join("spaced.jsonl");
        std::fs::write(&spaced, "{\"type\":\"user\",\"cwd\": \"/srv/app\"}\n").unwrap();
        assert_eq!(first_cwd_in_jsonl(&spaced), Some("/srv/app".to_string()));

        // A `cwd`-looking substring INSIDE another field must not be mistaken for the key (proper
        // JSON parsing only reads the top-level `cwd`).
        let decoy = dir.join("decoy.jsonl");
        std::fs::write(
            &decoy,
            "{\"type\":\"user\",\"text\":\"\\\"cwd\\\":\\\"/evil\\\"\",\"cwd\":\"/real\"}\n",
        )
        .unwrap();
        assert_eq!(first_cwd_in_jsonl(&decoy), Some("/real".to_string()));

        // An OVERLONG record (> the 256 KiB per-line cap) that carries a decoy `cwd` is drained
        // and skipped — never parsed as a fragment — so the real cwd in the NEXT small record is
        // what's returned. Proves the bounded drain resumes at a true record boundary.
        let overlong = dir.join("overlong.jsonl");
        let huge = "x".repeat(300 * 1024);
        std::fs::write(
            &overlong,
            format!("{{\"big\":\"{huge}\",\"cwd\":\"/decoy\"}}\n{{\"cwd\":\"/real-after\"}}\n"),
        )
        .unwrap();
        assert_eq!(
            first_cwd_in_jsonl(&overlong),
            Some("/real-after".to_string())
        );

        // A COMPLETE final record a writer left WITHOUT a trailing newline is still parsed (the
        // short read hit EOF below the cap, so it's complete — not an overlong-head fragment).
        let unterminated = dir.join("unterminated.jsonl");
        std::fs::write(&unterminated, "{\"type\":\"user\",\"cwd\":\"/no-nl\"}").unwrap();
        assert_eq!(first_cwd_in_jsonl(&unterminated), Some("/no-nl".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_truthy_flag_only_affirmative_values() {
        for t in ["1", "true", "TRUE", "Yes", "on", " on "] {
            assert!(is_truthy_flag(t), "{t:?} should be truthy");
        }
        // A `=0` a user meant as "keep the gate ON" must NOT open the escape hatch.
        for f in ["0", "false", "", "off", "no", "2", "enabled"] {
            assert!(!is_truthy_flag(f), "{f:?} should NOT be truthy");
        }
    }
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
    fn compose_normalizes_blank_segment() {
        // A blank ShieldOnly segment + a real wrapped line => just the wrapped line, with NO
        // stray leading "│" divider (the bug this normalization closes).
        assert_eq!(
            compose_line(Some("".into()), Some("⎇ main".into())),
            "⎇ main"
        );
        // Whitespace-only segment is likewise treated as absent.
        assert_eq!(compose_line(Some("   ".into()), None), "");
        assert_eq!(compose_line(Some("  ".into()), Some("⎇ main".into())), "⎇ main");
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

#[cfg(test)]
mod doctor_tests {
    use super::*;

    #[test]
    fn probes_run_and_classify_sensibly() {
        // Loopback + ephemeral bind work in any sane CI/dev environment.
        assert_eq!(probe_loopback_self_connect().status, ProbeStatus::Pass);
        assert_eq!(probe_ephemeral_bind().status, ProbeStatus::Pass);
        // localhost may resolve v4 or v6 depending on the host — must never be a FAIL.
        assert_ne!(probe_localhost_resolution().status, ProbeStatus::Fail);
        // A bogus project has no rendezvous → Info (not a crash, not a false healthy).
        assert_eq!(
            probe_project_proxy("/no/such/zlauder/project/xyz").status,
            ProbeStatus::Info
        );
        // State dir is writable (uses the default/env dir).
        assert_eq!(probe_state_dir().status, ProbeStatus::Pass);
        // Off Windows the excluded-range probe is skipped.
        #[cfg(not(windows))]
        assert_eq!(probe_windows_excluded_range().status, ProbeStatus::Skip);
        // Status labels are stable (consumed by the JSON output + plugin command).
        assert_eq!(ProbeStatus::Pass.label(), "PASS");
        assert_eq!(ProbeStatus::Fail.label(), "FAIL");
    }
}
