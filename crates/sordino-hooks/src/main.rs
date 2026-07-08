//! sordino-hooks — Claude Code control-plane integration for sordino.
//!
//! Subcommands:
//!   session-start  Launch this project's proxy (if not already running) and emit
//!                  the SessionStart hook JSON that points Claude Code at it. The proxy
//!                  binds an OS-assigned ephemeral port and publishes a per-project
//!                  rendezvous record consumers look up by project root.
//!   statusline     One-line status indicator (on/off + profile).
//!   config         View or change privacy settings (backs `/sordino:privacy`).
//!   reveal <tok>   Audit: decode a token to its plaintext via the running proxy.
//!
//! Per-project routing (writing `ANTHROPIC_BASE_URL` + `SORDINO_PORT` and a status
//! line into `.claude/settings.local.json`, gitignored) is plumbed AUTOMATICALLY by
//! this binary's `session-start` the first time it sees a project (installed = routed),
//! and can also be (re)done explicitly via the plugin's `/sordino:enable`. The plugin is
//! the sole install interface. See `sordino-plugin/`.
//!
//! ## Per-project isolation
//!
//! Each project runs its own proxy on an OS-assigned ephemeral port; consumers find it
//! through a project-identity-keyed rendezvous record (see [`sordino_state::live_port`]),
//! so its key, store, and config are isolated. Two `claude` windows in the same project
//! share the one proxy; different projects never interfere. The bound port is written into
//! each project's `.claude/settings.local.json` (as `ANTHROPIC_BASE_URL` + `SORDINO_PORT`)
//! by auto-plumb / `/sordino:enable`, so the load-bearing path is the static base URL — not
//! a best-effort dynamic env.

use std::io::Read;
use std::net::TcpListener;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sordino_engine::{EngineConfig, Profile};

mod transcript;

#[derive(Parser)]
#[command(name = "sordino-hooks", version, about)]
struct Cli {
    /// Target proxy port. Defaults to `$SORDINO_PORT` (set per project by auto-plumb /
    /// `/sordino:enable`), else the project's live proxy port resolved from its rendezvous record.
    #[arg(long, env = "SORDINO_PORT", global = true)]
    port: Option<u16>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// SessionStart hook: ensure this project's proxy is running.
    SessionStart {
        #[arg(long, env = "SORDINO_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = default_proxy_bin())]
        proxy_bin: String,
    },
    /// Bring this project's proxy up (launch / recycle a stale build) and print the port it
    /// bound on stdout. Used by `/sordino:enable` to learn the OS-assigned ephemeral port to
    /// write into settings.local.json. (Name retained for the shell contract; behaviorally a
    /// bare-port variant of `ensure-up`.)
    ReservePort {
        #[arg(long, env = "SORDINO_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = default_proxy_bin())]
        proxy_bin: String,
    },
    /// Ensure this project's proxy is running (launch or recycle a stale build) and, with
    /// `--print-url`, print its base URL. A standalone way to warm the proxy ahead of time,
    /// and the primitive a future zero-state launcher could exec Claude Code through (passing
    /// the URL via `--settings`, so no persistent settings write is needed).
    EnsureUp {
        #[arg(long, env = "SORDINO_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = default_proxy_bin())]
        proxy_bin: String,
        /// Print the proxy base URL on stdout (for the launcher's `--settings` injection).
        #[arg(long)]
        print_url: bool,
    },
    /// Preflight self-check: probe loopback reachability, localhost IPv4/IPv6, this project's
    /// proxy health, the state dir, and (Windows, static port) excluded ranges. Prints a
    /// pass/fail table (or `--json`) and exits non-zero on any FAIL. Backs `/sordino:doctor`.
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
    /// View or change privacy settings (backs the `/sordino:privacy` command).
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
    /// View registered-secret status (backs `/sordino:secrets`). Read-only — secret
    /// VALUES never appear (registration is by reference in `[[secrets]]`).
    Secrets {
        #[command(subcommand)]
        action: Option<SecretsAction>,
        /// Emit a machine-readable JSON posture projection instead of the human view.
        /// Read-only: reshapes the already-fetched proxy snapshot; never mutates.
        #[arg(long)]
        json: bool,
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
    /// stop routing through) the sordino proxy. Backs auto-plumb, `/sordino:enable`, and
    /// `/sordino:uninstall`, replacing the former shell+jq implementation so the plugin needs no `jq` on PATH
    /// (a hard blocker on Windows). Exit codes are a contract — see `SettingsAction`.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },
    /// Codex preflight: detect whether a usable OpenAI API key is reachable for the masking
    /// proxy's custom provider, and REFUSE (non-zero exit) when not.
    ///
    /// The sordino Codex plugin routes Codex's OpenAI provider through the local masking proxy
    /// by configuring a custom provider with `env_key = "OPENAI_API_KEY"`. A custom provider's
    /// `api_key()` reads ONLY the `OPENAI_API_KEY` ENV var and hard-errors when it is absent or
    /// empty — it does NOT fall back to a ChatGPT-subscription token or to `auth.json`. So if a
    /// user only has ChatGPT-subscription auth (or an API key sitting in `auth.json` but NOT
    /// exported to the env), every Codex request fails at provider construction — nothing is
    /// sent, therefore nothing is masked. This subcommand detects that up front.
    ///
    /// Exit 0 iff a usable env key is present (mode=apikey); non-zero otherwise, with a clear
    /// refusal on stderr. `--json` prints `{"mode": ..., "route_ok": <bool>}` to stdout.
    CodexAuthCheck {
        /// Emit machine-readable JSON (`{"mode": ..., "route_ok": <bool>}`) instead of the
        /// human refusal/confirmation. The exit code is still set (0 iff route_ok).
        #[arg(long)]
        json: bool,
    },
    /// Route (or stop routing) Codex's OpenAI traffic through the masking proxy by editing the
    /// custom-provider block in `$CODEX_HOME/config.toml` (the one writable config layer that
    /// survives Codex's project-config denylist). A format-preserving, atomic, reversible
    /// toml_edit merge — NEVER a `toml::Value` round-trip (that drops the user's comments and
    /// formatting). The block is marked `sordino_managed = true`; a same-id block WITHOUT that
    /// marker is user-owned and is never overwritten/removed. Exit codes mirror `SettingsAction`:
    /// 0 = changed, 3 = no-op (already in the target state), non-zero = error/refusal on stderr.
    ///
    /// NOTE: `enable` writes the `[model_providers.<id>]` block + top-level `model_provider`, and
    /// — when `--hooks-dir` is given — ALSO the ownership-aware `[hooks]` SessionStart/UserPromptSubmit
    /// entries pointing at the plugin scripts; `disable` removes only OUR provider block and hook
    /// entries, preserving any user-owned blocks/hooks.
    CodexConfig {
        #[command(subcommand)]
        action: CodexConfigAction,
    },
    /// Codex SessionStart hook delegate: read the SessionStart payload on stdin, verify whether
    /// THIS Codex session is actually routed through the masking proxy (config route + auth +
    /// /healthz identity + launch-generation), and emit ONLY a schema-valid
    /// `hookSpecificOutput.additionalContext` — a NEUTRAL token-handling onboarding when fully
    /// verified, a warn-only message otherwise, and NEVER an unqualified "masking is active" claim.
    ///
    /// SessionStart fires BEFORE any turn egresses, so the effective route is UNOBSERVABLE here;
    /// the onboarding is the conditional token-contract form, never a live-masking assertion. The
    /// output schema is `deny_unknown_fields`: emitting a top-level `env` key makes the parse FAIL
    /// and the context is silently DROPPED, so we emit NO `env` key. Diagnostics go to stderr;
    /// exit is always 0 in non-error paths (an empty stdout is a valid no-op).
    CodexSessionStart,
    /// Codex UserPromptSubmit hook delegate: the fail-CLOSED Codex intake gate. Reads the
    /// UserPromptSubmit payload on stdin and BLOCKS (`{"decision":"block","reason":<non-empty>}`) an
    /// unmasked Codex prompt UNLESS the session is confirmed routed through OUR live proxy
    /// (config-selects-sordino-loopback AND /healthz identity AND launch-generation), OR the project
    /// is opted out, OR the `SORDINO_NO_INTAKE_GATE` escape hatch is truthy, OR the prompt is a
    /// byte-0 `/sordino:` control command.
    ///
    /// Unlike the Claude gate, an UNCONFIGURED Codex session (no sordino provider) BLOCKs — its PII
    /// would egress unmasked, so there is NO `plumbed` term; `route_confirmed == false ⇒ BLOCK`. The
    /// BLOCK decision is computed entirely from facts checkable AT INTAKE without egress (no A8/inbound
    /// conjunct — that would deadlock turn 1). On an ALLOW it ALSO emits a NON-blocking
    /// `additionalContext` override-warn from the 2nd+ allowed prompt when A8 reports zero inbound for
    /// the session (a likely `-c`/`-p` provider override) — detect+warn only, never a block, and
    /// gracefully absent when A8 is unreachable.
    CodexUserPromptSubmit,
    /// Codex per-session override report (backs the verify skill's A8 line). Performs the
    /// KEY-BEARING authenticated read of `GET /sordino/session/{session_id}/routed` on this
    /// project's verified proxy and prints a one-line human verdict on stdout:
    ///   - `routed`        — inbound from this session reached the proxy recently;
    ///   - `not-routed`    — no inbound from this session (possible `-c`/`-p` override / not-yet-routed);
    ///   - `unavailable`   — A8 endpoint/proxy/key not reachable (older Codex build or proxy down).
    /// A REPORT only: always exits 0, never blocks. The admin key is resolved internally (via the
    /// same nonce-verified proxy identity probe the hook uses) so the skill needs no admin key — a
    /// bare keyless curl would always 403 against this key-gated endpoint.
    CodexSessionRouted {
        /// The raw Codex session/thread UUID (the key A8 indexes inbound `last_seen` by).
        session_id: String,
    },
    /// View or change the ZDR (trusted-routing) posture for THIS session (backs
    /// `/sordino:zdr`). Optional; off unless the user configures `[zdr]` targets.
    Zdr {
        #[command(subcommand)]
        action: Option<ZdrAction>,
        /// Emit a machine-readable JSON posture projection instead of the human view.
        /// Read-only: never engages/disengages ZDR — reshapes the status snapshot only.
        #[arg(long)]
        json: bool,
    },
    /// Turn Sordino masking OFF (backs `/sordino:disable`). Default: THIS conversation
    /// only (session-scoped, in-memory — lifts on the next Claude Code restart).
    /// `--project`: the whole project's master switch. Registered secrets stay masked
    /// either way, and the data policy (categories/profile/threshold) is untouched.
    /// Re-enable with `/sordino:privacy on`.
    Disable {
        /// Turn masking off for the WHOLE project (the master switch) instead of just
        /// this one conversation.
        #[arg(long)]
        project: bool,
    },
}

#[derive(Subcommand)]
enum CodexConfigAction {
    /// Insert/replace `[model_providers.<id>]` (default id `sordino`) pointed at `--url` and set
    /// `model_provider = "<id>"`, preserving the user's PRIOR provider so `disable` can restore
    /// it. REFUSES (writes nothing, non-zero) if a same-id block exists WITHOUT our marker.
    Enable {
        /// Proxy base URL to set as `base_url`, e.g. `http://127.0.0.1:PORT/v1`.
        #[arg(long)]
        url: String,
        /// Provider id (the `[model_providers.<id>]` table key). Defaults to `sordino`.
        #[arg(long = "provider-id")]
        provider_id: Option<String>,
        /// Absolute path to the plugin's `scripts/` dir. When given, enable ALSO installs the
        /// `[[hooks.SessionStart]]` / `[[hooks.UserPromptSubmit]]` entries pointing at
        /// `<hooks-dir>/codex-session-start.sh` and `<hooks-dir>/codex-user-prompt-submit.sh`
        /// (codex >0.140 fires hooks only from $CODEX_HOME). Ownership-aware: our entries are
        /// added alongside any user hooks, never clobbering them. Omit to write routing only.
        #[arg(long = "hooks-dir")]
        hooks_dir: Option<String>,
    },
    /// Remove OUR `[model_providers.<id>]` block (only if it carries `sordino_managed = true`)
    /// and restore the saved prior `model_provider` (or drop the top-level key if none saved).
    Disable {
        /// Provider id to remove. Defaults to `sordino`.
        #[arg(long = "provider-id")]
        provider_id: Option<String>,
    },
    /// Print the effective top-level `model_provider` and `[model_providers.<id>].base_url`.
    Show {
        /// Provider id to inspect. Defaults to `sordino`.
        #[arg(long = "provider-id")]
        provider_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum ZdrAction {
    /// Show this session's ZDR status + configured targets (default).
    Status,
    /// Engage ZDR for this session (uses the `[zdr]` default if no config named).
    /// BREAKS the prompt cache — never automatic.
    On {
        /// The `[zdr]` target name (omit to use the configured default).
        config: Option<String>,
    },
    /// Disengage ZDR (back to the masked Anthropic path). Also breaks the cache.
    Off,
    /// List the configured ZDR targets (names + trust basis + verified flag).
    Config,
}

#[derive(Subcommand)]
enum SettingsAction {
    /// Wire env.ANTHROPIC_BASE_URL + env.SORDINO_PORT and take over the statusLine slot
    /// (wrapping any existing line to the sidecar). A missing settings.local.json is treated
    /// as `{}` (and created). Exit 0 = file changed (caller announces masking activates after a
    /// one-time restart — Claude Code reads a freshly-written route reliably only at startup);
    /// exit 3 = already pointed at this proxy, nothing routing-relevant changed; non-zero
    /// = error (invalid JSON / write failure), message on stderr.
    Enable {
        /// Proxy base URL to bake in, e.g. http://127.0.0.1:18123.
        #[arg(long)]
        url: String,
        /// Port to store as env.SORDINO_PORT. Kept as a STRING (matching the historical
        /// jq behavior) and named `--zport` to avoid colliding with the global --port.
        #[arg(long = "zport")]
        zport: String,
        /// The exact statusLine command string to install.
        #[arg(long)]
        statusline: String,
    },
    /// Remove env.ANTHROPIC_BASE_URL + env.SORDINO_PORT (and drop an emptied env), then
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
        "sordino-proxy.exe".to_string()
    } else {
        "sordino-proxy".to_string()
    }
}

#[derive(Subcommand)]
enum SecretsAction {
    /// Show the readiness gate + resolved/required counts + any unresolved (default).
    Status,
    /// List each registered secret: name, operator, scheme, resolved — never values.
    List,
    /// Read-only, value-free scan of this project's `.env` files for candidate secrets
    /// that are not yet registered. Needs no live proxy; prints only KEY names + paths.
    Scan,
    /// Interactive, per-value opt-in import of `.env` keys into `sordino.toml` as
    /// `[[secrets]]` REFERENCE stanzas. Never auto-registers; prompts for every value.
    Import {
        /// Limit the import to a single `.env` file (default: all `.env`/`.env.*`).
        #[arg(long)]
        file: Option<PathBuf>,
    },
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
    /// Persist to `./sordino.toml` (committed) and apply now if the proxy is up.
    Project,
    /// Persist to `~/.config/sordino/config.toml` (all projects) and apply now.
    User,
    /// Persist to `./sordino.local.toml` (gitignored) and apply now.
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
        Cmd::Secrets { action, json } => secrets_cmd(action, json),
        Cmd::Zdr { action, json } => zdr_cmd(action, json),
        Cmd::Disable { project } => disable_cmd(project),
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
        Cmd::CodexAuthCheck { json } => codex_auth_check_cmd(json),
        Cmd::CodexConfig { action } => codex_config_cmd(action),
        Cmd::CodexSessionStart => codex_session_start_cmd(),
        Cmd::CodexUserPromptSubmit => codex_user_prompt_submit_cmd(),
        Cmd::CodexSessionRouted { session_id } => codex_session_routed_cmd(&session_id),
    }
}

// ---------------------------------------------------------------------------
// codex-auth-check — detect a usable OpenAI API key for Codex's masking-proxy
// custom provider, and REFUSE when not. See `Cmd::CodexAuthCheck` for the
// failure mechanism this guards.
// ---------------------------------------------------------------------------

/// Classification of how Codex auth is set up, from the masking-proxy's point of view.
/// `route_ok` is true ONLY when the custom provider's `env_key="OPENAI_API_KEY"` Bearer
/// lookup will find a usable value — i.e. an exported `sk-` env key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodexAuthMode {
    /// An `sk-`-shaped `$OPENAI_API_KEY` is exported — the provider will read it. route_ok.
    ApiKey,
    /// A ChatGPT subscription (auth_mode=chatgpt / a `tokens` object), or no auth at all.
    /// The provider has no env key to read → fails at construction. NOT route_ok.
    Chatgpt,
    /// An API key is on file in auth.json but NOT exported to the env. The single most
    /// actionable case: the fix is one `export`. NOT route_ok.
    KeyNotExported,
    /// Anything else (personal_access_token, bedrock_api_key, or an unrecognized shape).
    /// Fail-closed. NOT route_ok.
    Other,
}

impl CodexAuthMode {
    /// The stable string the `--json` form and downstream consumers key on.
    fn as_str(self) -> &'static str {
        match self {
            CodexAuthMode::ApiKey => "apikey",
            CodexAuthMode::Chatgpt => "chatgpt",
            CodexAuthMode::KeyNotExported => "key-not-exported",
            CodexAuthMode::Other => "other",
        }
    }
    /// True iff this mode means the custom provider has a usable env key (only `ApiKey`).
    /// Used by tests to assert the mode↔route_ok invariant.
    #[cfg(test)]
    fn route_ok(self) -> bool {
        matches!(self, CodexAuthMode::ApiKey)
    }
}

/// PURE detection: given the `$OPENAI_API_KEY` env value (if any) and the parsed `auth.json`
/// (if any, as a `serde_json::Value`), classify the auth situation. No env mutation, no I/O —
/// directly unit-testable. Returns `(mode, route_ok)`; an optional unmapped-auth_mode note is
/// surfaced by the caller (see [`detect_codex_auth`]).
///
/// Precedence mirrors codex's own `api_key()` lookup: an exported, `sk-`-shaped env key wins
/// outright (rule 1); otherwise we inspect auth.json and ALWAYS fail closed.
fn classify_codex_auth(env_key: Option<&str>, auth_json: Option<&Value>) -> (CodexAuthMode, bool) {
    // Rule 1: an exported, non-empty, sk-shaped env key is exactly what the custom provider's
    // env_key="OPENAI_API_KEY" Bearer lookup reads. Trim to reject whitespace-only values.
    if let Some(k) = env_key {
        let k = k.trim();
        if !k.is_empty() && k.starts_with("sk-") {
            return (CodexAuthMode::ApiKey, true);
        }
        // present-but-not-sk-shaped (or whitespace-only) → fall through to auth.json.
    }

    // Rule 2/3: no usable exported env key. Inspect auth.json (fail closed on anything).
    let Some(auth) = auth_json else {
        // No auth.json (or it was empty/unparseable) → treat as ChatGPT/none. NOT route_ok.
        return (CodexAuthMode::Chatgpt, false);
    };

    let auth_mode = auth
        .get("auth_mode")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let has_api_key_field = auth
        .get("OPENAI_API_KEY")
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let has_tokens = auth.get("tokens").map(|t| !t.is_null()).unwrap_or(false);
    let has_pat = auth
        .get("personal_access_token")
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let has_bedrock = auth.get("bedrock_api_key").map(|b| !b.is_null()).unwrap_or(false);

    // An API key on file (field present, or auth_mode==apikey) but NOT exported to the env:
    // the most actionable refusal. The env key was already checked above and is unusable.
    if has_api_key_field || auth_mode == Some("apikey") {
        return (CodexAuthMode::KeyNotExported, false);
    }
    if auth_mode == Some("chatgpt") || has_tokens {
        return (CodexAuthMode::Chatgpt, false);
    }
    if auth_mode == Some("personal_access_token") || has_pat {
        return (CodexAuthMode::Other, false);
    }
    if auth_mode == Some("bedrock_api_key") || has_bedrock {
        return (CodexAuthMode::Other, false);
    }

    // Unrecognized auth_mode / shape the detector cannot classify → fail closed.
    (CodexAuthMode::Other, false)
}

/// Was the auth.json's `auth_mode` an UNMAPPED value (one we don't classify by name and that
/// didn't otherwise match a known field)? The caller surfaces this on stderr so an unexpected
/// codex auth mode can be reported. Returns the offending string when so.
fn unmapped_auth_mode(auth_json: Option<&Value>) -> Option<String> {
    let auth = auth_json?;
    let am = auth
        .get("auth_mode")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    const KNOWN: &[&str] = &[
        "apikey",
        "chatgpt",
        "personal_access_token",
        "bedrock_api_key",
    ];
    if KNOWN.contains(&am) {
        return None;
    }
    // An unknown auth_mode that nevertheless carried a recognized field is already classified
    // by that field — not "unmapped". Only flag when nothing else matched it.
    let classifiable_by_field = auth
        .get("OPENAI_API_KEY")
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
        || auth.get("tokens").map(|t| !t.is_null()).unwrap_or(false)
        || auth
            .get("personal_access_token")
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        || auth.get("bedrock_api_key").map(|b| !b.is_null()).unwrap_or(false);
    if classifiable_by_field {
        None
    } else {
        Some(am.to_string())
    }
}

/// Read + parse `$CODEX_HOME/auth.json` (CODEX_HOME defaults to `~/.codex`), non-panicking.
/// ANY read/parse failure (missing file, bad JSON, no home dir) degrades to `None` — which the
/// pure classifier treats as the safe REFUSE path.
fn read_codex_auth_json() -> Option<Value> {
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".codex")))?;
    let path = codex_home.join("auth.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str::<Value>(&raw).ok()
}

/// Best-effort home directory from the environment ($HOME on Unix, $USERPROFILE on Windows).
/// No external crate; returns `None` rather than panicking when unset.
fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let var = "USERPROFILE";
    #[cfg(not(windows))]
    let var = "HOME";
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Run the live detection: read the real `$OPENAI_API_KEY` env + `auth.json`, classify, and
/// surface any unmapped auth_mode note. Returns `(mode, route_ok, unmapped_note)`.
fn detect_codex_auth() -> (CodexAuthMode, bool, Option<String>) {
    let env_key = std::env::var("OPENAI_API_KEY").ok();
    let auth = read_codex_auth_json();
    let (mode, route_ok) = classify_codex_auth(env_key.as_deref(), auth.as_ref());
    let note = unmapped_auth_mode(auth.as_ref());
    (mode, route_ok, note)
}

/// The shared refusal text printed to stderr for every `route_ok==false` case. Explains the
/// REAL mechanism so a user knows why their ChatGPT login won't work and what to do.
fn codex_refusal_message(mode: CodexAuthMode) -> String {
    let specific = match mode {
        CodexAuthMode::KeyNotExported => {
            "You have an OpenAI API key on file (auth.json) but it is not exported as the \
             OPENAI_API_KEY environment variable. The Codex custom provider reads the ENV var, \
             not auth.json — export it (export OPENAI_API_KEY=sk-...) before launching codex, \
             then re-run enable.\n\n"
        }
        CodexAuthMode::Chatgpt => {
            "Detected a ChatGPT-subscription login (or no OpenAI auth at all).\n\n"
        }
        CodexAuthMode::Other => {
            "Detected an OpenAI auth mode that does not export an OPENAI_API_KEY env var \
             (e.g. a personal access token or Bedrock key).\n\n"
        }
        CodexAuthMode::ApiKey => "", // unreachable for route_ok==false
    };
    format!(
        "{specific}sordino masking cannot be enabled for Codex with this auth. The masking \
         proxy routes Codex's OpenAI provider through a custom provider whose \
         env_key=OPENAI_API_KEY. When that env var has no value, codex fails at provider \
         construction with a missing-OPENAI_API_KEY env error — it never falls back to your \
         ChatGPT login — so the session cannot make ANY requests, and nothing is masked because \
         nothing is sent.\n\n\
         Fix: set OPENAI_API_KEY to a real OpenAI API key (sk-...) and re-run enable.\n  \
         export OPENAI_API_KEY=sk-...",
    )
}

/// `sordino-hooks codex-auth-check [--json]`. Exit 0 iff a usable exported env key is present;
/// non-zero (with a refusal on stderr) otherwise.
fn codex_auth_check_cmd(json: bool) -> Result<()> {
    let (mode, route_ok, unmapped) = detect_codex_auth();

    // Always surface an unmapped auth_mode on stderr so it can be reported, regardless of form.
    if let Some(am) = &unmapped {
        eprintln!(
            "note: unrecognized codex auth_mode {am:?} in auth.json — treating as unusable \
             (fail-closed). Please report this auth_mode."
        );
    }

    if json {
        println!(
            "{}",
            json!({ "mode": mode.as_str(), "route_ok": route_ok })
        );
        // Belt-and-suspenders: even in --json mode, surface the refusal mechanism on stderr
        // (stdout stays JSON-only) so anyone running this directly sees WHY route_ok is false.
        if !route_ok {
            eprintln!("{}", codex_refusal_message(mode));
        }
    } else if route_ok {
        println!("codex-auth-check: OK (mode=apikey) — OPENAI_API_KEY is exported; the masking proxy can route Codex.");
    } else {
        eprintln!("{}", codex_refusal_message(mode));
    }

    if route_ok {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// codex-config — route Codex's OpenAI provider through the masking proxy by editing
// $CODEX_HOME/config.toml. Format-preserving, atomic, reversible (toml_edit, never a
// toml::Value round-trip). See `Cmd::CodexConfig`.
// ---------------------------------------------------------------------------

/// Default provider id (the `[model_providers.<id>]` table key) when `--provider-id` is absent.
const CODEX_DEFAULT_PROVIDER_ID: &str = "sordino";
/// The ownership marker key. Only a block carrying `<MARKER> = true` is ours to replace/remove.
const SORDINO_MANAGED_KEY: &str = "sordino_managed";
/// Where the prior top-level `model_provider` is stashed (inside our block) so disable restores it.
const SORDINO_PRIOR_KEY: &str = "sordino_prior_provider";

/// Outcome of the pure `codex_enable_merge` / `codex_disable_merge` transforms, mapped to the
/// shell exit-code contract: `Changed` => exit 0, `NoOp` => exit 3, `Refused` => non-zero error.
enum CodexMergeOutcome {
    /// A change was produced; carries the new full config text to write atomically.
    Changed(String),
    /// Already in the target state — write nothing, exit 3.
    NoOp,
    /// Refused (a user-owned same-id block blocks us). Carries the stderr message; write nothing.
    Refused(String),
}

/// Resolve `$CODEX_HOME` (default `~/.codex`) → its `config.toml`. Mirrors `read_codex_auth_json`'s
/// CODEX_HOME resolution so auth-check and config write agree on the same home.
fn codex_config_path() -> Result<PathBuf> {
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".codex")))
        .context("cannot resolve $CODEX_HOME (no CODEX_HOME env and no home dir)")?;
    Ok(codex_home.join("config.toml"))
}

/// Is `[model_providers.<id>]` present AND carrying our `sordino_managed = true` marker?
/// Returns `(present, ours)`: `present` = a table exists under that id at all; `ours` = it
/// exists and the marker is `true`. An UNMARKED present block is user-owned (`present && !ours`).
fn codex_block_ownership(doc: &toml_edit::DocumentMut, id: &str) -> (bool, bool) {
    let Some(providers) = doc.get("model_providers").and_then(|i| i.as_table_like()) else {
        return (false, false);
    };
    let Some(block) = providers.get(id).and_then(|i| i.as_table_like()) else {
        return (false, false);
    };
    let ours = block
        .get(SORDINO_MANAGED_KEY)
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_bool())
        == Some(true);
    (true, ours)
}

/// PURE enable transform: given the current config text + id + url, return the merge outcome.
/// Refuses if a same-id block exists without our marker; no-ops if already in the exact target
/// state; otherwise inserts/replaces our block (preserving every other key + comment + format).
fn codex_enable_merge(current: &str, id: &str, url: &str) -> CodexMergeOutcome {
    let mut doc = match current.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return CodexMergeOutcome::Refused(format!(
                "$CODEX_HOME/config.toml is not valid TOML; refusing to overwrite: {e}"
            ));
        }
    };

    let (present, ours) = codex_block_ownership(&doc, id);
    if present && !ours {
        return CodexMergeOutcome::Refused(format!(
            "a [model_providers.{id}] block already exists in $CODEX_HOME/config.toml and is NOT \
             managed by sordino. Refusing to overwrite it. Pick a different id with --provider-id, \
             or remove your existing [model_providers.{id}] block first."
        ));
    }

    // Capture the user's PRIOR top-level model_provider BEFORE we change it. Only meaningful when
    // it exists and differs from <id> AND we have not already stashed one (idempotency: a re-enable
    // must not clobber a previously-saved prior with our own id).
    let prior_provider = doc
        .get("model_provider")
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let already_saved_prior = doc
        .get("model_providers")
        .and_then(|i| i.as_table_like())
        .and_then(|p| p.get(id))
        .and_then(|i| i.as_table_like())
        .and_then(|b| b.get(SORDINO_PRIOR_KEY))
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Idempotency: the EXACT target state already present → no-op. We compare the FULL set of
    // load-bearing keys (not just provider+url): a marked block missing supports_websockets=false
    // (e.g. written by an older plugin version, or a partial/tampered block) must be RE-WRITTEN,
    // not no-op'd — otherwise the session would silently use the WebSocket transport that bypasses
    // the HTTP masking proxy. (sordino_prior_provider is preserved on a re-enable.)
    if ours {
        let cur_provider = doc
            .get("model_provider")
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_str());
        let block = doc
            .get("model_providers")
            .and_then(|i| i.as_table_like())
            .and_then(|p| p.get(id))
            .and_then(|i| i.as_table_like());
        let block_matches_target = block.is_some_and(|b| {
            let s = |k: &str| b.get(k).and_then(|i| i.as_value()).and_then(|v| v.as_str());
            let f = |k: &str| b.get(k).and_then(|i| i.as_value()).and_then(|v| v.as_bool());
            s("base_url") == Some(url)
                && s("wire_api") == Some("responses")
                && s("env_key") == Some("OPENAI_API_KEY")
                && f("requires_openai_auth") == Some(false)
                && f("supports_websockets") == Some(false)
        });
        if cur_provider == Some(id) && block_matches_target {
            return CodexMergeOutcome::NoOp;
        }
    }

    // Decide which prior to record. Prefer a prior we ALREADY saved (re-enable preserves it);
    // else the live top-level model_provider when it exists and differs from <id>.
    let prior_to_record: Option<String> = already_saved_prior.or_else(|| {
        prior_provider
            .filter(|p| p != id)
    });

    // Build the managed block fresh (a replace drops any stale keys the user couldn't have set on
    // our marked block). Order keys deterministically for the worked-trace test.
    let mut block = toml_edit::Table::new();
    block["name"] = toml_edit::value("Sordino Masking Proxy");
    block["base_url"] = toml_edit::value(url);
    block["env_key"] = toml_edit::value("OPENAI_API_KEY");
    block["wire_api"] = toml_edit::value("responses");
    block["requires_openai_auth"] = toml_edit::value(false);
    block["supports_websockets"] = toml_edit::value(false);
    block[SORDINO_MANAGED_KEY] = toml_edit::value(true);
    if let Some(prior) = prior_to_record {
        block[SORDINO_PRIOR_KEY] = toml_edit::value(prior);
    }

    // Ensure the `[model_providers]` parent table exists, then set our sub-table.
    if !doc.contains_key("model_providers") {
        doc["model_providers"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["model_providers"][id] = toml_edit::Item::Table(block);
    doc["model_provider"] = toml_edit::value(id);

    CodexMergeOutcome::Changed(doc.to_string())
}

/// PURE disable transform: remove OUR marked `[model_providers.<id>]` block and restore the saved
/// prior model_provider (or drop the top-level key if none saved and it equals <id>). A no-op when
/// there is no marked block (an unmarked user block is left untouched).
fn codex_disable_merge(current: &str, id: &str) -> CodexMergeOutcome {
    let mut doc = match current.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return CodexMergeOutcome::Refused(format!(
                "$CODEX_HOME/config.toml is not valid TOML; refusing to overwrite: {e}"
            ));
        }
    };

    let (_present, ours) = codex_block_ownership(&doc, id);
    if !ours {
        // No managed block to remove (absent, or a user-owned unmarked block we must not touch).
        return CodexMergeOutcome::NoOp;
    }

    // Pull the saved prior provider out of our block before removing it.
    let saved_prior = doc
        .get("model_providers")
        .and_then(|i| i.as_table_like())
        .and_then(|p| p.get(id))
        .and_then(|i| i.as_table_like())
        .and_then(|b| b.get(SORDINO_PRIOR_KEY))
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Remove our sub-table.
    if let Some(providers) = doc
        .get_mut("model_providers")
        .and_then(|i| i.as_table_like_mut())
    {
        providers.remove(id);
    }
    // Drop an emptied `[model_providers]` parent so we don't leave a dangling empty table.
    let providers_empty = doc
        .get("model_providers")
        .and_then(|i| i.as_table_like())
        .map(|t| t.is_empty())
        .unwrap_or(false);
    if providers_empty {
        doc.remove("model_providers");
    }

    // Restore the top-level model_provider — but ONLY if it STILL points at us. If the user changed
    // `model_provider` to a different provider AFTER enabling (a newer selection), do NOT clobber it
    // with the stale prior we saved; leave their choice untouched.
    let currently_ours = doc
        .get("model_provider")
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())
        == Some(id);
    if currently_ours {
        match saved_prior {
            // It still points at us: restore the prior we recorded, or drop the key if none saved.
            Some(prior) => doc["model_provider"] = toml_edit::value(prior),
            None => {
                doc.remove("model_provider");
            }
        }
    }

    CodexMergeOutcome::Changed(doc.to_string())
}

/// The two Codex hook events we wire (SessionStart + UserPromptSubmit) paired with the script name
/// of the wrapper that handles each. Ownership on disable is determined by matching a hook command
/// against the trailing `scripts/<name>` path components (see `codex_hook_command_is_ours`) — so
/// removing OUR entries never touches a user's own hooks.
const CODEX_HOOK_SCRIPTS: &[(&str, &str)] = &[
    ("SessionStart", "codex-session-start.sh"),
    ("UserPromptSubmit", "codex-user-prompt-submit.sh"),
];

/// Does `command` reference one of OUR hook scripts? Ownership is a PATH-COMPONENT match on the
/// trailing `scripts/<script>` (the last two components must be exactly `scripts` then `<script>`),
/// robust to whatever absolute `hooks-dir` the plugin resolved (enable always writes
/// `<hooks_dir>/<script>` with `hooks_dir` ending in `/scripts`). A user hook with a different name,
/// a bare command, or one under a directory merely *ending* in "scripts" is foreign and preserved.
fn codex_hook_command_is_ours(command: &str, script: &str) -> bool {
    // PATH-COMPONENT match: the command's last two path components must be exactly `scripts` then
    // `<script>` (split on either separator). `enable` always writes `<hooks_dir>/<script>` with
    // hooks_dir ending in `/scripts`, so our own entries always match. This rejects a bare `<script>`
    // (no `scripts` parent) AND a user hook under a directory whose basename merely ENDS in "scripts"
    // (e.g. `/home/u/user-scripts/<script>`) — a plain `ends_with("scripts/<script>")` would
    // false-claim that as ours and let enable rewrite / disable delete a foreign user hook.
    let mut comps = command.rsplit(['/', '\\']);
    comps.next() == Some(script) && comps.next() == Some("scripts")
}

/// PURE [hooks]-merge for ENABLE: given the current config text and the absolute `hooks_dir`,
/// idempotently add a `[[hooks.SessionStart]]` / `[[hooks.UserPromptSubmit]]` MatcherGroup whose
/// single command is `<hooks_dir>/<script>`, ONLY when no existing entry for that event already
/// carries OUR command (by basename). User hook entries are preserved untouched. Returns the new
/// full config text and whether anything changed. Text in → (text, changed) out, for unit testing
/// without a real $CODEX_HOME.
fn codex_hooks_enable_merge(current: &str, hooks_dir: &str) -> (String, bool) {
    let mut doc = match current.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        // An unparseable doc is handled (refused) by the provider merge that runs first; if we ever
        // reach here on bad TOML, make no change rather than panic.
        Err(_) => return (current.to_string(), false),
    };
    let dir = hooks_dir.trim_end_matches(['/', '\\']);
    let mut changed = false;

    if !doc.contains_key("hooks") {
        // Lazily created only if we actually add something below; defer until first insert.
    }

    for (event, script) in CODEX_HOOK_SCRIPTS {
        let command = format!("{dir}/{script}");

        // NORMALIZE a present-but-wrong-shape event value into an array-of-tables BEFORE we reconcile
        // or append. TOML lets the user write this event two equivalent ways:
        //   [[hooks.SessionStart]]            (toml_edit: ArrayOfTables — what we emit)
        //   SessionStart = [ { ... } ]        (toml_edit: an inline Array of inline tables)
        // Both are valid Codex config, but `as_array_of_tables_mut()` returns None for the second.
        // Without this step the reconcile loop below never sees the user's inline entries (found_ours
        // stays false) AND the append guard short-circuits (`contains_key(event)` is true, yet
        // `as_array_of_tables_mut()` is None) — so OUR hook is silently dropped while `changed` may
        // already be true from the other event/provider, making enable.sh report a success/restart
        // for a hook that was never installed. Rewriting the inline array as an array-of-tables
        // preserves every user entry and lets both the reconcile and append paths operate on it.
        if let Some(hooks_tbl) = doc.get_mut("hooks").and_then(|h| h.as_table_mut()) {
            let needs_normalize = hooks_tbl
                .get(event)
                .map(|i| i.as_array().is_some() && i.as_array_of_tables().is_none())
                .unwrap_or(false);
            if needs_normalize {
                let mut normalized = toml_edit::ArrayOfTables::new();
                if let Some(arr) = hooks_tbl.get(event).and_then(|i| i.as_array()) {
                    for v in arr.iter() {
                        // Re-home each inline table as a standalone table; skip any non-table member
                        // (a malformed entry Codex would itself reject) rather than fail the merge.
                        if let Some(it) = v.as_inline_table() {
                            normalized.push(it.clone().into_table());
                        }
                    }
                }
                hooks_tbl.insert(event, toml_edit::Item::ArrayOfTables(normalized));
            }
        }

        // Reconcile any EXISTING entry that carries OUR script (by basename). Two cases:
        //   - its command already equals our DESIRED absolute path  → already correct, skip;
        //   - it carries our basename but a DIFFERENT (stale) path   → UPDATE it in place to the new
        //     path and mark changed. This is the re-install case (a versioned/content-addressed
        //     CLAUDE_PLUGIN_ROOT changes the absolute dir): a basename-only "already ours → continue"
        //     would silently leave the stale, now-nonexistent path wired, so the hooks stop firing.
        let mut found_ours = false;
        let mut updated = false;
        if let Some(arr) = doc
            .get_mut("hooks")
            .and_then(|h| h.as_table_mut())
            .and_then(|h| h.get_mut(event))
            .and_then(|i| i.as_array_of_tables_mut())
        {
            for grp in arr.iter_mut() {
                let Some(inner) = grp.get_mut("hooks").and_then(|i| i.as_array_mut()) else {
                    continue;
                };
                for h in inner.iter_mut() {
                    let Some(t) = h.as_inline_table_mut() else {
                        continue;
                    };
                    let is_ours = t
                        .get("command")
                        .and_then(|v| v.as_str())
                        .map(|c| codex_hook_command_is_ours(c, script))
                        .unwrap_or(false);
                    if !is_ours {
                        continue;
                    }
                    found_ours = true;
                    let current_cmd = t.get("command").and_then(|v| v.as_str());
                    if current_cmd != Some(command.as_str()) {
                        t.insert("command", command.clone().into());
                        updated = true;
                    }
                }
            }
        }
        if found_ours {
            // Our entry already exists; we either left it (correct path) or rewrote its command.
            changed |= updated;
            continue;
        }

        // Build our MatcherGroup: { matcher = "*", hooks = [{ type = "command", command = ... }] }.
        let mut hook = toml_edit::InlineTable::new();
        hook.insert("type", "command".into());
        hook.insert("command", command.into());
        let mut inner = toml_edit::Array::new();
        inner.push(toml_edit::Value::InlineTable(hook));
        let mut group = toml_edit::Table::new();
        group["matcher"] = toml_edit::value("*");
        group["hooks"] = toml_edit::value(inner);

        // Ensure [hooks] exists, then append to (or create) the event's array-of-tables.
        if !doc.contains_key("hooks") {
            doc["hooks"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let hooks_tbl = doc["hooks"].as_table_mut().expect("hooks is a table");
        if !hooks_tbl.contains_key(event) {
            hooks_tbl.insert(event, toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
        }
        if let Some(arr) = hooks_tbl.get_mut(event).and_then(|i| i.as_array_of_tables_mut()) {
            arr.push(group);
            changed = true;
        }
    }

    if changed {
        (doc.to_string(), true)
    } else {
        (current.to_string(), false)
    }
}

/// PURE [hooks]-merge for DISABLE: remove ONLY the MatcherGroups whose command references one of
/// OUR scripts (matched by basename), preserving every user hook entry. If removing our group
/// empties an event's array, drop the now-empty array; if that empties `[hooks]`, drop it too.
/// Returns the new full config text and whether anything changed.
fn codex_hooks_disable_merge(current: &str) -> (String, bool) {
    let mut doc = match current.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(_) => return (current.to_string(), false),
    };
    let mut changed = false;

    for (event, script) in CODEX_HOOK_SCRIPTS {
        let Some(hooks_tbl) = doc.get_mut("hooks").and_then(|i| i.as_table_mut()) else {
            continue;
        };
        // Mirror enable's normalization so disable also reaches OUR entry when the event is written
        // as an inline `SessionStart = [ {...} ]` array instead of `[[hooks.SessionStart]]`. Only
        // normalize when OUR script is actually present in that inline array — otherwise we'd rewrite
        // a purely-user inline array and spuriously report `changed` for a no-op disable.
        let inline_has_ours = hooks_tbl
            .get(event)
            .filter(|i| i.as_array_of_tables().is_none())
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter().any(|v| {
                    v.as_inline_table()
                        .and_then(|t| t.get("hooks"))
                        .and_then(|h| h.as_array())
                        .map(|inner| {
                            inner.iter().any(|h| {
                                h.as_inline_table()
                                    .and_then(|t| t.get("command"))
                                    .and_then(|v| v.as_str())
                                    .map(|c| codex_hook_command_is_ours(c, script))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if inline_has_ours {
            let mut normalized = toml_edit::ArrayOfTables::new();
            if let Some(arr) = hooks_tbl.get(event).and_then(|i| i.as_array()) {
                for v in arr.iter() {
                    if let Some(it) = v.as_inline_table() {
                        normalized.push(it.clone().into_table());
                    }
                }
            }
            hooks_tbl.insert(event, toml_edit::Item::ArrayOfTables(normalized));
        }
        let Some(arr) = hooks_tbl.get_mut(event).and_then(|i| i.as_array_of_tables_mut()) else {
            continue;
        };
        // Remove ONLY our hook entries from each group's `hooks` list, preserving any co-located
        // USER hooks. Do NOT drop a whole MatcherGroup just because it also contains one of ours —
        // that would delete a user hook sharing the group. The inner `hooks` may be either an inline
        // array (`hooks = [ {..} ]`, the form `enable` writes) OR an array-of-tables
        // (`[[..hooks]]`, a valid user-authored shape) — handle both.
        for grp in arr.iter_mut() {
            let Some(item) = grp.get_mut("hooks") else {
                continue;
            };
            if let Some(inner) = item.as_array_mut() {
                let before = inner.len();
                inner.retain(|h| {
                    !h.as_inline_table()
                        .and_then(|t| t.get("command"))
                        .and_then(|v| v.as_str())
                        .map(|c| codex_hook_command_is_ours(c, script))
                        .unwrap_or(false)
                });
                if inner.len() != before {
                    changed = true;
                }
            } else if let Some(inner) = item.as_array_of_tables_mut() {
                let before = inner.len();
                inner.retain(|t| {
                    !t.get("command")
                        .and_then(|v| v.as_value())
                        .and_then(|v| v.as_str())
                        .map(|c| codex_hook_command_is_ours(c, script))
                        .unwrap_or(false)
                });
                if inner.len() != before {
                    changed = true;
                }
            }
        }
        // Drop groups whose `hooks` list is now empty (ours was the only entry); keep groups that
        // still hold user hooks, and groups with no `hooks` key (an untouched user shape).
        arr.retain(|grp| {
            grp.get("hooks")
                .map(|i| {
                    if let Some(a) = i.as_array() {
                        !a.is_empty()
                    } else if let Some(a) = i.as_array_of_tables() {
                        !a.is_empty()
                    } else {
                        true // unknown shape → keep (do not silently drop a user's group)
                    }
                })
                .unwrap_or(true)
        });
        // Drop the now-empty event array.
        if arr.is_empty() {
            hooks_tbl.remove(event);
        }
    }

    // Drop an emptied [hooks] parent.
    let hooks_empty = doc
        .get("hooks")
        .and_then(|i| i.as_table_like())
        .map(|t| t.is_empty())
        .unwrap_or(false);
    if hooks_empty {
        doc.remove("hooks");
    }

    if changed {
        (doc.to_string(), true)
    } else {
        (current.to_string(), false)
    }
}

/// Atomically write `text` to `path` via a same-dir temp + rename (mirrors `atomic_write_json`'s
/// durability contract for the TOML target). Creates the parent dir if absent.
fn atomic_write_text(path: &Path, text: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".config.toml.tmp-{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, text.as_bytes()) {
        return Err(e).with_context(|| format!("writing {}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replacing {}", path.display()));
    }
    Ok(())
}

/// `sordino-hooks codex-config {enable,disable,show}`. Exit 0 = changed, 3 = no-op, non-zero =
/// error/refusal. The merges are pure (`codex_enable_merge`/`codex_disable_merge`); this only does
/// the I/O (read CODEX_HOME, apply, atomic write) + the exit-code mapping.
fn codex_config_cmd(action: CodexConfigAction) -> Result<()> {
    match action {
        CodexConfigAction::Enable {
            url,
            provider_id,
            hooks_dir,
        } => {
            let id = provider_id.as_deref().unwrap_or(CODEX_DEFAULT_PROVIDER_ID);
            let path = codex_config_path()?;
            // Distinguish "no file yet" (enable creates one) from an UNREADABLE existing file
            // (permission error / invalid UTF-8). Swallowing the latter to an empty doc would let
            // the atomic write replace — and silently destroy — the user's real config, violating
            // the non-destructive-merge contract. Mirror the Disable path below.
            let current = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            };
            // Provider merge first (it owns the unparseable-TOML refusal). Then layer the hooks
            // merge onto the resulting text. A run that changes EITHER the provider block or the
            // [hooks] entries is Changed (exit 0); only an all-no-op run is exit 3.
            let (after_provider, provider_changed) = match codex_enable_merge(&current, id, &url) {
                CodexMergeOutcome::Changed(out) => (out, true),
                CodexMergeOutcome::NoOp => (current.clone(), false),
                CodexMergeOutcome::Refused(msg) => bail!(msg),
            };
            let (final_text, hooks_changed) = match hooks_dir {
                Some(ref dir) => codex_hooks_enable_merge(&after_provider, dir),
                None => (after_provider, false),
            };
            if provider_changed || hooks_changed {
                atomic_write_text(&path, &final_text)?;
                Ok(())
            } else {
                std::process::exit(3)
            }
        }
        CodexConfigAction::Disable { provider_id } => {
            let id = provider_id.as_deref().unwrap_or(CODEX_DEFAULT_PROVIDER_ID);
            let path = codex_config_path()?;
            let current = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // No file → nothing to disable.
                    std::process::exit(3);
                }
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            };
            // Remove the provider block (owns the unparseable refusal), then strip OUR hook
            // entries. Changed if EITHER changed; an all-no-op run is exit 3.
            let (after_provider, provider_changed) = match codex_disable_merge(&current, id) {
                CodexMergeOutcome::Changed(out) => (out, true),
                CodexMergeOutcome::NoOp => (current.clone(), false),
                CodexMergeOutcome::Refused(msg) => bail!(msg),
            };
            let (final_text, hooks_changed) = codex_hooks_disable_merge(&after_provider);
            if provider_changed || hooks_changed {
                atomic_write_text(&path, &final_text)?;
                Ok(())
            } else {
                std::process::exit(3)
            }
        }
        CodexConfigAction::Show { provider_id } => {
            let id = provider_id.as_deref().unwrap_or(CODEX_DEFAULT_PROVIDER_ID);
            let path = codex_config_path()?;
            let current = std::fs::read_to_string(&path).unwrap_or_default();
            let doc = current
                .parse::<toml_edit::DocumentMut>()
                .unwrap_or_else(|_| toml_edit::DocumentMut::new());
            let provider = doc
                .get("model_provider")
                .and_then(|i| i.as_value())
                .and_then(|v| v.as_str())
                .unwrap_or("(unset)");
            let base_url = doc
                .get("model_providers")
                .and_then(|i| i.as_table_like())
                .and_then(|p| p.get(id))
                .and_then(|i| i.as_table_like())
                .and_then(|b| b.get("base_url"))
                .and_then(|i| i.as_value())
                .and_then(|v| v.as_str())
                .unwrap_or("(unset)");
            println!("model_provider = {provider}");
            println!("model_providers.{id}.base_url = {base_url}");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// codex-session-start — the SessionStart hook verification delegate. Verifies the
// config route + auth + /healthz identity + launch-generation, and emits ONLY a
// schema-valid `hookSpecificOutput.additionalContext`: a NEUTRAL token-handling
// onboarding when fully verified, a warn-only message otherwise — NEVER an
// unqualified active-masking claim (SessionStart precedes egress, so the effective
// route is unobservable). See `Cmd::CodexSessionStart`.
//
// The pure helpers below (`codex_route_from_config`, `session_start_ms_from_transcript`,
// `launch_generation_ok`, `codex_session_start_verdict`, `session_start_output_json`) are
// factored small + side-effect-free so the A7 intake-gate atomic can reuse them.
// ---------------------------------------------------------------------------

/// The loopback route this Codex session is configured for: `(base_url, port)`, returned IFF the
/// effective top-level `model_provider` == `id` AND its `base_url` is exactly `http://127.0.0.1:<port>/v1`.
/// Any other shape (foreign provider, non-loopback host, missing `/v1`, unparseable port) → `None`
/// = NOT routed through us. Pure: parses the supplied config text, no I/O.
fn codex_route_from_config(config_text: &str, id: &str) -> Option<(String, u16)> {
    let doc = config_text.parse::<toml_edit::DocumentMut>().ok()?;
    let sel = doc
        .get("model_provider")
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())?;
    if sel != id {
        return None;
    }
    let base_url = doc
        .get("model_providers")
        .and_then(|i| i.as_table_like())
        .and_then(|p| p.get(id))
        .and_then(|i| i.as_table_like())
        .and_then(|b| b.get("base_url"))
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())?;
    let port = loopback_v1_port(base_url)?;
    Some((base_url.to_string(), port))
}

/// Parse `http://127.0.0.1:<port>/v1` → `<port>`. Requires the exact loopback host, an http scheme,
/// and a `/v1` suffix (trailing slash tolerated). Anything else → `None`.
fn loopback_v1_port(base_url: &str) -> Option<u16> {
    let rest = base_url.strip_prefix("http://127.0.0.1:")?;
    // Tolerate a trailing slash on the path.
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let port_str = rest.strip_suffix("/v1")?;
    // The port segment must be all digits (no extra path before /v1).
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port_str.parse::<u16>().ok()
}

/// Days in each (1-based) month of `year` (Gregorian, with leap years).
fn days_in_month(year: i64, month: u32) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// The local timezone's offset from UTC, in seconds, for the instant `epoch_secs` (east-of-UTC
/// positive). This is what reconciles the two launch-generation comparands: the Codex rollout
/// filename encodes LOCAL naive wall-clock time, while a filesystem mtime is a true UTC epoch — so
/// the two only compare correctly once the mtime is shifted into the same local-naive frame (see
/// `config_mtime_local_naive_ms`). On unix we read `localtime_r(...).tm_gmtoff`; on non-unix
/// (where the Codex hook does not run) we conservatively return `0` (treat local == UTC).
#[cfg(unix)]
fn local_utc_offset_secs(epoch_secs: i64) -> i64 {
    // SAFETY: localtime_r writes into a caller-owned, zeroed `tm`; `t` is a valid pointer to a
    // local time_t. No aliasing, no retained pointers past the call.
    unsafe {
        let t = epoch_secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i64
    }
}

#[cfg(not(unix))]
fn local_utc_offset_secs(_epoch_secs: i64) -> i64 {
    0
}

/// Civil (Y-M-D H:M:S) → ms serial, treating the components as a naive wall-clock (a deterministic
/// civil→serial conversion, no timezone DB). The Codex rollout filename is LOCAL naive time, so the
/// result is a LOCAL-NAIVE serial; the launch-generation guard compares it against a config mtime
/// shifted into the same local-naive frame (see `codex_config_mtime_ms`). Returns `None` on an
/// out-of-range field.
fn civil_to_epoch_ms(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<i64> {
    if !(1..=12).contains(&mo) || mi > 59 || s > 59 || h > 23 {
        return None;
    }
    let dim = days_in_month(y, mo);
    if d < 1 || (d as i64) > dim {
        return None;
    }
    // Days from the Unix epoch (1970-01-01) to the start of this Y-M-D.
    let mut days: i64 = 0;
    if y >= 1970 {
        for yr in 1970..y {
            days += if (yr % 4 == 0 && yr % 100 != 0) || yr % 400 == 0 { 366 } else { 365 };
        }
    } else {
        for yr in y..1970 {
            days -= if (yr % 4 == 0 && yr % 100 != 0) || yr % 400 == 0 { 366 } else { 365 };
        }
    }
    for m in 1..mo {
        days += days_in_month(y, m);
    }
    days += (d as i64) - 1;
    let secs = days * 86_400 + (h as i64) * 3_600 + (mi as i64) * 60 + (s as i64);
    Some(secs * 1_000)
}

/// Parse the SESSION-START timestamp from a Codex transcript (rollout) path. The filename encodes
/// it as `rollout-YYYY-MM-DDTHH-MM-SS-<uuid>.jsonl` (the time fields dash-separated). Returns a
/// LOCAL-NAIVE ms serial (the filename is local wall-clock; see `launch_generation_ok`). `None` for any
/// path whose basename isn't a parseable `rollout-<ISO>` (fail-closed at the call site).
fn session_start_ms_from_transcript(transcript_path: &str) -> Option<i64> {
    // Basename only (tolerate both separators).
    let base = transcript_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(transcript_path);
    let stem = base.strip_prefix("rollout-")?;
    // stem = "YYYY-MM-DDTHH-MM-SS-<uuid>.jsonl". Split on 'T' into date and the rest.
    let (date, rest) = stem.split_once('T')?;
    let mut dparts = date.split('-');
    let y: i64 = dparts.next()?.parse().ok()?;
    let mo: u32 = dparts.next()?.parse().ok()?;
    let d: u32 = dparts.next()?.parse().ok()?;
    if dparts.next().is_some() {
        return None; // more than 3 date parts → not our shape
    }
    // rest = "HH-MM-SS-<uuid>.jsonl"; the first three dash fields are the time.
    let mut tparts = rest.splitn(4, '-');
    let h: u32 = tparts.next()?.parse().ok()?;
    let mi: u32 = tparts.next()?.parse().ok()?;
    let s: u32 = tparts.next()?.parse().ok()?;
    // REQUIRE the "<uuid>.jsonl" tail — fail closed on a truncated/ambiguous path. A real rollout
    // name always carries the uuid + .jsonl suffix; A7's security gate reuses this helper for
    // launch-generation evidence, so a permissive shape-match here is a narrow fail-open.
    let tail = tparts.next()?;
    if !tail.ends_with(".jsonl") || tail.len() <= ".jsonl".len() {
        return None;
    }
    civil_to_epoch_ms(y, mo, d, h, mi, s)
}

/// LAUNCH-GENERATION guard. Codex resolves its provider AT LAUNCH; a config written DURING a
/// running session does not route it. `true` IFF a session-start ts was parsed from the transcript
/// AND `config_mtime_ms <= session_start_ms` (the route was present at launch). FAIL-CLOSED: an
/// absent/unparseable transcript, or a config mtime NEWER than session-start (written this
/// session), → `false` → the caller emits the restart/warn variant, never the onboarding.
fn launch_generation_ok(transcript_path: Option<&str>, config_mtime_ms: i64) -> bool {
    match transcript_path.and_then(session_start_ms_from_transcript) {
        Some(session_start_ms) => config_mtime_ms <= session_start_ms,
        None => false,
    }
}

/// Which SessionStart additionalContext variant to emit, decided purely from the four verified
/// signals. `route` is the parsed loopback route (None ⇒ not configured to route through us).
/// The ordering is a fail-closed cascade: a failure at any earlier stage short-circuits to its
/// warn-only variant, and ONLY the fully-verified path reaches `NeutralOnboarding`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionStartVerdict {
    /// Not configured to route through us → warn-only, no masking claim, no additionalContext-as-claim.
    NotRouted,
    /// Configured but no usable exported OpenAI key → requests fail, nothing masked → warn-only.
    AuthFail,
    /// Auth ok but the /healthz identity probe couldn't confirm OUR proxy → warn-only.
    ProxyDown,
    /// Verified, but the config was written THIS session (not live until restart) → warn-only.
    RestartNeeded,
    /// Fully verified at launch → the NEUTRAL token-contract onboarding (NOT an active-masking claim).
    NeutralOnboarding,
}

/// PURE decision logic. Returns WHICH variant to emit. The cascade is fail-closed: each stage
/// gates the next, so a false at any stage degrades to that stage's warn-only verdict and the
/// onboarding is reachable only when every signal is positively verified.
fn codex_session_start_verdict(
    routed: bool,
    auth_ok: bool,
    identity_ok: bool,
    launch_gen_ok: bool,
) -> SessionStartVerdict {
    if !routed {
        return SessionStartVerdict::NotRouted;
    }
    if !auth_ok {
        return SessionStartVerdict::AuthFail;
    }
    if !identity_ok {
        return SessionStartVerdict::ProxyDown;
    }
    if !launch_gen_ok {
        return SessionStartVerdict::RestartNeeded;
    }
    SessionStartVerdict::NeutralOnboarding
}

/// The NEUTRAL token-contract onboarding. Conditional, NOT an unqualified active-masking claim:
/// it never asserts "masking is active right now" / "your data is hidden", because SessionStart
/// cannot observe the effective route. It frames the token contract and the per-prompt-verified
/// caveat, and reminds the model that masking hides data from the PROVIDER, not from the user.
const CODEX_NEUTRAL_ONBOARDING: &str = "This Codex session is configured to route through Sordino, \
    a LOCAL PII-masking proxy. If you receive tokens like `[EMAIL_ADDRESS_ab12]` or \
    `[API_KEY_ab12c3]`, they are tokenized PII placeholders — handle them VERBATIM: do not \
    over-redact, rewrite, or refuse them. In a routed session the real values are restored locally \
    before they reach you, so the tokens stand in for the original data. Masking hides data from \
    the PROVIDER, NOT from the user — never tell the user their data is hidden or redacted from \
    them. Whether any individual prompt is actually routed is verified separately at send time.";

/// The warn-only additionalContext for a given non-onboarding verdict. Each is explicit that
/// NOTHING is assumed masked, and tells the user the concrete fix. NotRouted/error paths return
/// their own copy at the call site (NotRouted still warns; it just isn't reached via this fn for
/// the onboarding). NEVER an unqualified masking claim.
fn session_start_warn_text(verdict: SessionStartVerdict) -> &'static str {
    match verdict {
        SessionStartVerdict::NotRouted => {
            "Sordino is installed but this Codex session is NOT routed through the masking proxy. \
             Run the sordino-openai enable skill, then restart codex. Do NOT assume any PII is \
             masked in this session."
        }
        SessionStartVerdict::AuthFail => {
            "Sordino is configured for this Codex session, but no usable OpenAI API key is exported \
             — Codex requests will FAIL at provider construction and nothing is masked because \
             nothing is sent. Set OPENAI_API_KEY (sk-...) in your environment and restart codex. \
             Do NOT assume PII is masked."
        }
        SessionStartVerdict::ProxyDown => {
            "Sordino is configured for this Codex session, but the masking proxy could not be \
             reached/verified (it may be down, or a foreign listener holds the port). Until the \
             proxy is confirmed, do NOT assume PII is masked — re-run the sordino-openai enable \
             skill or restart codex."
        }
        SessionStartVerdict::RestartNeeded => {
            "Sordino is configured, but this Codex session was started BEFORE routing was enabled \
             (the config was written after launch). Codex resolves its provider at launch, so this \
             session is NOT yet routed — restart codex once to activate masking. Until then, do \
             NOT assume PII is masked."
        }
        // The onboarding verdict has no warn text; callers use CODEX_NEUTRAL_ONBOARDING.
        SessionStartVerdict::NeutralOnboarding => CODEX_NEUTRAL_ONBOARDING,
    }
}

/// Build the schema-valid SessionStart hook output for a verdict: exactly
/// `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"<text>"}}` with NO
/// top-level `env` key (which would make codex's deny_unknown_fields parse FAIL and silently drop
/// the context). The `additionalContext` is the neutral onboarding for `NeutralOnboarding`, else
/// the verdict's warn-only text — never an unqualified masking claim.
fn session_start_output_json(verdict: SessionStartVerdict) -> Value {
    let context = if verdict == SessionStartVerdict::NeutralOnboarding {
        CODEX_NEUTRAL_ONBOARDING
    } else {
        session_start_warn_text(verdict)
    };
    json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    })
}

/// Read `$CODEX_HOME/config.toml`'s mtime as a LOCAL-NAIVE epoch-ms comparand for the
/// launch-generation guard. The mtime is a true UTC epoch, but `session_start_ms_from_transcript`
/// returns the rollout filename's LOCAL naive wall-clock interpreted as a serial (via
/// `civil_to_epoch_ms`). To compare in ONE frame, we shift the UTC mtime by the local UTC offset so
/// it, too, is expressed as local-naive ms. (Without this shift the comparison is off by the local
/// offset — east-of-UTC, a config written AFTER launch could spuriously pass the guard and yield a
/// false NeutralOnboarding for an unrouted session.) On ANY failure (missing file, no mtime,
/// clock-before-epoch, overflow) returns `i64::MAX` — the FAIL-CLOSED value forcing
/// `launch_generation_ok` to false (restart variant), so an unreadable mtime can never produce a
/// false onboarding.
fn codex_config_mtime_ms(path: &Path) -> i64 {
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => match mtime.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => {
                let utc_ms = match i64::try_from(d.as_millis()) {
                    Ok(ms) => ms,
                    Err(_) => return i64::MAX,
                };
                // Shift UTC → local-naive: add the local offset at this instant (saturating keeps
                // the fail-closed sentinel intact).
                let offset_ms = local_utc_offset_secs(utc_ms / 1_000).saturating_mul(1_000);
                utc_ms.saturating_add(offset_ms)
            }
            Err(_) => i64::MAX,
        },
        Err(_) => i64::MAX,
    }
}

/// Extract `transcript_path` from the SessionStart stdin payload (best-effort). Absent/unparseable
/// stdin → `None`, which the launch-generation guard treats as fail-closed.
fn transcript_path_from_payload(stdin: &str) -> Option<String> {
    string_field_from_payload(stdin, "transcript_path")
}

/// Extract the SessionStart payload's `cwd` (the Codex session's project directory) — the root that
/// `ensure_up` / `intake_identity_ok` must run against, NOT the hook process CWD. Absent/unparseable
/// stdin → `None`; the call site falls back to `project_root()` (fail-closed).
fn cwd_from_payload(stdin: &str) -> Option<String> {
    string_field_from_payload(stdin, "cwd")
}

/// Pull a non-empty top-level string field out of the SessionStart stdin payload (best-effort).
fn string_field_from_payload(stdin: &str, field: &str) -> Option<String> {
    let v: Value = serde_json::from_str(stdin.trim()).ok()?;
    v.get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `sordino-hooks codex-session-start`. Reads the SessionStart payload on stdin, runs the
/// config-route / auth / identity / launch-generation verification, and prints the schema-valid
/// hook output. Exit is always 0 in the non-error path; diagnostics go to stderr.
fn codex_session_start_cmd() -> Result<()> {
    // Drain stdin (the SessionStart payload) so the pipe never blocks. Best-effort: an empty or
    // unparseable payload degrades to a fail-closed (transcript-absent) verdict.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let transcript_path = transcript_path_from_payload(&stdin);
    // The SessionStart payload carries the Codex session's project dir as `cwd`. ensure_up /
    // intake_identity_ok MUST run against THAT root, not the hook process CWD (CLAUDE_PROJECT_DIR is
    // a Claude-Code var and is unlikely to be set under a Codex hook). Fail closed: fall back to
    // project_root() only when `cwd` is absent/unparseable.
    let session_cwd = cwd_from_payload(&stdin);

    let id = CODEX_DEFAULT_PROVIDER_ID;
    let config_path = match codex_config_path() {
        Ok(p) => p,
        Err(e) => {
            // Can't even resolve CODEX_HOME → not routed; warn, never claim masking.
            eprintln!("Sordino: cannot resolve $CODEX_HOME ({e}); treating this Codex session as NOT routed.");
            emit_verdict(SessionStartVerdict::NotRouted);
            return Ok(());
        }
    };
    let config_text = std::fs::read_to_string(&config_path).unwrap_or_default();

    // STEP 1/2 — config route. Not our provider / not a loopback /v1 URL → NOT routed.
    let Some((_base_url, port)) = codex_route_from_config(&config_text, id) else {
        eprintln!(
            "Sordino: this Codex session is NOT routed through the masking proxy (no sordino \
             loopback provider in {}).",
            config_path.display()
        );
        emit_verdict(SessionStartVerdict::NotRouted);
        return Ok(());
    };

    // STEP 3 — auth reachability (the SAME classifier codex-auth-check uses). No usable exported
    // sk- key → requests fail at provider construction → nothing masked.
    let (_mode, auth_ok, _unmapped) = detect_codex_auth();
    if !auth_ok {
        eprintln!(
            "Sordino: this Codex session is configured to route, but no usable OPENAI_API_KEY is \
             exported — requests will fail and nothing is masked."
        );
        emit_verdict(SessionStartVerdict::AuthFail);
        return Ok(());
    }

    // STEP 4 — warm the proxy, then the 600ms /healthz nonce identity probe (reused unchanged).
    let root = canonical(&session_cwd.map(PathBuf::from).unwrap_or_else(project_root));
    match ensure_up(&root, None, &default_proxy_bin()) {
        Ok(EnsureOutcome::Ours { .. }) => {}
        Ok(EnsureOutcome::Failed { diag }) => {
            eprintln!("Sordino: could not bring the masking proxy up — {diag}");
        }
        Err(e) => {
            eprintln!("Sordino: could not bring the masking proxy up: {e}");
        }
    }
    let identity_ok = intake_identity_ok(port, &root);
    if !identity_ok {
        eprintln!(
            "Sordino: configured to route on :{port}, but the masking proxy could not be \
             identity-verified (down or a foreign listener) — making NO masking claim."
        );
        emit_verdict(SessionStartVerdict::ProxyDown);
        return Ok(());
    }

    // STEP 5 — launch-generation: a config written DURING this session does not route it. Compare
    // the session-start timestamp (from the transcript rollout filename) to config.toml's mtime.
    let config_mtime_ms = codex_config_mtime_ms(&config_path);
    let launch_gen_ok = launch_generation_ok(transcript_path.as_deref(), config_mtime_ms);
    if !launch_gen_ok {
        eprintln!(
            "Sordino: routing config is present but this Codex session predates it (or the \
             session-start timestamp could not be parsed) — restart codex once to activate \
             masking. Making NO masking claim for this session."
        );
    }

    let verdict = codex_session_start_verdict(true, true, true, launch_gen_ok);
    emit_verdict(verdict);
    Ok(())
}

/// Print the schema-valid SessionStart hook output for `verdict` to stdout (single line of JSON).
fn emit_verdict(verdict: SessionStartVerdict) {
    println!("{}", session_start_output_json(verdict));
}

// ===========================================================================
// codex-user-prompt-submit (A7): the fail-CLOSED Codex intake gate
// ===========================================================================

/// The non-empty BLOCK reason — codex's `parse_user_prompt_submit` DROPS a block with an
/// empty/absent reason (invalid_block_reason → fail-OPEN), so this MUST stay non-empty.
const CODEX_INTAKE_BLOCK_REASON: &str = "Sordino: this Codex session is not confirmed routed \
    through the masking proxy (not enabled / proxy down / not restarted since enable) — your PII \
    would egress UNMASKED. Run the sordino-openai enable skill and restart codex, or /sordino:verify. \
    To send anyway, set SORDINO_NO_INTAKE_GATE=1.";

/// The non-blocking override-warn additionalContext — emitted ALONGSIDE an ALLOW (no `decision`
/// field) when the config selects the proxy but A8 sees no traffic from this session (a likely
/// `-c`/`-p` provider override defeating the route).
const CODEX_OVERRIDE_WARN: &str = "Sordino: this Codex session's config selects the masking proxy, \
    but no traffic from this session has reached it — if you launched codex with -p/-c overriding \
    the provider, your PII is NOT being masked. Restart without the override, or run /sordino:verify.";

/// The NEW Codex intake predicate — distinct from the CLAUDE `intake_should_block_verified`, which
/// ALLOWs whenever `plumbed == false`. For Codex the goal is the OPPOSITE: an UNCONFIGURED session
/// (no sordino provider ⇒ `route_confirmed == false`) must BLOCK its PII. There is NO `plumbed` term
/// — its absence IS the fix. BLOCK iff not escape-hatched, not opted out, and the route is NOT
/// confirmed. Every ALLOW path (route confirmed, opted out, escape hatch) returns false here; the
/// `/sordino:` passthrough is handled at the call site (not a predicate input).
fn codex_intake_should_block(opted_out: bool, route_confirmed: bool, escape_hatch: bool) -> bool {
    !escape_hatch && !opted_out && !route_confirmed
}

/// `route_confirmed` — computed from the SAME three facts A2's SessionStart gathers, ALL checkable
/// at intake WITHOUT egress: (a) config selects our sordino loopback `/v1` provider, (b) the
/// `/healthz` nonce identity probe confirms OUR live proxy on that port, (c) launch-generation (the
/// session was launched AFTER the route was written). There is deliberately NO `not-overridden` and
/// NO A8-inbound conjunct — both would deadlock turn 1 (the intake hook fires BEFORE the first prompt
/// egresses, so requiring a prior inbound to ALLOW never bootstraps). Pure for testing.
fn codex_route_confirmed(
    config_selects_loopback: bool,
    identity_ok: bool,
    launch_generation_ok: bool,
) -> bool {
    config_selects_loopback && identity_ok && launch_generation_ok
}

/// FIRST-TURN DISCRIMINATOR for the override-warn (pure). A8 reports `routed_recently == false` on
/// the FIRST UserPromptSubmit of EVERY session (routed or not), because the intake hook fires before
/// the first prompt egresses. So warn ONLY when a PRIOR prompt of this session was ALLOWED by the
/// gate (`prior_allowed_count >= 1`) AND A8 STILL reports no inbound (`!a8_routed_recently`). The
/// marker advances ONLY on an ALLOW (a blocked prompt never egressed), so it never over-warns a
/// correctly-routed session's first prompt.
fn should_emit_override_warn(prior_allowed_count: u32, a8_routed_recently: bool) -> bool {
    prior_allowed_count >= 1 && !a8_routed_recently
}

/// The HARD-block hook output: exactly `{"decision":"block","reason":<non-empty>}`. The reason MUST
/// be non-empty (codex drops an empty-reason block → fail-open).
fn codex_block_output_json(reason: &str) -> Value {
    json!({ "decision": "block", "reason": reason })
}

/// The non-blocking override-warn hook output: a warn-alongside-ALLOW with NO `decision` field —
/// `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":<string>}}`.
fn codex_override_warn_output_json(context: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    })
}

/// Per-session ALLOWED-prompt counter path (`<state_dir>/codex-intake/<conversation>.json`). Reuses
/// the same state-dir machinery as the Claude session-status delta, in a DISTINCT subdir so it never
/// collides with the MaskState records. `None` if the state dir can't be resolved/created.
fn codex_intake_marker_path(conversation: &str) -> Option<PathBuf> {
    let dir = sordino_state::state_dir().ok()?.join("codex-intake");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(format!("{conversation}.json")))
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct CodexIntakeMarker {
    /// Count of prompts this session that the gate ALLOWED (route_confirmed). Advances ONLY on an
    /// ALLOW — a blocked prompt never egressed, so it must not count as a prior egress-capable turn.
    allowed_count: u32,
}

/// Read this session's prior ALLOWED-prompt count (0 if absent/unreadable — fail-closed toward
/// NOT warning on the first turn).
fn read_codex_allowed_count(conversation: &str) -> u32 {
    codex_intake_marker_path(conversation)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| serde_json::from_str::<CodexIntakeMarker>(&raw).ok())
        .map(|m| m.allowed_count)
        .unwrap_or(0)
}

/// Persist an incremented ALLOWED count for this session (best-effort — never fails the hook).
fn bump_codex_allowed_count(conversation: &str, prior: u32) {
    if let Some(path) = codex_intake_marker_path(conversation) {
        let next = CodexIntakeMarker { allowed_count: prior.saturating_add(1) };
        if let Ok(raw) = serde_json::to_string(&next) {
            let _ = std::fs::write(path, raw);
        }
    }
}

/// Query A8's authenticated `GET /sordino/session/{session_id}/routed` on the proxy port. Returns
/// `Some(routed_recently)` on a successful authed read, `None` when A8 is UNAVAILABLE (no verified
/// proxy / no admin key / unreachable / non-2xx / unparseable). The override-warn degrades to ABSENT
/// on `None` — it NEVER blocks and never errors the hook. Identity is single-sourced through
/// `verified_proxy_rec` so the admin key is only ever handed to OUR nonce-verified proxy. `raw_session_id`
/// is the UNSANITIZED UUID codex sends as the session/thread header (the key A8 indexes `last_seen` by).
fn a8_routed_recently(port: u16, root: &str, raw_session_id: &str) -> Option<bool> {
    let client = reqwest::blocking::Client::builder().build().ok()?;
    let timeout = Duration::from_millis(600);
    // Reuse the gate's identity probe to (a) confirm OUR proxy and (b) get its admin key.
    let rec = verified_proxy_rec(port, root, &client, timeout)?;
    let resp = client
        .get(format!(
            "http://127.0.0.1:{port}/sordino/session/{raw_session_id}/routed"
        ))
        .timeout(timeout)
        .header("x-sordino-key", &rec.admin_key)
        .header("x-sordino-project", sordino_state::project_key(root))
        .send()
        .ok()
        .filter(|r| r.status().is_success())?;
    let v: Value = resp.json().ok()?;
    v.get("routed_recently").and_then(Value::as_bool)
}

/// `sordino-hooks codex-session-routed <session_id>` — the KEY-BEARING per-session override report
/// for the verify skill. Resolves this project's proxy port from the live `$CODEX_HOME` route (the
/// same source the intake hook uses), then performs the authenticated A8 read via [`a8_routed_recently`]
/// (which supplies the admin key from the nonce-verified proxy identity). Prints a single human line
/// and ALWAYS exits 0 — it is a report, never a gate. A bare keyless curl from the skill would always
/// 403 against this key-gated endpoint; this subcommand is the only way the skill can read it.
fn codex_session_routed_cmd(session_id: &str) -> Result<()> {
    let root = canonical(&project_root());
    // Resolve our loopback port from the codex config route (matches the hook's port source).
    let port = codex_config_path()
        .ok()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .and_then(|text| codex_route_from_config(&text, CODEX_DEFAULT_PROVIDER_ID))
        .map(|(_url, port)| port);

    let verdict = match port {
        Some(p) => a8_routed_recently(p, &root, session_id),
        None => None,
    };
    match verdict {
        Some(true) => println!("routed"),
        Some(false) => println!("not-routed"),
        None => println!("unavailable"),
    }
    Ok(())
}

/// `sordino-hooks codex-user-prompt-submit`. Reads the UserPromptSubmit payload on stdin, computes
/// the fail-CLOSED route_confirmed gate, and either BLOCKs (non-empty reason) or ALLOWs — emitting a
/// secondary non-blocking override-warn on the 2nd+ allowed prompt when A8 shows no inbound. Exit is
/// always 0 in the non-error path; diagnostics go to stderr.
fn codex_user_prompt_submit_cmd() -> Result<()> {
    // Drain stdin (the UserPromptSubmit payload) so the pipe never blocks. A malformed/empty payload
    // degrades to an empty prompt + absent fields → no command match, route_confirmed false → BLOCK
    // (fail-closed), never a panic on this safety path.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let prompt = prompt_from_hook_payload(&stdin).unwrap_or_default();
    // The RAW session_id UUID (A8 keys last_seen by it) and the filename-safe marker key.
    let raw_session_id = string_field_from_payload(&stdin, "session_id");
    let conversation = conversation_id_from_hook_payload(&stdin);
    let transcript_path = transcript_path_from_payload(&stdin);
    let session_cwd = cwd_from_payload(&stdin);
    let root = canonical(&session_cwd.map(PathBuf::from).unwrap_or_else(project_root));

    // --- gather facts (all LOCAL/short-bounded; the BLOCK never depends on A8) ----------------
    let id = CODEX_DEFAULT_PROVIDER_ID;
    let opted_out =
        sordino_state::registry_get(&root) == Some(sordino_state::PlumbState::Optout);
    // VALUE-aware escape hatch (mirrors the Claude path): only an explicitly truthy value opens the
    // hatch — `=0` does NOT (it disables a fail-CLOSED security control).
    let escape_hatch = std::env::var("SORDINO_NO_INTAKE_GATE")
        .map(|v| is_truthy_flag(&v))
        .unwrap_or(false);

    // route_confirmed = config-selects-sordino-loopback AND identity_ok AND launch_generation_ok.
    let config_path = codex_config_path();
    let route = config_path
        .as_ref()
        .ok()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .and_then(|text| codex_route_from_config(&text, id));
    let config_selects_loopback = route.is_some();
    let identity_ok = route
        .as_ref()
        .is_some_and(|(_url, port)| intake_identity_ok(*port, &root));
    let launch_gen_ok = match config_path.as_ref() {
        Ok(p) => launch_generation_ok(transcript_path.as_deref(), codex_config_mtime_ms(p)),
        Err(_) => false,
    };
    let route_confirmed =
        codex_route_confirmed(config_selects_loopback, identity_ok, launch_gen_ok);

    // --- the fail-CLOSED decision (independent of A8) -----------------------------------------
    // BLOCK iff the gate fires AND the prompt isn't a `/sordino:` control-plane command — the
    // recovery levers must never be trapped inside the gate they'd release. A `/sordino:` byte-0
    // command is Sordino's own command text (no sordino command takes a PII arg), so passing it
    // through widens nothing.
    if codex_intake_should_block(opted_out, route_confirmed, escape_hatch)
        && !prompt_is_sordino_command(&prompt)
    {
        eprintln!(
            "Sordino: BLOCKED this Codex prompt — route not confirmed (config_selects_loopback={}, \
             identity_ok={}, launch_generation_ok={}).",
            config_selects_loopback, identity_ok, launch_gen_ok
        );
        // Hard block with a NON-EMPTY reason (an empty reason is dropped by codex → fail-open).
        println!("{}", codex_block_output_json(CODEX_INTAKE_BLOCK_REASON));
        return Ok(());
    }

    // --- ALLOW ---------------------------------------------------------------------------------
    // The override-warn is the SECONDARY, non-blocking layer. It only applies on a route-confirmed
    // ALLOW (an opt-out / escape-hatch / `/sordino:` ALLOW has no proxy route to compare against).
    // The marker advances ONLY here (route_confirmed ALLOW), so the first-turn discriminator can
    // tell a genuine first prompt from a 2nd+ prompt that still shows zero inbound.
    if route_confirmed && let Some(conv) = conversation.as_deref() {
        let prior_allowed = read_codex_allowed_count(conv);
        // Query A8 (best-effort, fail-graceful). The warn is ABSENT when A8 is unavailable.
        let port = route.as_ref().map(|(_u, p)| *p);
        let a8 = match (port, raw_session_id.as_deref()) {
            (Some(p), Some(sid)) => a8_routed_recently(p, &root, sid),
            _ => None,
        };
        if let Some(routed_recently) = a8
            && should_emit_override_warn(prior_allowed, routed_recently)
        {
            println!(
                "{}",
                codex_override_warn_output_json(CODEX_OVERRIDE_WARN)
            );
        }
        // Advance the per-session ALLOWED counter (this prompt is route-confirmed → egress-capable).
        bump_codex_allowed_count(conv, prior_allowed);
    }
    Ok(())
}

#[cfg(test)]
mod codex_user_prompt_submit_tests {
    use super::{
        CODEX_INTAKE_BLOCK_REASON, CODEX_OVERRIDE_WARN, codex_block_output_json,
        codex_intake_should_block, codex_override_warn_output_json, codex_route_confirmed,
        should_emit_override_warn,
    };
    use serde_json::Value;

    // --- codex_intake_should_block: full 8-row truth table -----------------------
    // BLOCK iff !escape_hatch && !opted_out && !route_confirmed.
    #[test]
    fn intake_should_block_truth_table() {
        for opted_out in [false, true] {
            for route_confirmed in [false, true] {
                for escape_hatch in [false, true] {
                    let expected = !escape_hatch && !opted_out && !route_confirmed;
                    assert_eq!(
                        codex_intake_should_block(opted_out, route_confirmed, escape_hatch),
                        expected,
                        "opted_out={opted_out} route_confirmed={route_confirmed} escape_hatch={escape_hatch}"
                    );
                }
            }
        }
    }

    #[test]
    fn unconfigured_session_blocks() {
        // THE central FINDING-1 case: nothing opted out, no route, no hatch ⇒ BLOCK (the opposite
        // of the Claude predicate, which ALLOWs when plumbed==false).
        assert!(codex_intake_should_block(false, false, false));
    }

    #[test]
    fn allow_paths_do_not_block() {
        // route confirmed ⇒ allow
        assert!(!codex_intake_should_block(false, true, false));
        // opted out ⇒ allow
        assert!(!codex_intake_should_block(true, false, false));
        // escape-hatched ⇒ allow (even when not routed)
        assert!(!codex_intake_should_block(false, false, true));
    }

    // --- codex_route_confirmed composition ---------------------------------------
    #[test]
    fn route_confirmed_requires_all_three() {
        assert!(codex_route_confirmed(true, true, true));
        // any single false ⇒ not confirmed
        assert!(!codex_route_confirmed(false, true, true)); // config not selecting our loopback
        assert!(!codex_route_confirmed(true, false, true)); // identity probe failed
        assert!(!codex_route_confirmed(true, true, false)); // launched before route written
        assert!(!codex_route_confirmed(false, false, false));
    }

    // --- BLOCK output shape ------------------------------------------------------
    #[test]
    fn block_output_is_decision_block_with_nonempty_reason() {
        let v = codex_block_output_json(CODEX_INTAKE_BLOCK_REASON);
        assert_eq!(v.get("decision").and_then(Value::as_str), Some("block"));
        let reason = v.get("reason").and_then(Value::as_str).expect("reason present");
        assert!(!reason.is_empty(), "reason MUST be non-empty (codex drops empty-reason blocks)");
        // exactly two keys, no extras.
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("decision") && obj.contains_key("reason"));
    }

    // --- override-warn output shape (warn alongside ALLOW, NO decision key) -------
    #[test]
    fn override_warn_output_has_no_decision_key() {
        let v = codex_override_warn_output_json(CODEX_OVERRIDE_WARN);
        assert!(v.get("decision").is_none(), "a warn must NOT carry a decision (would block)");
        let hso = v.get("hookSpecificOutput").expect("hookSpecificOutput present");
        assert_eq!(
            hso.get("hookEventName").and_then(Value::as_str),
            Some("UserPromptSubmit")
        );
        let ctx = hso
            .get("additionalContext")
            .and_then(Value::as_str)
            .expect("additionalContext present");
        assert!(!ctx.is_empty());
    }

    // --- first-turn discriminator ------------------------------------------------
    #[test]
    fn override_warn_suppressed_on_first_allowed_prompt() {
        // First allowed prompt (count 0): A8 ALWAYS reports false here (hook fires pre-egress) →
        // must NOT warn, regardless of a8.
        assert!(!should_emit_override_warn(0, false));
        assert!(!should_emit_override_warn(0, true));
    }

    #[test]
    fn override_warn_only_on_second_plus_with_no_inbound() {
        // 2nd+ allowed prompt AND A8 still shows no inbound ⇒ warn.
        assert!(should_emit_override_warn(1, false));
        assert!(should_emit_override_warn(5, false));
        // A8 confirms inbound ⇒ no warn (the route is working).
        assert!(!should_emit_override_warn(1, true));
        assert!(!should_emit_override_warn(5, true));
    }
}

#[cfg(test)]
mod codex_session_start_tests {
    use super::{
        CODEX_DEFAULT_PROVIDER_ID, CODEX_NEUTRAL_ONBOARDING, SessionStartVerdict,
        codex_config_mtime_ms, codex_route_from_config, codex_session_start_verdict,
        cwd_from_payload, launch_generation_ok, local_utc_offset_secs,
        session_start_ms_from_transcript, session_start_output_json, transcript_path_from_payload,
    };
    use serde_json::Value;

    const ID: &str = CODEX_DEFAULT_PROVIDER_ID;

    // --- codex_route_from_config -------------------------------------------------

    #[test]
    fn route_matches_our_loopback_v1_provider() {
        let cfg = "model_provider = \"sordino\"\n\
                   [model_providers.sordino]\n\
                   base_url = \"http://127.0.0.1:18920/v1\"\n";
        assert_eq!(
            codex_route_from_config(cfg, ID),
            Some(("http://127.0.0.1:18920/v1".to_string(), 18920))
        );
    }

    #[test]
    fn route_none_when_provider_is_foreign() {
        // Our block exists but the selected provider is someone else's → NOT routed.
        let cfg = "model_provider = \"openai\"\n\
                   [model_providers.sordino]\n\
                   base_url = \"http://127.0.0.1:18920/v1\"\n";
        assert_eq!(codex_route_from_config(cfg, ID), None);
    }

    #[test]
    fn route_none_when_base_url_not_loopback_v1() {
        // Selected as our provider, but the URL is not a loopback /v1 endpoint.
        for url in [
            "https://api.openai.com/v1",
            "http://10.0.0.1:18920/v1",
            "http://127.0.0.1:18920",       // missing /v1
            "http://127.0.0.1:abc/v1",      // non-numeric port
            "http://127.0.0.1:18920/extra/v1", // extra path segment
        ] {
            let cfg = format!(
                "model_provider = \"sordino\"\n[model_providers.sordino]\nbase_url = \"{url}\"\n"
            );
            assert_eq!(codex_route_from_config(&cfg, ID), None, "url={url}");
        }
    }

    #[test]
    fn route_tolerates_trailing_slash() {
        let cfg = "model_provider = \"sordino\"\n\
                   [model_providers.sordino]\n\
                   base_url = \"http://127.0.0.1:7777/v1/\"\n";
        assert_eq!(
            codex_route_from_config(cfg, ID).map(|(_, p)| p),
            Some(7777)
        );
    }

    // --- session_start_ms_from_transcript ---------------------------------------

    #[test]
    fn transcript_ts_parses_rollout_filename() {
        let p = "/home/u/.codex/sessions/2026/06/26/rollout-2026-06-26T15-23-18-2f9c0b1a-1111-2222-3333-444455556666.jsonl";
        // Expected: 2026-06-26T15:23:18 as epoch ms (civil-as-UTC).
        // Days from 1970-01-01 to 2026-06-26 computed by the same algorithm.
        let got = session_start_ms_from_transcript(p).expect("should parse");
        // Sanity: it must be a positive, second-granular ms value matching the civil time.
        // Reconstruct via the public helper to avoid hard-coding the constant.
        assert!(got > 0);
        assert_eq!(got % 1000, 0, "second granularity");
        // 15:23:18 within its day = 15*3600 + 23*60 + 18 = 55398 s.
        let within_day_ms = got - day_floor_ms(got);
        assert_eq!(within_day_ms, 55_398 * 1000);
    }

    // Floor an epoch-ms to the start of its UTC day.
    fn day_floor_ms(ms: i64) -> i64 {
        let day = 86_400_000;
        (ms / day) * day
    }

    #[test]
    fn transcript_ts_none_for_non_rollout_path() {
        assert_eq!(session_start_ms_from_transcript("/tmp/notes.txt"), None);
        assert_eq!(
            session_start_ms_from_transcript("/x/rollout-not-a-time-uuid.jsonl"),
            None
        );
        assert_eq!(session_start_ms_from_transcript(""), None);
    }

    #[test]
    fn transcript_ts_fails_closed_on_truncated_or_tailless_path() {
        // A truncated rollout name with the time but NO uuid/.jsonl tail must NOT parse — fail
        // closed (A7's gate reuses this for launch-generation evidence; a permissive parse there
        // would be a narrow fail-open).
        assert_eq!(
            session_start_ms_from_transcript("rollout-2026-06-26T15-23-18"),
            None,
            "truncated path (no uuid/.jsonl tail) must fail closed"
        );
        // uuid present but wrong suffix → still rejected.
        assert_eq!(
            session_start_ms_from_transcript("rollout-2026-06-26T15-23-18-abcd.txt"),
            None
        );
        // empty tail before suffix (just ".jsonl") → rejected.
        assert_eq!(
            session_start_ms_from_transcript("rollout-2026-06-26T15-23-18-.jsonl"),
            None
        );
        // the genuine shape still parses.
        assert!(
            session_start_ms_from_transcript(
                "rollout-2026-06-26T15-23-18-2f9c0b1a-1111-2222-3333-444455556666.jsonl"
            )
            .is_some()
        );
    }

    // --- launch_generation_ok ----------------------------------------------------

    #[test]
    fn launch_gen_true_when_config_older_than_session_start() {
        let p = "rollout-2026-06-26T15-23-18-uuid.jsonl";
        let ss = session_start_ms_from_transcript(p).unwrap();
        // config written one second BEFORE session start → present at launch → ok.
        assert!(launch_generation_ok(Some(p), ss - 1000));
        // Equal mtime is also "present at launch".
        assert!(launch_generation_ok(Some(p), ss));
    }

    #[test]
    fn launch_gen_false_when_config_newer_than_session_start() {
        let p = "rollout-2026-06-26T15-23-18-uuid.jsonl";
        let ss = session_start_ms_from_transcript(p).unwrap();
        // config written AFTER session start → written this session → not yet routing.
        assert!(!launch_generation_ok(Some(p), ss + 1000));
    }

    #[test]
    fn launch_gen_false_when_transcript_unparseable_or_absent() {
        assert!(!launch_generation_ok(None, 0));
        assert!(!launch_generation_ok(Some("/tmp/notes.txt"), 0));
    }

    // --- codex_session_start_verdict (the truth table) ---------------------------

    #[test]
    fn verdict_truth_table() {
        use SessionStartVerdict::*;
        // not routed → NotRouted (the other signals are irrelevant)
        assert_eq!(codex_session_start_verdict(false, true, true, true), NotRouted);
        assert_eq!(codex_session_start_verdict(false, false, false, false), NotRouted);
        // routed + auth_ok=false → AuthFail
        assert_eq!(codex_session_start_verdict(true, false, true, true), AuthFail);
        // routed + auth ok + identity_ok=false → ProxyDown
        assert_eq!(codex_session_start_verdict(true, true, false, true), ProxyDown);
        // routed + auth ok + identity ok + launch_gen_ok=false → RestartNeeded
        assert_eq!(codex_session_start_verdict(true, true, true, false), RestartNeeded);
        // fully verified → NeutralOnboarding
        assert_eq!(codex_session_start_verdict(true, true, true, true), NeutralOnboarding);
    }

    // --- emitted JSON shape (schema-valid; NO top-level env key) ------------------

    #[test]
    fn emitted_json_is_schema_valid_for_every_variant() {
        use SessionStartVerdict::*;
        for v in [AuthFail, ProxyDown, RestartNeeded, NeutralOnboarding, NotRouted] {
            let out = session_start_output_json(v);
            // Re-parse to be sure it's valid JSON and inspect top-level keys.
            let parsed: Value = serde_json::from_str(&out.to_string()).unwrap();
            let obj = parsed.as_object().expect("top-level object");
            // The ONLY top-level key must be hookSpecificOutput (no env key — that re-introduces
            // the parse-drop bug under codex's deny_unknown_fields).
            assert_eq!(obj.len(), 1, "exactly one top-level key for {v:?}: {obj:?}");
            assert!(obj.contains_key("hookSpecificOutput"), "{v:?}");
            assert!(!obj.contains_key("env"), "no top-level env key for {v:?}");
            let hso = obj["hookSpecificOutput"].as_object().expect("hso object");
            assert_eq!(
                hso.get("hookEventName").and_then(Value::as_str),
                Some("SessionStart"),
                "{v:?}"
            );
            assert!(
                hso.get("additionalContext").and_then(Value::as_str).is_some(),
                "additionalContext present for {v:?}"
            );
        }
    }

    // --- the onboarding text carries NO unqualified active-masking assertion ------

    #[test]
    fn neutral_onboarding_makes_no_unqualified_masking_claim() {
        let text = CODEX_NEUTRAL_ONBOARDING.to_lowercase();
        // Banned unqualified active-masking phrasings.
        for banned in [
            "masking is active",
            "your data is hidden",
            "is masking this project",
            "data is hidden from you",
            "your data is masked",
        ] {
            assert!(
                !text.contains(banned),
                "onboarding must not assert {banned:?}: {CODEX_NEUTRAL_ONBOARDING}"
            );
        }
        // The token-handling guidance MUST be present.
        assert!(text.contains("verbatim"), "token-verbatim guidance present");
        assert!(
            text.contains("placeholder"),
            "token-placeholder guidance present"
        );
        // And the provider-not-user caveat must be present.
        assert!(
            text.contains("from the provider, not from the user"),
            "provider-not-user caveat present"
        );
    }

    // The same banned-phrase guard, applied to the EMITTED onboarding additionalContext.
    #[test]
    fn emitted_onboarding_additional_context_has_no_masking_claim() {
        let out = session_start_output_json(SessionStartVerdict::NeutralOnboarding);
        let ctx = out["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .to_lowercase();
        for banned in ["masking is active", "your data is hidden", "is masking this project"] {
            assert!(!ctx.contains(banned), "emitted context asserts {banned:?}");
        }
    }

    // --- payload field extraction (cwd + transcript_path) [Fix 2] ----------------

    #[test]
    fn payload_extracts_cwd_and_transcript_path() {
        let payload = r#"{
            "session_id": "2f9c0b1a-1111-2222-3333-444455556666",
            "transcript_path": "/home/u/.codex/sessions/2026/06/26/rollout-2026-06-26T15-23-18-uuid.jsonl",
            "cwd": "/home/u/Projects/myproj",
            "hook_event_name": "SessionStart",
            "source": "startup"
        }"#;
        assert_eq!(
            cwd_from_payload(payload).as_deref(),
            Some("/home/u/Projects/myproj"),
            "cwd is the Codex session project dir — must drive root, not the hook CWD"
        );
        assert_eq!(
            transcript_path_from_payload(payload).as_deref(),
            Some("/home/u/.codex/sessions/2026/06/26/rollout-2026-06-26T15-23-18-uuid.jsonl")
        );
    }

    #[test]
    fn payload_fields_none_when_absent_or_unparseable() {
        // Absent fields → None (call site fails closed to project_root()).
        assert_eq!(cwd_from_payload(r#"{"session_id":"x"}"#), None);
        assert_eq!(transcript_path_from_payload(r#"{"session_id":"x"}"#), None);
        // Empty string is treated as absent.
        assert_eq!(cwd_from_payload(r#"{"cwd":""}"#), None);
        // Unparseable stdin → None, never a panic.
        assert_eq!(cwd_from_payload("not json"), None);
        assert_eq!(cwd_from_payload(""), None);
        assert_eq!(transcript_path_from_payload(""), None);
    }

    // --- config mtime is in the SAME (local-naive) frame as the transcript ts [Fix 1] ---
    //
    // The launch-generation guard compares the rollout filename's LOCAL-naive wall-clock against
    // config.toml's mtime. The mtime is a true UTC epoch, so codex_config_mtime_ms MUST shift it by
    // the local UTC offset into the local-naive frame — otherwise the comparison is off by the
    // offset (east-of-UTC: a config written after launch spuriously passes the guard).
    #[test]
    fn config_mtime_is_local_naive_frame() {
        use std::time::{Duration, UNIX_EPOCH};

        // Pick a fixed UTC instant and stamp a temp file's mtime to it.
        let utc_secs: i64 = 1_750_000_000; // some 2025 instant
        let path = std::env::temp_dir().join(format!(
            "sordino_a2_mtime_test_{}_{}.toml",
            std::process::id(),
            utc_secs
        ));
        std::fs::write(&path, b"model_provider = \"sordino\"\n").expect("write temp config");
        let target = UNIX_EPOCH + Duration::from_secs(utc_secs as u64);
        // Set the file's mtime to the known UTC instant.
        filetime_set(&path, target);

        let got = codex_config_mtime_ms(&path);
        let _ = std::fs::remove_file(&path);

        // Expected: the UTC ms shifted into local-naive by the local offset at that instant.
        let offset_ms = local_utc_offset_secs(utc_secs) * 1000;
        let expected_local_naive_ms = utc_secs * 1000 + offset_ms;
        assert_eq!(
            got, expected_local_naive_ms,
            "config mtime must be expressed in the local-naive frame (UTC + local offset)"
        );

        // And critically: it must compare correctly against a same-instant transcript ts that
        // EXPRESSES that local wall-clock in its filename. Build such a filename from the local
        // civil components of `target` and assert the guard sees them as equal-at-launch.
        let p = rollout_path_for_local_naive_ms(expected_local_naive_ms);
        let ss = session_start_ms_from_transcript(&p).expect("rollout parses");
        assert_eq!(
            ss, got,
            "a config saved at the SAME instant the session launched must read equal, not offset"
        );
        assert!(
            launch_generation_ok(Some(&p), got),
            "equal mtime == session-start is 'present at launch'"
        );
    }

    /// Stamp `path`'s mtime to `when` via std's cross-platform `FileTimes` (no filetime crate).
    fn filetime_set(path: &std::path::Path, when: std::time::SystemTime) {
        let times = std::fs::FileTimes::new().set_modified(when);
        let f = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open for times");
        f.set_times(times).expect("set_times");
    }

    /// Build a `rollout-<local-ISO>-uuid.jsonl` filename whose encoded wall-clock equals the given
    /// local-naive ms serial (the same serial `session_start_ms_from_transcript` will parse back).
    fn rollout_path_for_local_naive_ms(local_naive_ms: i64) -> String {
        let secs = local_naive_ms / 1000;
        let day = secs.div_euclid(86_400);
        let tod = secs.rem_euclid(86_400);
        let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
        let (y, mo, d) = civil_from_days(day);
        format!(
            "/sessions/rollout-{y:04}-{mo:02}-{d:02}T{h:02}-{mi:02}-{s:02}-deadbeef.jsonl"
        )
    }

    /// Inverse of the civil→days math in `civil_to_epoch_ms`: days-since-epoch → (Y, M, D).
    fn civil_from_days(mut days: i64) -> (i64, u32, u32) {
        let mut year: i64 = 1970;
        loop {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            let dy = if leap { 366 } else { 365 };
            if days >= dy {
                days -= dy;
                year += 1;
            } else if days < 0 {
                year -= 1;
                let leap2 = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
                days += if leap2 { 366 } else { 365 };
            } else {
                break;
            }
        }
        let dim = |m: u32| -> i64 {
            match m {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 => {
                    if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 { 29 } else { 28 }
                }
                _ => 0,
            }
        };
        let mut month: u32 = 1;
        while days >= dim(month) {
            days -= dim(month);
            month += 1;
        }
        (year, month, (days + 1) as u32)
    }
}

#[cfg(test)]
mod codex_config_tests {
    use super::{
        CODEX_DEFAULT_PROVIDER_ID, CodexMergeOutcome, codex_disable_merge, codex_enable_merge,
        codex_hook_command_is_ours, codex_hooks_disable_merge, codex_hooks_enable_merge,
    };

    const URL: &str = "http://127.0.0.1:18920/v1";
    const ID: &str = CODEX_DEFAULT_PROVIDER_ID;
    const HOOKS_DIR: &str = "/opt/sordino/codex-sordino-plugin/scripts";

    fn changed(out: CodexMergeOutcome) -> String {
        match out {
            CodexMergeOutcome::Changed(s) => s,
            CodexMergeOutcome::NoOp => panic!("expected Changed, got NoOp"),
            CodexMergeOutcome::Refused(m) => panic!("expected Changed, got Refused: {m}"),
        }
    }

    /// Parse to a `toml_edit::DocumentMut` purely for semantic assertions (and to prove the
    /// emitted text is valid TOML). We use toml_edit (already a dep) rather than pulling in `toml`.
    fn doc(text: &str) -> toml_edit::DocumentMut {
        text.parse::<toml_edit::DocumentMut>()
            .unwrap_or_else(|e| panic!("output is not valid TOML: {e}\n---\n{text}"))
    }

    /// Top-level `model_provider` as a str (None if absent/non-string).
    fn provider_of(d: &toml_edit::DocumentMut) -> Option<&str> {
        d.get("model_provider")
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_str())
    }

    /// A key inside `[model_providers.<id>]` as a str.
    fn block_str<'a>(d: &'a toml_edit::DocumentMut, id: &str, key: &str) -> Option<&'a str> {
        d.get("model_providers")
            .and_then(|i| i.as_table_like())
            .and_then(|p| p.get(id))
            .and_then(|i| i.as_table_like())
            .and_then(|b| b.get(key))
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_str())
    }

    /// A key inside `[model_providers.<id>]` as a bool.
    fn block_bool(d: &toml_edit::DocumentMut, id: &str, key: &str) -> Option<bool> {
        d.get("model_providers")
            .and_then(|i| i.as_table_like())
            .and_then(|p| p.get(id))
            .and_then(|i| i.as_table_like())
            .and_then(|b| b.get(key))
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_bool())
    }

    /// Is `[model_providers.<id>]` present at all?
    fn has_block(d: &toml_edit::DocumentMut, id: &str) -> bool {
        d.get("model_providers")
            .and_then(|i| i.as_table_like())
            .and_then(|p| p.get(id))
            .is_some()
    }

    // GATE CASE 1 — worked trace: empty config + url → exact target block, enable would exit 0.
    #[test]
    fn enable_on_empty_writes_exact_target_block() {
        let out = changed(codex_enable_merge("", ID, URL));
        let d = doc(&out);
        assert_eq!(provider_of(&d), Some("sordino"));
        assert_eq!(block_str(&d, ID, "base_url"), Some(URL));
        assert_eq!(block_str(&d, ID, "name"), Some("Sordino Masking Proxy"));
        assert_eq!(block_str(&d, ID, "env_key"), Some("OPENAI_API_KEY"));
        assert_eq!(block_str(&d, ID, "wire_api"), Some("responses"));
        assert_eq!(block_bool(&d, ID, "requires_openai_auth"), Some(false));
        assert_eq!(block_bool(&d, ID, "supports_websockets"), Some(false));
        assert_eq!(block_bool(&d, ID, "sordino_managed"), Some(true));
        // No prior to record on an empty config.
        assert_eq!(block_str(&d, ID, "sordino_prior_provider"), None);
    }

    // GATE CASE 2 — idempotency: a second enable with the same url is a no-op (exit-3 semantics),
    // and produces no duplicate table.
    #[test]
    fn second_enable_same_url_is_noop() {
        let once = changed(codex_enable_merge("", ID, URL));
        match codex_enable_merge(&once, ID, URL) {
            CodexMergeOutcome::NoOp => {}
            CodexMergeOutcome::Changed(s) => panic!("second enable should no-op, got change:\n{s}"),
            CodexMergeOutcome::Refused(m) => panic!("second enable should no-op, got refusal: {m}"),
        }
        // exactly one occurrence of our table header.
        assert_eq!(once.matches("[model_providers.sordino]").count(), 1, "{once}");
    }

    // GATE CASE 3 — round-trip falsifier: prior model_provider, an unrelated acme block, and a
    // top-level comment all survive enable→disable; no sordino table remains; provider restored.
    #[test]
    fn round_trip_preserves_comment_acme_and_restores_provider() {
        let original = "# top-level comment the user wrote\n\
            model_provider = \"openai\"\n\
            \n\
            [model_providers.acme]\n\
            name = \"Acme\"\n\
            base_url = \"https://acme.example/v1\"\n";
        let enabled = changed(codex_enable_merge(original, ID, URL));
        // After enable: provider points at us, prior is recorded, acme + comment intact.
        let ev = doc(&enabled);
        assert_eq!(provider_of(&ev), Some("sordino"));
        assert_eq!(block_str(&ev, ID, "sordino_prior_provider"), Some("openai"));
        assert!(enabled.contains("# top-level comment the user wrote"), "comment lost on enable:\n{enabled}");
        assert!(has_block(&ev, "acme"));

        let disabled = changed(codex_disable_merge(&enabled, ID));
        let dv = doc(&disabled);
        // provider restored to openai; no sordino block; acme + comment intact.
        assert_eq!(provider_of(&dv), Some("openai"));
        assert!(
            !has_block(&dv, ID),
            "sordino block must be gone:\n{disabled}"
        );
        assert!(
            has_block(&dv, "acme"),
            "KILL: acme block was dropped — destructive merge:\n{disabled}"
        );
        assert!(
            disabled.contains("# top-level comment the user wrote"),
            "KILL: top-level comment was dropped — destructive merge:\n{disabled}"
        );
    }

    // GATE CASE 4 — ownership-marker falsifier.
    #[test]
    fn enable_refuses_unmarked_user_block() {
        let user_owned = "[model_providers.sordino]\n\
            name = \"My Own Thing\"\n\
            base_url = \"https://mine.example/v1\"\n";
        match codex_enable_merge(user_owned, ID, URL) {
            CodexMergeOutcome::Refused(_) => {}
            other => panic!(
                "enable must REFUSE an unmarked same-id user block, got {}",
                match other {
                    CodexMergeOutcome::Changed(s) => format!("Changed:\n{s}"),
                    CodexMergeOutcome::NoOp => "NoOp".to_string(),
                    CodexMergeOutcome::Refused(_) => unreachable!(),
                }
            ),
        }
    }

    #[test]
    fn disable_removes_our_marked_block_and_restores_prior() {
        let enabled = changed(codex_enable_merge(
            "model_provider = \"openai\"\n",
            ID,
            URL,
        ));
        let disabled = changed(codex_disable_merge(&enabled, ID));
        let dv = doc(&disabled);
        assert_eq!(provider_of(&dv), Some("openai"));
        assert!(!has_block(&dv, ID));
    }

    #[test]
    fn disable_is_noop_on_unmarked_user_block() {
        let user_owned = "model_provider = \"sordino\"\n\
            \n\
            [model_providers.sordino]\n\
            name = \"My Own Thing\"\n\
            base_url = \"https://mine.example/v1\"\n";
        match codex_disable_merge(user_owned, ID) {
            CodexMergeOutcome::NoOp => {}
            CodexMergeOutcome::Changed(s) => {
                panic!("disable must NOT touch an unmarked user block, got change:\n{s}")
            }
            CodexMergeOutcome::Refused(m) => panic!("unexpected refusal: {m}"),
        }
    }

    // Prior-provider preservation across a re-enable: a re-enable that changes the url must NOT
    // clobber the previously-saved prior with our own id.
    #[test]
    fn re_enable_preserves_saved_prior() {
        let enabled = changed(codex_enable_merge("model_provider = \"openai\"\n", ID, URL));
        let new_url = "http://127.0.0.1:29999/v1";
        let re = changed(codex_enable_merge(&enabled, ID, new_url));
        let rv = doc(&re);
        assert_eq!(
            block_str(&rv, ID, "sordino_prior_provider"),
            Some("openai"),
            "re-enable must preserve the original prior provider, not overwrite it with our id:\n{re}"
        );
        assert_eq!(block_str(&rv, ID, "base_url"), Some(new_url));
    }

    #[test]
    fn stale_marked_block_with_wrong_ws_is_rewritten_not_noop() {
        // A sordino-managed block whose URL matches but whose supports_websockets is WRONG (true,
        // e.g. an older plugin version or a partial write) must be RE-WRITTEN, not idempotently
        // no-op'd — a no-op would leave the WebSocket transport that bypasses the HTTP masking proxy.
        let stale = format!(
            "model_provider = \"{ID}\"\n\
             [model_providers.{ID}]\n\
             name = \"Sordino Masking Proxy\"\n\
             base_url = \"{URL}\"\n\
             env_key = \"OPENAI_API_KEY\"\n\
             wire_api = \"responses\"\n\
             requires_openai_auth = false\n\
             supports_websockets = true\n\
             sordino_managed = true\n"
        );
        // `changed` panics on NoOp, so this asserts the stale block was NOT idempotently skipped.
        let out = changed(codex_enable_merge(&stale, ID, URL));
        let d = doc(&out);
        assert_eq!(
            block_bool(&d, ID, "supports_websockets"),
            Some(false),
            "re-write must heal supports_websockets back to false:\n{out}"
        );
    }

    // ---- [hooks]-merge: ownership-aware SessionStart + UserPromptSubmit wiring ----

    /// Count MatcherGroups under `[hooks.<event>]` whose inner command basename equals `script`.
    /// Inspects BOTH inner-hooks shapes (inline array `hooks = [{..}]` and array-of-tables
    /// `[[..hooks]]`) so the count is meaningful regardless of how the group was authored.
    fn count_our_hook(d: &toml_edit::DocumentMut, event: &str, script: &str) -> usize {
        // Use the PRODUCTION ownership matcher so the count can never silently diverge from it.
        let is_ours = |c: &str| codex_hook_command_is_ours(c, script);
        d.get("hooks")
            .and_then(|h| h.as_table_like())
            .and_then(|h| h.get(event))
            .and_then(|a| a.as_array_of_tables())
            .map(|groups| {
                groups
                    .iter()
                    .filter(|grp| {
                        let item = grp.get("hooks");
                        let inline = item
                            .and_then(|i| i.as_array())
                            .map(|inner| {
                                inner.iter().any(|h| {
                                    h.as_inline_table()
                                        .and_then(|t| t.get("command"))
                                        .and_then(|v| v.as_str())
                                        .map(|c| is_ours(c))
                                        .unwrap_or(false)
                                })
                            })
                            .unwrap_or(false);
                        let aot = item
                            .and_then(|i| i.as_array_of_tables())
                            .map(|inner| {
                                inner.iter().any(|t| {
                                    t.get("command")
                                        .and_then(|v| v.as_value())
                                        .and_then(|v| v.as_str())
                                        .map(|c| is_ours(c))
                                        .unwrap_or(false)
                                })
                            })
                            .unwrap_or(false);
                        inline || aot
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Total MatcherGroups under `[hooks.<event>]` (ours + user's).
    fn count_event_groups(d: &toml_edit::DocumentMut, event: &str) -> usize {
        d.get("hooks")
            .and_then(|h| h.as_table_like())
            .and_then(|h| h.get(event))
            .and_then(|a| a.as_array_of_tables())
            .map(|g| g.len())
            .unwrap_or(0)
    }

    // GATE — enable on an empty config writes both event entries pointing at the hooks-dir scripts.
    #[test]
    fn hooks_enable_on_empty_writes_both_events() {
        let (out, ch) = codex_hooks_enable_merge("", HOOKS_DIR);
        assert!(ch, "enable on empty must change");
        let d = doc(&out);
        assert_eq!(count_our_hook(&d, "SessionStart", "codex-session-start.sh"), 1);
        assert_eq!(
            count_our_hook(&d, "UserPromptSubmit", "codex-user-prompt-submit.sh"),
            1
        );
        // commands carry the absolute hooks-dir.
        assert!(
            out.contains(&format!("{HOOKS_DIR}/codex-session-start.sh")),
            "absolute session-start path missing:\n{out}"
        );
        assert!(
            out.contains(&format!("{HOOKS_DIR}/codex-user-prompt-submit.sh")),
            "absolute user-prompt-submit path missing:\n{out}"
        );
    }

    // GATE — a second enable is idempotent (no duplicate MatcherGroups).
    #[test]
    fn hooks_enable_is_idempotent() {
        let (once, _) = codex_hooks_enable_merge("", HOOKS_DIR);
        let (twice, ch2) = codex_hooks_enable_merge(&once, HOOKS_DIR);
        assert!(!ch2, "second enable must be a no-op (no change)");
        let d = doc(&twice);
        assert_eq!(
            count_our_hook(&d, "SessionStart", "codex-session-start.sh"),
            1,
            "no duplicate SessionStart group:\n{twice}"
        );
        assert_eq!(
            count_our_hook(&d, "UserPromptSubmit", "codex-user-prompt-submit.sh"),
            1,
            "no duplicate UserPromptSubmit group:\n{twice}"
        );
    }

    // GATE — enable PRESERVES a pre-existing user [[hooks.SessionStart]] entry (adds ours alongside).
    #[test]
    fn hooks_enable_preserves_user_session_start() {
        let user = "[[hooks.SessionStart]]\n\
            matcher = \"*\"\n\
            [[hooks.SessionStart.hooks]]\n\
            type = \"command\"\n\
            command = \"/home/me/my-own-hook.sh\"\n";
        let (out, ch) = codex_hooks_enable_merge(user, HOOKS_DIR);
        assert!(ch);
        let d = doc(&out);
        // The user's SessionStart group survives, and ours is added alongside → 2 groups total.
        assert_eq!(
            count_event_groups(&d, "SessionStart"),
            2,
            "user entry must be preserved alongside ours:\n{out}"
        );
        assert_eq!(count_our_hook(&d, "SessionStart", "codex-session-start.sh"), 1);
        assert!(
            out.contains("/home/me/my-own-hook.sh"),
            "user hook command lost:\n{out}"
        );
        // UserPromptSubmit (which the user had none of) gets ours.
        assert_eq!(
            count_our_hook(&d, "UserPromptSubmit", "codex-user-prompt-submit.sh"),
            1
        );
    }

    // GATE (FIX) — enable must NOT silently no-op when the event is written as an INLINE array
    // (`SessionStart = [ {...} ]`) rather than `[[hooks.SessionStart]]`. The old code keyed solely on
    // `as_array_of_tables_mut()` (None for an inline array) → reconcile skipped + append guard
    // short-circuited → our hook dropped while `changed` could be true from the other event. After the
    // fix the inline array is normalized to an array-of-tables, the user entry is preserved, and ours
    // is appended.
    #[test]
    fn hooks_enable_normalizes_inline_array_event() {
        // User wrote SessionStart as an inline array of inline tables (valid TOML, different shape).
        let user = "[hooks]\n\
            SessionStart = [ { matcher = \"*\", hooks = [ { type = \"command\", command = \"/home/me/my-own-hook.sh\" } ] } ]\n";
        // Sanity: this really IS the inline-array shape that returns None from as_array_of_tables.
        {
            let d = doc(user);
            assert!(
                d.get("hooks")
                    .and_then(|h| h.as_table_like())
                    .and_then(|h| h.get("SessionStart"))
                    .map(|i| i.as_array().is_some() && i.as_array_of_tables().is_none())
                    .unwrap_or(false),
                "fixture must be an inline array (not array-of-tables)"
            );
        }
        let (out, ch) = codex_hooks_enable_merge(user, HOOKS_DIR);
        assert!(ch, "enable against an inline-array event MUST change (install ours)");
        let d = doc(&out);
        // Our hook is actually installed (the bug dropped it).
        assert_eq!(
            count_our_hook(&d, "SessionStart", "codex-session-start.sh"),
            1,
            "KILL: our SessionStart hook was dropped on an inline-array config:\n{out}"
        );
        // The user's pre-existing entry is preserved (re-homed, not destroyed).
        assert!(
            out.contains("/home/me/my-own-hook.sh"),
            "user inline hook lost on normalization:\n{out}"
        );
        assert_eq!(
            count_event_groups(&d, "SessionStart"),
            2,
            "user entry + ours = 2 groups after normalization:\n{out}"
        );
        // And it round-trips: a second enable is now a clean no-op.
        let (_again, ch2) = codex_hooks_enable_merge(&out, HOOKS_DIR);
        assert!(!ch2, "re-enable after normalization must be a no-op:\n{_again}");
    }

    // GATE (FIX) — disable must also reach OUR entry when it lives in an inline-array event, removing
    // ours while preserving the user's inline entry.
    #[test]
    fn hooks_disable_handles_inline_array_event() {
        // Inline array carrying BOTH a user hook and ours.
        let user = format!(
            "[hooks]\n\
             SessionStart = [ \
             {{ matcher = \"*\", hooks = [ {{ type = \"command\", command = \"/home/me/my-own-hook.sh\" }} ] }}, \
             {{ matcher = \"*\", hooks = [ {{ type = \"command\", command = \"{HOOKS_DIR}/codex-session-start.sh\" }} ] }} ]\n"
        );
        let (disabled, ch) = codex_hooks_disable_merge(&user);
        assert!(ch, "disable must change (it removed our inline entry)");
        let d = doc(&disabled);
        assert_eq!(
            count_our_hook(&d, "SessionStart", "codex-session-start.sh"),
            0,
            "our SessionStart entry must be removed from the inline array:\n{disabled}"
        );
        assert!(
            disabled.contains("/home/me/my-own-hook.sh"),
            "KILL: user inline hook removed on disable:\n{disabled}"
        );
        // A purely-user inline array (no entry of ours) must be a clean no-op (not a spurious rewrite).
        let user_only = "[hooks]\n\
            SessionStart = [ { matcher = \"*\", hooks = [ { type = \"command\", command = \"/home/me/my-own-hook.sh\" } ] } ]\n";
        let (out2, ch2) = codex_hooks_disable_merge(user_only);
        assert!(!ch2, "disable on a user-only inline array must be a no-op:\n{out2}");
    }

    // GATE (FIX #2) — re-enable from a DIFFERENT hooks-dir UPDATES our stale command in place
    // (versioned/content-addressed CLAUDE_PLUGIN_ROOT case). A basename-only "already ours →
    // continue" would leave the old, now-nonexistent path wired and the hooks would stop firing.
    #[test]
    fn hooks_enable_from_new_dir_updates_stale_command() {
        const OLD_DIR: &str = "/opt/sordino/v1/codex-sordino-plugin/scripts";
        const NEW_DIR: &str = "/opt/sordino/v2/codex-sordino-plugin/scripts";
        let (v1, _) = codex_hooks_enable_merge("", OLD_DIR);
        assert!(v1.contains(&format!("{OLD_DIR}/codex-session-start.sh")));

        let (v2, ch) = codex_hooks_enable_merge(&v1, NEW_DIR);
        assert!(ch, "re-enable from a new dir must change (stale path rewritten)");
        let d = doc(&v2);
        // Still exactly ONE of each (updated in place, NOT duplicated).
        assert_eq!(
            count_our_hook(&d, "SessionStart", "codex-session-start.sh"),
            1,
            "must not duplicate on re-enable from a new dir:\n{v2}"
        );
        assert_eq!(
            count_our_hook(&d, "UserPromptSubmit", "codex-user-prompt-submit.sh"),
            1,
            "must not duplicate on re-enable from a new dir:\n{v2}"
        );
        // The NEW path is wired and the OLD (now-nonexistent) path is GONE.
        assert!(
            v2.contains(&format!("{NEW_DIR}/codex-session-start.sh")),
            "new SessionStart path must be wired:\n{v2}"
        );
        assert!(
            v2.contains(&format!("{NEW_DIR}/codex-user-prompt-submit.sh")),
            "new UserPromptSubmit path must be wired:\n{v2}"
        );
        assert!(
            !v2.contains(OLD_DIR),
            "KILL: stale hooks-dir path must be purged on re-enable:\n{v2}"
        );

        // And a SECOND re-enable from the SAME new dir is now a clean no-op (no spurious change).
        let (v3, ch3) = codex_hooks_enable_merge(&v2, NEW_DIR);
        assert!(!ch3, "re-enable from the same dir must be a no-op:\n{v3}");
    }

    // GATE — disable removes ONLY our entries (by basename) and leaves the user entry intact.
    #[test]
    fn hooks_disable_removes_only_ours_preserving_user() {
        // Start from a user SessionStart hook + our two entries layered on.
        let user = "[[hooks.SessionStart]]\n\
            matcher = \"*\"\n\
            [[hooks.SessionStart.hooks]]\n\
            type = \"command\"\n\
            command = \"/home/me/my-own-hook.sh\"\n";
        let (enabled, _) = codex_hooks_enable_merge(user, HOOKS_DIR);
        let (disabled, ch) = codex_hooks_disable_merge(&enabled);
        assert!(ch, "disable must change (it removed our entries)");
        let d = doc(&disabled);
        // Ours gone; user's SessionStart survives.
        assert_eq!(
            count_our_hook(&d, "SessionStart", "codex-session-start.sh"),
            0,
            "our SessionStart entry must be removed:\n{disabled}"
        );
        assert_eq!(
            count_event_groups(&d, "SessionStart"),
            1,
            "exactly the user's SessionStart group should remain:\n{disabled}"
        );
        assert!(
            disabled.contains("/home/me/my-own-hook.sh"),
            "KILL: user hook removed on disable:\n{disabled}"
        );
        // Our UserPromptSubmit entry (the user had none) is gone AND its empty array is dropped.
        assert_eq!(count_event_groups(&d, "UserPromptSubmit"), 0);
        assert!(
            !disabled.contains("UserPromptSubmit"),
            "empty UserPromptSubmit array should be dropped:\n{disabled}"
        );
    }

    // GATE — disable on a config with only-our entries drops them and the now-empty arrays + [hooks].
    #[test]
    fn hooks_disable_only_ours_drops_empty_hooks_table() {
        let (enabled, _) = codex_hooks_enable_merge("", HOOKS_DIR);
        let (disabled, ch) = codex_hooks_disable_merge(&enabled);
        assert!(ch);
        let d = doc(&disabled);
        assert_eq!(count_event_groups(&d, "SessionStart"), 0);
        assert_eq!(count_event_groups(&d, "UserPromptSubmit"), 0);
        assert!(
            d.get("hooks").is_none(),
            "empty [hooks] table must be dropped:\n{disabled}"
        );
        // A second disable is a no-op.
        let (_again, ch2) = codex_hooks_disable_merge(&disabled);
        assert!(!ch2, "disable on a config with no hooks must be a no-op");
    }

    // CUMULATIVE-GATE HIGH: a user hook MANUALLY co-located with ours in the SAME MatcherGroup must
    // survive disable (remove only OUR entry from the group's hooks array, never the whole group).
    #[test]
    fn hooks_disable_preserves_user_hook_co_located_in_same_group() {
        let co_located = format!(
            "[[hooks.SessionStart]]\n\
             matcher = \"*\"\n\
             [[hooks.SessionStart.hooks]]\n\
             type = \"command\"\n\
             command = \"/home/me/user-hook.sh\"\n\
             [[hooks.SessionStart.hooks]]\n\
             type = \"command\"\n\
             command = \"{HOOKS_DIR}/codex-session-start.sh\"\n"
        );
        let (disabled, ch) = codex_hooks_disable_merge(&co_located);
        assert!(ch, "disable must remove our co-located entry");
        let d = doc(&disabled);
        assert_eq!(
            count_our_hook(&d, "SessionStart", "codex-session-start.sh"),
            0,
            "our entry must be removed from the shared group:\n{disabled}"
        );
        assert_eq!(
            count_event_groups(&d, "SessionStart"),
            1,
            "the shared group must SURVIVE (it still holds the user hook):\n{disabled}"
        );
        assert!(
            disabled.contains("/home/me/user-hook.sh"),
            "KILL: user hook co-located with ours was deleted on disable:\n{disabled}"
        );
    }

    // CUMULATIVE-GATE HIGH: ownership is the trailing `scripts/<name>` path, NOT a bare basename —
    // a user's own hook that merely shares our FILENAME elsewhere must NOT be treated as ours.
    #[test]
    fn hook_ownership_requires_scripts_path_not_bare_basename() {
        assert!(!codex_hook_command_is_ours(
            "/home/u/codex-session-start.sh",
            "codex-session-start.sh"
        ));
        assert!(!codex_hook_command_is_ours(
            "/home/u/bin/codex-user-prompt-submit.sh",
            "codex-user-prompt-submit.sh"
        ));
        // PATH-COMPONENT boundary: a dir whose basename merely ENDS in "scripts" is NOT a `scripts`
        // path component, so a same-named user hook under it must NOT be claimed as ours.
        assert!(!codex_hook_command_is_ours(
            "/home/me/user-scripts/codex-session-start.sh",
            "codex-session-start.sh"
        ));
        assert!(!codex_hook_command_is_ours(
            "/home/me/myscripts/codex-user-prompt-submit.sh",
            "codex-user-prompt-submit.sh"
        ));
        // A bare command (no `scripts` parent) is not ours either.
        assert!(!codex_hook_command_is_ours(
            "codex-session-start.sh",
            "codex-session-start.sh"
        ));
        // Ours, written under the plugin's scripts/ dir, IS recognized (abs + relative).
        assert!(codex_hook_command_is_ours(
            "/opt/p/codex-sordino-plugin/scripts/codex-session-start.sh",
            "codex-session-start.sh"
        ));
        assert!(codex_hook_command_is_ours(
            "scripts/codex-user-prompt-submit.sh",
            "codex-user-prompt-submit.sh"
        ));
    }

    // CUMULATIVE-GATE MED: disable must NOT restore the saved prior model_provider over a NEWER user
    // selection (the user switched model_provider away from us after enabling).
    #[test]
    fn disable_does_not_clobber_newer_user_provider() {
        let enabled = changed(codex_enable_merge("model_provider = \"openai\"\n", ID, URL));
        let switched = enabled.replace(
            "model_provider = \"sordino\"",
            "model_provider = \"anthropic\"",
        );
        assert!(
            switched.contains("model_provider = \"anthropic\""),
            "setup: provider switched away from us"
        );
        let out = changed(codex_disable_merge(&switched, ID));
        let d = doc(&out);
        assert_eq!(
            provider_of(&d),
            Some("anthropic"),
            "disable must NOT clobber the user's newer model_provider with the saved prior:\n{out}"
        );
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
            // then ONLY mean "a prior /sordino:uninstall's strip didn't land" (safe to strip). If we
            // wrote the route first and the registry write then failed, the next session would
            // silently strip the route we just enabled — UNMASKING against the user's fresh intent.
            sordino_state::registry_set(
                &canonical(&project_root()),
                sordino_state::PlumbState::Plumbed,
            )?;
            settings_enable(&url, &zport, &statusline)?
        }
        SettingsAction::Disable { all } => {
            if all {
                // Multi-project sweep: no exit-3 contract, no per-project opt-out (entries are
                // removed). Exits 0 on a full or empty sweep; exits NON-ZERO when some projects
                // could not be cleaned, so a scripted pre-uninstall can gate on success.
                settings_disable_all()?;
                return Ok(());
            }
            let outcome = settings_disable()?;
            // Opt the project out so SessionStart never AUTO-re-plumbs it (a later explicit
            // /sordino:enable clears the opt-out). Best-effort.
            let _ = sordino_state::registry_set(
                &canonical(&project_root()),
                sordino_state::PlumbState::Optout,
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
// Sordino writes these into the project's settings.local.json on enable and removes them on
// disable. They constrain the MODEL's own tool calls. Two facts about how Claude Code routes
// permissions shape them — and correct an earlier misconception worth stating plainly:
//   - SessionStart/PreToolUse HOOKS run outside the permission system (their writes are never
//     classifier-gated): that is how `sordino-hooks` edits settings.local.json freely.
//   - `!`-prefixed slash-command bash does NOT bypass permissions. It goes through the SAME
//     canUseTool path as a model Bash call and, in `auto` mode, the auto-mode classifier — which
//     is exactly why a bare `/sordino:disable` was getting denied ("disabling a privacy proxy").
//     Our `/sordino:` commands keep working because each command's markdown frontmatter declares
//     a script-scoped rule: `allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/<name>.sh":*)`.
//     Claude Code injects that as a COMMAND-SOURCED allow rule for the duration of that command's
//     own bang, so it (a) clears the classifier DETERMINISTICALLY for the user's slash command and
//     (b) does NOT apply to a model-issued `Bash` of the same script — `disable-model-invocation`'s
//     user-only property survives. The rule MUST be path-scoped: `auto` mode strips any allow rule
//     that grants the `bash` interpreter wildcard (`Bash`, `Bash(bash:*)`) as "arbitrary
//     execution", but keeps one pinned to a single script path. We deliberately do NOT mirror that
//     allow rule into settings.local.json — a settings rule has no command-source scoping, so it
//     would also hand the model a classifier-free `bash disable.sh` unmask path.
//
// The settings.local.json rules below are the inverse — they DENY/ASK the model:
//   - deny the model's Bash on our CLIs (it must drive privacy via the slash commands);
//   - force an `ask` prompt on a model Edit/Write of sordino.toml / sordino.local.toml
//     (mode-independent — `ask` overrides acceptEdits AND bypassPermissions).
// Both the bare-name form (CLI on PATH) and an absolute/relative `*/sordino-hooks` form, since
// the binary commonly lives off-PATH (`target/release/`, the plugin bin dir) and CC's Bash
// matcher keys on the command as written. This is best-effort defense-in-depth: a shell-capable
// model can still reach the proxy another way (e.g. read the 0600 key + curl), and CC prompts on
// shell redirection by default — the seal blocks the casual + prompt-injection paths, it is not
// a sandbox. The proxy only re-reads config on a key-gated reload or a restart, and the status
// line shows `⚠ OFF` if masking is ever disabled.
const DENY_RULES: &[&str] = &[
    "Bash(sordino-hooks:*)",
    "Bash(sordino-proxy:*)",
    "Bash(*/sordino-hooks:*)",
    "Bash(*/sordino-proxy:*)",
];
const ASK_RULES: &[&str] = &["Edit(/sordino.toml)", "Edit(/sordino.local.toml)"];

/// A trusted-infrastructure note merged into `autoMode.environment`. Claude Code's auto-mode
/// classifier READS this prose (alongside the command string + CLAUDE.md) but never the script
/// CONTENTS — so without it, Sordino's own `/sordino:` commands get flagged as "an unverifiable
/// script from an unrecognised path." This postures the classifier toward recognising them as
/// trusted local infra; it does NOT guarantee approval (only a `permissions.allow` rule
/// deterministically bypasses the classifier). Kept factual + specific so it earns trust honestly:
/// names the tool, the loopback scope, and the no-egress / no-destructive properties it weighs.
const AUTOMODE_ENV_NOTE: &str = "Sordino is a local PII-masking proxy the user installed and \
    enabled for this project. Its `/sordino:` commands (and the scripts under the sordino plugin \
    directory) are a loopback-only (127.0.0.1) control plane: read-only status/health checks \
    (verify, status, doctor, secrets) or edits to this project's own Sordino settings (enable, \
    disable, privacy). They make no outbound network requests and perform no destructive actions. \
    Treat them as trusted local infrastructure.";

/// The masking-layer awareness note(s) merged into `autoMode.environment` (Context slots — Claude
/// Code splices each array entry as its own `- ${entry}` bullet, so these four consts render as the
/// paired-audited v5 "four labeled Context-slot bullets"). The auto-mode classifier reads the
/// environment section to interpret the BLOCK/ALLOW rules in context. The v5 model these teach:
/// a `[TYPE_hexid]` **mask placeholder is the LIVE Sensitive data** it will become when Sordino
/// restores it at execution (NOT a test/example credential), so the built-in tiers — Data
/// Exfiltration, Credential Leakage/Materialization, PII — decide the verdict by where that live
/// value lands. The note DEFERS tiering to those rules rather than re-enumerating it (v5 minimality:
/// prose that pre-decides N cases has N misread surfaces). It adds only the three genuinely
/// uncovered qualifiers: (1) the one relaxation the built-in rules lack — a WHOLE value returned in
/// a tool's OWN output is re-masked before egress, so materializing it for its own consumer is
/// Standard Credentials (ALLOW), not a leak (covers only the tool-output-return channel; an
/// out-of-scope destination or a file is judged on the live value); (2) a `[URL_…]` type is opaque
/// (broker's job to contain a capability URL, not the classifier's); (3) Masking Circumvention still
/// bites on splitting/spacing/re-encoding or reassembling a would-be-masked value, provenance-gated.
/// Wording is preserved VERBATIM from GUIDANCE-DRAFT-automode.md `## The wording` (v5) — the paired
/// audit diffs it. Bullet 4 defers to [`AUTOMODE_SOFT_DENY_MASKING`] ("Masking Circumvention") by
/// name, which MUST stay co-present.
const AUTOMODE_ENV_MASKING_NOTE: &str = "**Masking proxy (Sordino)**: this project's traffic — including your own classification request — is routed through Sordino, which replaces real secrets and personal data with **mask placeholders** shaped `[TYPE_hexid]` (`[API_KEY_…]`, `[EMAIL_ADDRESS_…]`, `[URL_…]`); you see only these, not the raw value. A placeholder is not a test or example credential — at execution on the user's machine Sordino restores it to the real value. So **treat a placeholder as the live Sensitive data it will become and apply the existing rules to that value**: Data Exfiltration, Credential Leakage/Materialization, and PII handling already decide the tier by where the value lands — let them, judging each placeholder on its own.";
const AUTOMODE_ENV_MASKING_RELAXATION: &str = "**One relaxation those rules lack**: a value that comes back WHOLE in a tool's own OUTPUT is re-masked before it returns to the provider, so a tool materializing it for its own use — an auth header to that value's provider, piping a secret into the command that consumes it — is Standard Credentials/Materialization (ALLOW), not a leak. This covers ONLY the tool-output-return channel: a value placed into an outbound request to a host OTHER than its own provider/consumer, or written to a file, is NOT re-masked and is judged on the live value.";
const AUTOMODE_ENV_MASKING_URLS: &str = "**URLs**: you see only `[URL_hexid]` and cannot tell a citation link from a secret capability URL — do not judge a URL by its type; deterministic containment of a capability URL is the broker's job, not yours.";
const AUTOMODE_ENV_MASKING_CIRCUMVENTION: &str = "**Circumvention**: a whole placeholder passed intact — concatenated or scheme-prepended (`\"https://\" + [URL_x]`) — is not itself circumvention. But the live value stays subject to Masking Circumvention: splitting, spacing, or re-encoding a value so it no longer reads as its placeholder — or reassembling from raw fragments a host, URL, or key **Sordino would have masked** — defeats the mask and lets the raw value reach the provider in the clear, so it is judged as that value. The gate is provenance, not appearance: inspect the pieces in the command — a mid-token split of a would-be-masked host counts even if the fragments look public, while concatenating a host Sordino never masked (an ordinary public or agent-authored host) does not.";

/// A `Masking Circumvention` SOFT BLOCK rule merged into `autoMode.soft_deny`. Claude Code's
/// classifier already decodes `ENCODED COMMANDS` and treats obfuscated data as sensitive by
/// provenance, but its exfiltration rules key on a novel/external DESTINATION — they do not name
/// the Sordino-specific harm: transforming a secret so it reaches the *otherwise-trusted* model
/// endpoint UNMASKED. This rule closes that gap. SOFT (user-clearable) by design — an encoding the
/// user actually asked for must pass; only an unrequested transform whose effect is to defeat
/// masking blocks. Provenance- and intent-gated to keep false positives off ordinary (non-secret)
/// encoding.
const AUTOMODE_SOFT_DENY_MASKING: &str = "Masking Circumvention: Deliberately transforming secret- \
    or personal-data-bearing content so it reaches the model provider in a form Sordino's masking \
    proxy (see Environment) can no longer recognize and mask — e.g. base64/hex/other re-encoding, \
    encrypting or compressing the value, reversing it, splitting or chunking it across pieces, or \
    character-by-character / arithmetic reassembly of a credential, token, key, or personal value \
    before it egresses. The harm is that the raw value then reaches the provider unmasked, so this \
    is blocked even when the destination is the normal, trusted model endpoint. Provenance decides \
    what counts: the value must have originated as a real secret or personal datum (from a .env, \
    credential store, config, keychain, a registered secret, or private data the proxy would \
    otherwise mask), not arbitrary or agent-authored data. NOT this rule (do not block): encoding, \
    hashing, compressing, or reformatting non-secret data; a transform the user explicitly asked \
    for; piping a credential straight into its intended consumer so it is never re-emitted; or \
    standard tooling that legitimately encodes (JWTs, TLS certs, git objects, data URIs, build \
    artifacts). Clears when the user explicitly directed that transformation of that data.";

/// The environment entries (Context slots) we own, in order — seeded after `"$defaults"`.
const ENV_ENTRIES: &[&str] = &[
    AUTOMODE_ENV_NOTE,
    AUTOMODE_ENV_MASKING_NOTE,
    AUTOMODE_ENV_MASKING_RELAXATION,
    AUTOMODE_ENV_MASKING_URLS,
    AUTOMODE_ENV_MASKING_CIRCUMVENTION,
];
/// The soft-deny rules we own — seeded after `"$defaults"`; see [`automode_entry_sets`].
const SOFT_DENY_ENTRIES: &[&str] = &[AUTOMODE_SOFT_DENY_MASKING];

/// The `(permissions.<key>, our-rules)` pairs we own.
fn permission_rule_sets() -> [(&'static str, &'static [&'static str]); 2] {
    [("deny", DENY_RULES), ("ask", ASK_RULES)]
}

/// The `(autoMode.<key>, our-entries)` pairs we own. Every key's array is seeded with `"$defaults"`
/// FIRST on creation (see [`merge_automode_entries`]) so we only ever ADD to Claude Code's built-in
/// entries at that position. This is load-bearing for `soft_deny`: a non-`"$defaults"` array
/// REPLACES the defaults (Claude Code's `SSt` splice), which would silently drop every built-in
/// block rule (Data Exfiltration, the Credential rules, Irreversible Local Destruction, …).
fn automode_entry_sets() -> [(&'static str, &'static [&'static str]); 2] {
    [("environment", ENV_ENTRIES), ("soft_deny", SOFT_DENY_ENTRIES)]
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
                 overwrite it. Fix it and re-run /sordino:enable."
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

/// Merge our entries into each `autoMode.<key>` array (append-if-absent, preserving the user's
/// entries). Seeds a freshly-created array with `"$defaults"` FIRST, so we only ever ADD to Claude
/// Code's built-in entries at that position — never silently replace them (for `soft_deny` that
/// would drop every built-in block rule). Refuses (rather than clobbers) a non-array value; every
/// owned key is validated array-or-absent UP FRONT so the merge is all-or-nothing — a malformed
/// later key can't leave an earlier key half-seeded/appended.
fn merge_automode_entries(v: &mut Value) -> Result<()> {
    let auto = ensure_object(v, "autoMode");
    // Transactional refuse-not-clobber: reject on ANY malformed key we own before mutating ANY of
    // them, so e.g. a non-array `soft_deny` can't leave `environment` half-merged in `v`.
    for (key, _) in automode_entry_sets() {
        if auto.get(key).is_some_and(|x| !x.is_array()) {
            bail!(
                "settings.local.json autoMode.{key} is not a JSON array; refusing to \
                 overwrite it. Fix it and re-run /sordino:enable."
            );
        }
    }
    for (key, wanted) in automode_entry_sets() {
        let arr = auto
            .entry(key.to_string())
            .or_insert_with(|| json!(["$defaults"]))
            .as_array_mut()
            .ok_or_else(|| {
                // Unreachable after the up-front validation above; kept as a non-panicking guard.
                anyhow::anyhow!(
                    "settings.local.json autoMode.{key} is not a JSON array; refusing to \
                     overwrite it. Fix it and re-run /sordino:enable."
                )
            })?;
        // An EMPTY existing array means "inherit defaults" (Claude Code's SSt returns the built-in
        // list for an empty user array). Appending our entry to it would flip it into a
        // defaults-REPLACING array — for soft_deny that silently drops every built-in block rule —
        // so seed "$defaults" FIRST, exactly as we do for a freshly-created key. A NON-empty user
        // array without "$defaults" is a deliberate replacement and is left as-is (we only append).
        if arr.is_empty() {
            arr.push(Value::String("$defaults".to_string()));
        }
        for w in wanted {
            if !arr.iter().any(|x| x.as_str() == Some(*w)) {
                arr.push(Value::String((*w).to_string()));
            }
        }
    }
    Ok(())
}

/// Every one of our entries is present across all keys (so a re-enable is a true NoOp; an upgrade
/// from a build that lacked one is correctly detected as Changed).
fn automode_entries_present(v: &Value) -> bool {
    automode_entry_sets().iter().all(|(key, wanted)| {
        v.pointer(&format!("/autoMode/{key}"))
            .and_then(Value::as_array)
            .map(|a| wanted.iter().all(|w| a.iter().any(|x| x.as_str() == Some(*w))))
            .unwrap_or(false)
    })
}

/// ANY of our entries is present (so disable still cleans a file carrying only our entries, after
/// the env/statusLine takeover was already removed by hand).
fn any_automode_entry_present(v: &Value) -> bool {
    automode_entry_sets().iter().any(|(key, wanted)| {
        v.pointer(&format!("/autoMode/{key}"))
            .and_then(Value::as_array)
            .map(|a| wanted.iter().any(|w| a.iter().any(|x| x.as_str() == Some(*w))))
            .unwrap_or(false)
    })
}

/// Remove ONLY our entries from each `autoMode.<key>` array, preserving user entries — the inverse
/// of [`merge_automode_entries`]. Drops a key's array that empties or is left as only `"$defaults"`
/// (the no-op sentinel we seeded), and the `autoMode` object if it empties. Returns whether
/// anything changed.
fn remove_automode_entries(v: &mut Value) -> bool {
    let mut changed = false;
    let mut auto_empty = false;
    if let Some(auto) = v.get_mut("autoMode").and_then(Value::as_object_mut) {
        for (key, ours) in automode_entry_sets() {
            if let Some(arr) = auto.get_mut(key).and_then(Value::as_array_mut) {
                let before = arr.len();
                arr.retain(|x| !ours.iter().any(|o| x.as_str() == Some(*o)));
                let this_changed = arr.len() != before;
                changed |= this_changed;
                if this_changed && arr.iter().all(|x| x.as_str() == Some("$defaults")) {
                    auto.remove(key);
                }
            }
        }
        auto_empty = auto.is_empty();
    }
    if auto_empty
        && let Some(root) = v.as_object_mut()
    {
        root.remove("autoMode");
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

/// The status-line command sordino bakes into settings: an ABSOLUTE path to THIS binary's
/// dir so it resolves in the user's bare shell (which won't have the plugin bin dir on
/// PATH). Mirrors enable.sh's format — single-quote only the dir so an install path with
/// spaces survives Claude Code's argv splitting, and keep `<exe> statusline` contiguous and
/// preceded by `/` for the `is_sordino_statusline` ownership check. Used by SessionStart
/// auto-plumb; the explicit /sordino:enable path computes its own from the resolved bin dir.
fn statusline_command() -> String {
    match std::env::current_exe().ok().and_then(|p| {
        Some((
            p.parent()?.to_string_lossy().into_owned(),
            p.file_name()?.to_string_lossy().into_owned(),
        ))
    }) {
        Some((dir, name)) => format!("'{dir}'/{name} statusline"),
        None => "sordino-hooks statusline".to_string(),
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
        .pointer("/env/SORDINO_PORT")
        .and_then(Value::as_str)
        .unwrap_or("");
    // NoOp only when the route AND the model-gating permission rules AND ALL of our auto-mode
    // posture entries (the environment notes + the soft-deny Masking Circumvention rule) are
    // already present; a route-present-but-rules/entries-missing install (e.g. an upgrade from a
    // build before any of them landed) is Changed so the merge below runs.
    let already = base_url_matches(cur_url, url)
        && cur_port == zport
        && permission_rules_present(&local_v)
        && automode_entries_present(&local_v);

    // Status-line takeover: snapshot the user's original line to the sidecar that
    // /sordino:uninstall restores from. NEVER delete the sidecar here — an OLD install routed
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
            "Sordino: wrapping your existing status line (saved to {}; restored on /sordino:uninstall).",
            sidecar.display()
        );
    }

    // Migrate an OLD install that baked routing/our status line into the COMMITTED
    // settings.json: strip OUR env wiring + OUR status line out of it so there is exactly
    // ONE takeover (in local) and the committed file is never the viral dead-pointer. Pass
    // `None` so migration only REMOVES our keys — it never restores into committed; the
    // original is preserved in the sidecar and restored into local by /sordino:uninstall.
    if strip_routing_from(&committed_file, None)?.0 {
        // STDERR (see note above): keeps the SessionStart hook's stdout pure JSON.
        eprintln!(
            "Sordino: migrated routing out of {} into {} (no longer committed).",
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
    env.insert("SORDINO_PORT".to_string(), Value::String(zport.to_string()));
    v["statusLine"] = json!({ "type": "command", "command": statusline });
    // Seal the Approval Kernel: deny the model's Bash on our CLIs + force an `ask` on its
    // edits of sordino.toml/sordino.local.toml. Merge (never clobber) the user's own rules.
    merge_permission_rules(&mut v)?;
    // Posture the auto-mode classifier: environment notes so our local control-plane commands
    // aren't denied as "unverifiable scripts" AND so it knows a masking proxy sits on the wire,
    // plus a `Masking Circumvention` soft-deny rule that blocks transforming a secret out of a
    // maskable form before egress. Merge-not-clobber, each key seeded with "$defaults" so we never
    // drop Claude Code's built-in entries (for soft_deny that would wipe every built-in block rule).
    merge_automode_entries(&mut v)?;

    atomic_write_json(&local_file, &v)?;
    Ok(if already {
        SettingsOutcome::NoOp
    } else {
        SettingsOutcome::Changed
    })
}

/// Best-effort: ensure git won't track the machine-local files this binary writes into
/// `.claude/` — `settings.local.json` (which holds the per-machine loopback
/// `ANTHROPIC_BASE_URL`) and the `sordino-statusline.json` sidecar. We write a
/// `.claude/.gitignore` so the route can't be `git add`-ed into version control and strand a
/// teammate on a dead pointer. Idempotent (only appends entries that are missing; never
/// clobbers existing `.gitignore` content) and non-fatal — routing works regardless, so a
/// failure here only warns on stderr.
fn ensure_local_gitignored(settings_dir: &Path) {
    let gitignore = settings_dir.join(".gitignore");
    let wanted = ["settings.local.json", "sordino-statusline.json"];
    let existing = match std::fs::read_to_string(&gitignore) {
        Ok(s) => s,
        // No file yet → start empty and create it below.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        // The file EXISTS but we can't read it as text (non-UTF-8, perms, a directory, …).
        // Treating it as empty would clobber the user's real .gitignore on the write below, so
        // bail instead — best-effort, warn on stderr only.
        Err(e) => {
            eprintln!(
                "Sordino: could not read {} to confirm settings.local.json is ignored: {e}. \
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
            "# Sordino machine-local routing/state — never commit (per-machine proxy URL)\n",
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
            "Sordino: could not write {} to ignore settings.local.json: {e}. Add \
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
        assert!(c1.lines().any(|l| l.trim() == "sordino-statusline.json"), "{c1:?}");

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
        assert!(c3.lines().any(|l| l.trim() == "sordino-statusline.json"), "{c3:?}");

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
        ASK_RULES, AUTOMODE_ENV_MASKING_CIRCUMVENTION, AUTOMODE_ENV_MASKING_NOTE,
        AUTOMODE_ENV_MASKING_RELAXATION, AUTOMODE_ENV_MASKING_URLS, AUTOMODE_ENV_NOTE,
        AUTOMODE_SOFT_DENY_MASKING, DENY_RULES, ONBOARDING, any_automode_entry_present,
        any_permission_rule_present, automode_entries_present, merge_automode_entries,
        merge_permission_rules, permission_rules_present, remove_automode_entries,
        remove_permission_rules,
    };
    use serde_json::{Value, json};

    fn env_arr(v: &Value) -> Vec<String> {
        key_arr(v, "environment")
    }
    fn key_arr(v: &Value, key: &str) -> Vec<String> {
        v.pointer(&format!("/autoMode/{key}"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }

    #[test]
    fn automode_seeds_defaults_then_appends_across_keys_and_is_idempotent() {
        // Fresh object: EACH key seeds "$defaults" FIRST (never replace built-in defaults), then
        // our entries in order. soft_deny MUST be seeded — a bare rule array would wipe every
        // built-in block rule.
        let mut v = json!({});
        merge_automode_entries(&mut v).unwrap();
        assert_eq!(
            env_arr(&v),
            vec![
                "$defaults".to_string(),
                AUTOMODE_ENV_NOTE.to_string(),
                AUTOMODE_ENV_MASKING_NOTE.to_string(),
                AUTOMODE_ENV_MASKING_RELAXATION.to_string(),
                AUTOMODE_ENV_MASKING_URLS.to_string(),
                AUTOMODE_ENV_MASKING_CIRCUMVENTION.to_string(),
            ],
            "environment: $defaults first, then the trusted-infra note + the four v5 masking slots"
        );
        assert_eq!(
            key_arr(&v, "soft_deny"),
            vec!["$defaults".to_string(), AUTOMODE_SOFT_DENY_MASKING.to_string()],
            "soft_deny: $defaults first (no-wipe), then the Masking Circumvention rule"
        );
        assert!(automode_entries_present(&v));
        assert!(any_automode_entry_present(&v));
        // Re-run must not duplicate any entry.
        merge_automode_entries(&mut v).unwrap();
        assert_eq!(env_arr(&v).iter().filter(|s| *s == AUTOMODE_ENV_NOTE).count(), 1);
        assert_eq!(env_arr(&v).iter().filter(|s| *s == AUTOMODE_ENV_MASKING_NOTE).count(), 1);
        assert_eq!(env_arr(&v).iter().filter(|s| *s == AUTOMODE_ENV_MASKING_RELAXATION).count(), 1);
        assert_eq!(env_arr(&v).iter().filter(|s| *s == AUTOMODE_ENV_MASKING_URLS).count(), 1);
        assert_eq!(
            env_arr(&v).iter().filter(|s| *s == AUTOMODE_ENV_MASKING_CIRCUMVENTION).count(),
            1
        );
        assert_eq!(
            key_arr(&v, "soft_deny").iter().filter(|s| *s == AUTOMODE_SOFT_DENY_MASKING).count(),
            1
        );
    }

    #[test]
    fn v5_automode_wording_and_onboarding_are_wired() {
        // CHANGE 1 — the v5 masking guidance is present across the AUTOMODE env slots, with the
        // load-bearing phrases that make the classifier judge the LIVE value (not the placeholder).
        let env: String = super::ENV_ENTRIES.join("\n");
        assert!(
            env.contains("not a test or example credential"),
            "v5 bullet 1: placeholder is NOT a test/example credential"
        );
        assert!(
            env.contains("is judged on the live value"),
            "v5 bullet 2 (relaxation): out-of-scope / file egress is judged on the live value"
        );
        // The circumvention slot must defer to the co-present soft-deny rule BY NAME.
        assert!(AUTOMODE_ENV_MASKING_CIRCUMVENTION.contains("Masking Circumvention"));
        assert!(AUTOMODE_SOFT_DENY_MASKING.starts_with("Masking Circumvention:"));

        // CHANGE 2 — ONBOARDING carries the Issue-3 non-fabrication guidance and no longer makes
        // the stale unqualified "tool arguments ... restored" claim.
        assert!(ONBOARDING.contains("NEVER invent"), "Issue-3: never invent tokens");
        assert!(
            ONBOARDING.contains("will resolve to nothing"),
            "Issue-3: a fabricated token resolves to nothing (not a write-back channel)"
        );
        assert!(
            ONBOARDING.contains("split, reassemble, or re-encode"),
            "Issue-3: never reassemble/split a masked value across fragments"
        );
        assert!(
            !ONBOARDING.contains("tool arguments"),
            "the stale unqualified 'tool arguments ... restored' claim must be gone (A4b whole-value)"
        );
        // The A4b whole-value semantics replace it: whole non-secret restores, a secret/embedded
        // token stays verbatim but is STILL safe to pass.
        assert!(ONBOARDING.contains("WHOLE value of a non-secret field"));
        assert!(ONBOARDING.contains("stays a verbatim token"));
        assert!(ONBOARDING.contains("STILL correct to pass"));
        // Preserved invariants: conditional (no live-state) framing + the status channel + the
        // user-sees-real-values / don't-tell-them-hidden bullet.
        assert!(ONBOARDING.contains("When masking is active"));
        assert!(ONBOARDING.contains("/sordino:verify"));
        assert!(ONBOARDING.contains("Never tell the user their data is hidden"));
    }

    #[test]
    fn automode_partial_entries_are_not_present_the_upgrade_signal() {
        // An install from a build that shipped only the first env note (no masking note, no
        // soft_deny) must read as NOT fully present ⇒ Changed ⇒ the merge below runs on upgrade.
        let mut v = json!({ "autoMode": { "environment": ["$defaults", AUTOMODE_ENV_NOTE] } });
        assert!(!automode_entries_present(&v), "missing masking note + soft_deny ⇒ not present");
        assert!(any_automode_entry_present(&v));
        merge_automode_entries(&mut v).unwrap();
        assert!(automode_entries_present(&v));
    }

    #[test]
    fn automode_merge_preserves_user_entries() {
        // User already curated BOTH keys (their own entries, no "$defaults"): append only, and
        // never inject "$defaults" into a user-populated array.
        let mut v = json!({
            "autoMode": {
                "environment": ["Trusted: my CI box"],
                "soft_deny": ["My Rule: never touch prod"]
            }
        });
        merge_automode_entries(&mut v).unwrap();
        let e = env_arr(&v);
        assert!(e.contains(&"Trusted: my CI box".to_string()), "user env entry kept: {e:?}");
        assert!(e.contains(&AUTOMODE_ENV_NOTE.to_string()));
        assert!(e.contains(&AUTOMODE_ENV_MASKING_NOTE.to_string()));
        assert!(!e.contains(&"$defaults".to_string()), "don't inject $defaults into a user array");
        let s = key_arr(&v, "soft_deny");
        assert!(s.contains(&"My Rule: never touch prod".to_string()), "user soft_deny kept: {s:?}");
        assert!(s.contains(&AUTOMODE_SOFT_DENY_MASKING.to_string()));
        assert!(!s.contains(&"$defaults".to_string()));
    }

    #[test]
    fn automode_merge_seeds_defaults_into_an_empty_existing_array() {
        // A pre-existing EMPTY array means "inherit defaults" to Claude Code. Appending our rule
        // without seeding "$defaults" would turn it into a defaults-REPLACING array — for soft_deny
        // that would wipe every built-in block rule. Must seed "$defaults" first here too.
        let mut v = json!({ "autoMode": { "environment": [], "soft_deny": [] } });
        merge_automode_entries(&mut v).unwrap();
        assert_eq!(env_arr(&v).first().map(String::as_str), Some("$defaults"), "{:?}", env_arr(&v));
        let s = key_arr(&v, "soft_deny");
        assert_eq!(s.first().map(String::as_str), Some("$defaults"), "no-wipe seed: {s:?}");
        assert!(s.contains(&AUTOMODE_SOFT_DENY_MASKING.to_string()));
    }

    #[test]
    fn automode_merge_refuses_a_non_array_key() {
        // A malformed (schema-invalid) autoMode.soft_deny must be REFUSED, never clobbered.
        let mut v = json!({ "autoMode": { "soft_deny": "oops-not-an-array" } });
        assert!(merge_automode_entries(&mut v).is_err());
        assert_eq!(
            v.pointer("/autoMode/soft_deny").and_then(Value::as_str),
            Some("oops-not-an-array"),
            "the user's value must be left intact"
        );
    }

    #[test]
    fn automode_merge_is_transactional_on_a_malformed_later_key() {
        // soft_deny is iterated AFTER environment. A malformed soft_deny must refuse the WHOLE
        // merge before environment is touched — no half-seeded earlier key (all-or-nothing).
        let mut v = json!({ "autoMode": { "soft_deny": "oops-not-an-array" } });
        assert!(merge_automode_entries(&mut v).is_err());
        assert!(
            v.pointer("/autoMode/environment").is_none(),
            "environment must NOT be half-merged when a later key is malformed: {v}"
        );
        assert_eq!(
            v.pointer("/autoMode/soft_deny").and_then(Value::as_str),
            Some("oops-not-an-array"),
            "the user's malformed value must be left intact"
        );
    }

    #[test]
    fn automode_remove_is_a_true_inverse_but_keeps_user_entries() {
        // Fresh enable then disable → autoMode fully gone (we seeded $defaults on every key we
        // own, so each empties to $defaults-only and is dropped, then the object empties).
        let mut v = json!({});
        merge_automode_entries(&mut v).unwrap();
        assert!(remove_automode_entries(&mut v));
        assert!(v.get("autoMode").is_none(), "our-only autoMode dropped on disable: {v}");
        assert!(!any_automode_entry_present(&v));
        // User entries in BOTH keys survive disable; only our entries are stripped.
        let mut v = json!({
            "autoMode": {
                "environment": ["Trusted: my CI box"],
                "soft_deny": ["My Rule: never touch prod"]
            }
        });
        merge_automode_entries(&mut v).unwrap();
        assert!(remove_automode_entries(&mut v));
        assert_eq!(env_arr(&v), vec!["Trusted: my CI box".to_string()]);
        assert_eq!(key_arr(&v, "soft_deny"), vec!["My Rule: never touch prod".to_string()]);
        assert!(!automode_entries_present(&v));
        assert!(!any_automode_entry_present(&v));
    }

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

/// The user's ORIGINAL status line: the highest-precedence NON-sordino `statusLine` across
/// local (which wins) then committed, or `None` if the effective current line is already
/// OUR takeover (its original lives in the sidecar) or neither file has a line. Used by
/// enable to decide what to snapshot for /sordino:uninstall to restore.
fn effective_user_statusline(local_v: &Value, committed_v: &Value) -> Option<Value> {
    for v in [local_v, committed_v] {
        let cmd = v
            .pointer("/statusLine/command")
            .and_then(Value::as_str)
            .unwrap_or("");
        if is_sordino_statusline(cmd) {
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
    // so a non-sordino project surfaced by the scan is never touched. Registry roots are swept
    // unconditionally (settings_disable_at is an idempotent no-op when the route is already
    // gone, and registry_remove then clears the stale entry).
    let mut roots = sordino_state::registry_plumbed_roots();
    let mut seen: std::collections::HashSet<String> = roots.iter().cloned().collect();
    for r in discover_session_cwds() {
        if !seen.contains(&r) && project_baked_route(&r).is_some() {
            seen.insert(r.clone());
            roots.push(r);
        }
    }
    if roots.is_empty() {
        println!("Sordino: no plumbed projects to disable — nothing to sweep.");
        return Ok(());
    }
    let mut done = 0usize;
    for root in &roots {
        match settings_disable_at(Path::new(root)) {
            Ok(_) => {
                // Drop the registry entry entirely (not Optout): the plugin is being removed,
                // so there is nothing left to auto-re-plumb against.
                let _ = sordino_state::registry_remove(root);
                done += 1;
                println!("Sordino: removed routing from {root}");
            }
            Err(e) => {
                eprintln!("Sordino: could not disable {root}: {e} — left as-is.");
            }
        }
    }
    let failed = roots.len() - done;
    if failed == 0 {
        println!(
            "Sordino: swept all {done} plumbed project(s). Routing removed — you can uninstall \
             the plugin safely now."
        );
    } else {
        println!(
            "Sordino: swept {done}/{} plumbed project(s); {failed} could NOT be cleaned (see the \
             warnings above). Do NOT uninstall yet — re-run /sordino:uninstall --all (or remove the \
             routing by hand) so no project is left pointing at a dead proxy.",
            roots.len()
        );
        // Exit NON-ZERO so a scripted pre-uninstall sweep can gate on success. The full per-project
        // summary is already on stdout; exit 1 = "ran, but some projects could not be cleaned"
        // (mirrors verify/doctor's ran-but-failed=1), distinct from the exit 0 of a full sweep or an
        // empty no-op. uninstall.sh forwards this via `exit $?`.
        std::process::exit(1);
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

/// Strip sordino routing from one project's settings (both `settings.local.json` and the
/// committed `settings.json`) and restore any wrapped status line. The single-project
/// `/sordino:uninstall` (current dir) and the `--all` sweep both go through here.
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

/// Remove sordino's routing env (and our status-line takeover) from one settings file.
/// Returns `(changed, restored)`: `changed` is true iff the file existed and carried wiring
/// we removed; `restored` is true iff we wrote `restore` back into this file's status-line
/// slot (so the caller can consume the original and not write it twice). A missing file, or
/// one with no sordino wiring, is a no-op (`(false, false)`). The original status line is
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

    // Ownership matters: `SORDINO_PORT` is OUR private co-key (no user sets it), so it is
    // always ours to remove. `ANTHROPIC_BASE_URL`, however, may be the USER's own (e.g. a
    // corporate gateway) — we only remove it when its VALUE is provably ours (a loopback URL
    // whose port matches our co-baked `SORDINO_PORT`). This keeps disable/migration from deleting a user's own
    // base URL that was merely shadowed by our local route. We still trigger on ANY of our
    // wiring (ours-env or our status line) so disable is a true inverse in asymmetric state.
    // The co-baked SORDINO_PORT identifies OUR (ephemeral) loopback URL even though its port
    // isn't derivable. Tolerate a string or numeric JSON value.
    let baked_zport = v
        .pointer("/env/SORDINO_PORT")
        .and_then(|z| {
            z.as_str()
                .and_then(|s| s.parse::<u16>().ok())
                .or_else(|| z.as_u64().and_then(|n| u16::try_from(n).ok()))
        });
    let abu_is_ours = v
        .pointer("/env/ANTHROPIC_BASE_URL")
        .and_then(Value::as_str)
        .map(|u| is_sordino_base_url(u, baked_zport))
        .unwrap_or(false);
    let zport_present = v.pointer("/env/SORDINO_PORT").is_some();
    let has_env_wiring = abu_is_ours || zport_present;
    let sl_is_ours = is_sordino_statusline(
        v.pointer("/statusLine/command")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    // Also trigger when only our permission rules OR any of our auto-mode entries remain
    // (env/statusLine hand-removed) so disable stays a true inverse and never leaves them orphaned.
    let has_perms_wiring = any_permission_rule_present(&v);
    let has_automode_entries = any_automode_entry_present(&v);
    if !has_env_wiring && !sl_is_ours && !has_perms_wiring && !has_automode_entries {
        return Ok((false, false));
    }

    // Delete only OUR env keys (and the env object if it ends up empty). A user's own
    // non-loopback ANTHROPIC_BASE_URL is left untouched.
    if let Some(env) = v.get_mut("env").and_then(Value::as_object_mut) {
        env.remove("SORDINO_PORT");
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

    // Strip our model-gating permission rules + all auto-mode posture entries too (preserving any
    // user permissions / environment / soft_deny entries), so disable is a true inverse of enable's
    // merge.
    remove_permission_rules(&mut v);
    remove_automode_entries(&mut v);

    atomic_write_json(settings_file, &v)?;
    Ok((true, restored))
}

/// Is `url` a base URL WE would have written — a path-less loopback authority whose port
/// matches the co-baked `SORDINO_PORT` (`co_key`)? Lets migration/disable tell OUR
/// `ANTHROPIC_BASE_URL` apart from a user's own (a corporate gateway, a different local
/// proxy), so we never delete an env var that isn't ours. The port is OS-assigned (not
/// derivable), so the co-baked `SORDINO_PORT` is the only durable ownership signal.
fn is_sordino_base_url(url: &str, co_key: Option<u16>) -> bool {
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
    // Ours iff the loopback port matches the co-baked SORDINO_PORT. A bare loopback URL that
    // doesn't match is a user's own (a corporate gateway, a different local proxy) and is
    // left untouched.
    co_key == Some(p)
}

#[cfg(test)]
mod base_url_ownership_tests {
    use super::is_sordino_base_url;

    #[test]
    fn ours_is_ephemeral_loopback_matching_co_key() {
        // An OS-assigned ephemeral port is ours ONLY when it matches the co-baked SORDINO_PORT.
        assert!(is_sordino_base_url("http://127.0.0.1:41234", Some(41234)));
        assert!(is_sordino_base_url("http://localhost:53999/", Some(53999)));
        // Same ephemeral URL but a MISMATCHED / absent co-key is NOT claimed as ours.
        assert!(!is_sordino_base_url("http://127.0.0.1:41234", Some(40000)));
        assert!(!is_sordino_base_url("http://127.0.0.1:41234", None));
    }

    #[test]
    fn not_ours_user_gateway_or_mismatched_port() {
        // A user's own base URL must NOT be claimed as ours (else disable/migration would
        // delete their committed env var) -- even with a stale co-key present.
        assert!(!is_sordino_base_url("http://nothost:5000", Some(41234))); // non-loopback host
        assert!(!is_sordino_base_url("http://127.0.0.1:4000", None)); // user's local proxy, no co-key
        assert!(!is_sordino_base_url("http://127.0.0.1:18123/v1", Some(18123))); // has a path -> theirs
        assert!(!is_sordino_base_url("http://127.0.0.1", None)); // no port
        // A loopback port that doesn't match the co-key is not ours.
        assert!(!is_sordino_base_url("http://127.0.0.1:18123", Some(41234)));
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
// doctor — preflight self-check (/sordino:doctor)
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

/// `/sordino:doctor`: run the preflight probes, print a table (or `--json`), exit non-zero on
/// any FAIL. Catches the firewall/loopback/port footguns the masking flow depends on.
fn doctor(json: bool) -> Result<()> {
    let root = canonical(&project_root());
    let probes = vec![
        probe_loopback_self_connect(),
        probe_localhost_resolution(),
        probe_ephemeral_bind(),
        probe_state_dir(),
        probe_project_proxy(&root),
        probe_dual_instance(&root),
        probe_windows_excluded_range(),
        probe_no_bare_or_safe_mode_env(),
        probe_transcript_exposure(&root),
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
            "Sordino doctor — {}",
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

/// `/sordino:verify` — proves THIS session both MASKS and ROUTES, as two DISTINCT verdicts.
/// A green engine is NOT a routed session: Leg 1 (engine masks) is a key-gated canary echo via
/// /sordino/diag/mask; Leg 2 (session routed) is whether $ANTHROPIC_BASE_URL points at this
/// project's proxy. A green engine + red session reads ✗ overall — the exact bug verify exists
/// to surface (masking is on, but this session bypasses it and sends UNMASKED).
fn verify(json: bool) -> Result<()> {
    let root = canonical(&project_root());
    let legs = vec![
        verify_engine_masks(&root),
        verify_session_routed(&root),
        verify_category_coverage(&root),
    ];
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
            "Sordino verify — {}",
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

/// Verify Leg 1: does the proxy actually MASK? A key-gated /sordino/diag/mask canary echo —
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
                Some("open a session in this project (it auto-starts the proxy), or /sordino:doctor"),
            );
        }
    };
    let canary = "verify.canary@example.com";
    let resp = blocking_client()
        .post(format!("http://127.0.0.1:{port}/sordino/diag/mask"))
        .header("x-sordino-key", &key)
        .header("x-sordino-project", sordino_state::project_key(root))
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
                    Some("turn masking on: /sordino:privacy on"),
                )
            }
        }
        _ => probe(
            name,
            ProbeStatus::Fail,
            "the diag/mask canary call failed".to_string(),
            Some("check proxy health with /sordino:doctor"),
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
            Some("restart Claude Code once to apply the route (written but not live this session), or /sordino:enable"),
        )
    }
}

/// Verify disclosure leg F3 (report-only, ALWAYS Info): make it LEGIBLE that a green
/// `verify` still passes whole categories through untouched. Under the Balanced default
/// both Network and Personal are OFF, so their entity classes are sent in clear — this
/// leg names them at preflight. It reads config only (the LIVE snapshot if the proxy is
/// reachable, else the config FILES — see `effective_categories`), opens no extra
/// connection, and mutates nothing. It is never a Pass/Fail and it does NOT close the
/// gap; it only surfaces it.
fn verify_category_coverage(root: &str) -> Probe {
    let name = "category coverage (report-only)";
    let effective = effective_categories(
        live_identity(root),
        &sordino_state::project_key(root),
        root,
    );
    probe(
        name,
        ProbeStatus::Info,
        category_coverage_detail(&effective),
        None,
    )
}

/// Pure copy for [`verify_category_coverage`]: given the EFFECTIVE enabled-category
/// name set (snake_case), name every category that is OFF and what it lets through in
/// clear. Diffs against `sordino_engine::Category::ALL`; the per-category clause is an
/// EXHAUSTIVE (compiler-enforced) 6-arm match, so a new category can't silently ship
/// without a sentence. If every category is on, says so. This describes the
/// pass-through — it does NOT read as if it closes it.
fn category_coverage_detail(effective: &[String]) -> String {
    let on: std::collections::HashSet<&str> = effective.iter().map(String::as_str).collect();
    let mut clauses: Vec<String> = Vec::new();
    for c in sordino_engine::Category::ALL {
        let cat_name = serde_json::to_value(c)
            .ok()
            .and_then(|j| j.as_str().map(str::to_string))
            .unwrap_or_default();
        if on.contains(cat_name.as_str()) {
            continue;
        }
        // Exhaustive over all 6 variants: a new Category variant fails to compile until
        // it gets an honest pass-through sentence here.
        let sentence = match c {
            sordino_engine::Category::Secrets => {
                "API keys/tokens/private keys sent in clear"
            }
            sordino_engine::Category::Financial => {
                "card/IBAN/financial numbers sent in clear"
            }
            sordino_engine::Category::Identity => {
                "SSNs and other identity numbers sent in clear"
            }
            sordino_engine::Category::Contact => {
                "emails/phone numbers sent in clear"
            }
            sordino_engine::Category::Network => {
                "bare URLs/IPs/MACs sent in clear (a real secret in a URL is still caught via Secrets/URL_CREDENTIAL)"
            }
            sordino_engine::Category::Personal => {
                "names/locations need the ML model and are not masked"
            }
        };
        clauses.push(format!("{cat_name} OFF — {sentence}"));
    }
    if clauses.is_empty() {
        "all categories on".to_string()
    } else {
        format!(
            "a green verify still passes whole categories through untouched: {}",
            clauses.join("; ")
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
/// Does the NAME "localhost" resolve to IPv4 first? Sordino always uses the literal 127.0.0.1
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
                "harmless — Sordino uses the literal 127.0.0.1, not the name. Do NOT set \
                 ANTHROPIC_BASE_URL to use \"localhost\".",
            ),
        ),
        None => probe(
            name,
            ProbeStatus::Warn,
            "could not resolve localhost".into(),
            Some("non-fatal — Sordino uses 127.0.0.1 directly"),
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
            Some("pin a static `[proxy] port` in sordino.toml"),
        ),
        Err(e) => probe(
            name,
            ProbeStatus::Fail,
            format!("could not bind :0 ({e})"),
            Some("pin a static `[proxy] port` in sordino.toml"),
        ),
    }
}

/// Is the state dir creatable + writable (and 0600-capable on Unix)?
fn probe_state_dir() -> Probe {
    let name = "state dir writable";
    let dir = match sordino_state::state_dir() {
        Ok(d) => d,
        Err(e) => {
            return probe(
                name,
                ProbeStatus::Fail,
                format!("cannot create the state dir ({e})"),
                Some("set $SORDINO_STATE_DIR to a writable directory"),
            );
        }
    };
    let test = dir.join(format!(".doctor-{}", std::process::id()));
    if let Err(e) = std::fs::write(&test, b"x") {
        return probe(
            name,
            ProbeStatus::Fail,
            format!("cannot write under {} ({e})", dir.display()),
            Some("set $SORDINO_STATE_DIR to a writable directory"),
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
    match sordino_state::live_port(root) {
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
            Some("start a `claude` session here, or run /sordino:enable"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Dual-instance / chained-masker preflight (advisory WARN, read-only)
// ---------------------------------------------------------------------------
//
// Incident this catches: a session served by TWO masking proxies with SEPARATE
// vaults (e.g. one build plus a second build wired in as an "upstream shim"). A
// token minted by one instance is unresolvable FOREIGN garbage to the other, which
// produces non-restoring tokens, "which build served this session" ambiguity, and
// fabricated-looking handles. Doctor never warned about it before.

/// One observed loopback masking control plane during the dual-instance probe. The
/// pure decision below is a function ONLY of these observations + the configured
/// upstream — the I/O (registry walk + `/healthz` verify + config read) is factored
/// out so the decision is unit-tested with no network or filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MaskerObservation {
    /// Loopback port the control plane answered on.
    port: u16,
    /// It identified as a Sordino proxy (nonce-verified `/healthz`, via `live_identity`).
    is_sordino: bool,
    /// Its canonical project root == THIS project's — i.e. our own instance, not a foreign one.
    is_this_project: bool,
}

/// How this session's route (`$ANTHROPIC_BASE_URL`) relates to THIS project's own masking
/// plane. Fed to the pure decision below; resolved by the thin [`observe_routed_endpoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoutedEndpoint {
    /// The route is unset, points at the real provider / a non-loopback gateway, or resolves to
    /// THIS project's own verified proxy — no cross-instance risk.
    OwnOrDirect,
    /// The route points at a DIFFERENT local Sordino instance than this project's own plane —
    /// tokens minted by that instance are unresolvable here.
    ForeignInstance,
}

/// PURE dual-instance / chained-masker decision. Given the observed loopback control
/// planes, this proxy's CONFIGURED upstream target, and how this session is ROUTED, return
/// the advisory WARN detail (or `None` for a clean single-instance setup). Advisory only — the
/// message names the RISK and never reveals a token or secret (a loopback `host:port` is
/// operational config, not a vault value). Three independent signals, any of which fires:
///   (a) a SECOND distinct Sordino control plane is reachable beyond this project's own —
///       separate vaults, so a token from one is foreign garbage to the other;
///   (b) the configured upstream is ITSELF a loopback address (a chained masker) rather
///       than the real provider — masked traffic is handed to a second vault that can't
///       resolve the first's tokens;
///   (c) this session is ROUTED to a DIFFERENT local Sordino instance than this project's own
///       plane — the client mints/resolves against a foreign vault.
/// (a) is the endpoint the client is chained-to as upstream; (c) is the endpoint the client is
/// routed-to. An instance that is NEITHER routed-to (c) NOR chained (b) cannot inject a foreign
/// token into THIS session, so it is harmless and deliberately not scanned for.
fn dual_instance_decision(
    observed: &[MaskerObservation],
    upstream: &str,
    routed: RoutedEndpoint,
) -> Option<String> {
    let foreign = observed
        .iter()
        .filter(|o| o.is_sordino && !o.is_this_project)
        .count();
    let chained = upstream_is_loopback(upstream);
    let foreign_route = routed == RoutedEndpoint::ForeignInstance;
    if foreign == 0 && !chained && !foreign_route {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if foreign_route {
        parts.push(
            "this session's route ($ANTHROPIC_BASE_URL) points at a DIFFERENT local Sordino \
             instance than this project's own masking plane — a FOREIGN-INSTANCE route. Tokens \
             minted/resolved against that instance's separate vault are unresolvable here, so this \
             session can see non-restoring, foreign handles. Route this project's session through \
             THIS project's proxy only."
                .to_string(),
        );
    }
    if foreign > 0 {
        parts.push(format!(
            "{foreign} other running Sordino masking prox{} found on loopback beyond this \
             project's own — each masking instance keeps a SEPARATE vault, so a token minted by \
             one is unresolvable FOREIGN garbage to another (the footgun behind non-restoring \
             tokens and 'which build served this session' ambiguity). Make sure this project's \
             session routes through THIS project's proxy only.",
            if foreign == 1 { "y" } else { "ies" }
        ));
    }
    if chained {
        parts.push(format!(
            "this proxy's configured upstream ({upstream}) is itself a loopback address, not the \
             real provider (api.anthropic.com) — a CHAINED masker. Masked traffic is handed to a \
             SECOND instance with its own vault, which sees only foreign tokens it cannot resolve. \
             Point [proxy] upstream_base_url / $SORDINO_UPSTREAM at the real provider."
        ));
    }
    Some(parts.join(" "))
}

/// PURE: split a URL's authority into `(host, optional port-string)`, tolerant of scheme,
/// userinfo, path, query, fragment, and bracketed IPv6. The authority ends at the first `/`,
/// `?`, or `#`; any userinfo before `@` is dropped; the rightmost `:` outside IPv6 brackets
/// separates the port. Host/port are returned unvalidated — callers decide. Shared by
/// [`upstream_is_loopback`] and [`loopback_url_port_path_tolerant`] so the authority parse
/// lives in ONE place.
fn split_host_port(url: &str) -> (&str, Option<&str>) {
    let s = url.trim();
    let rest = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    // Authority ends at the first path/query/fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Drop any userinfo before the last `@`.
    let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    if let Some(end) = hostport.strip_prefix('[').and_then(|_| hostport.find(']')) {
        // Bracketed IPv6: `[::1]:port` → host `::1`, port after the `]`.
        let host = &hostport[1..end];
        let port = hostport[end + 1..].strip_prefix(':');
        (host, port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    }
}

/// PURE: is `host` a loopback address? `localhost`, `::1`, or anything in `127.0.0.0/8`.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "::1")
        || host
            .parse::<std::net::Ipv4Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// PURE: is `url`'s host a loopback address (regardless of scheme/port/path)? Broader than
/// [`loopback_url_port`] (which rejects any path) because a chained masker may forward to
/// `http://127.0.0.1:PORT/v1`. Handles `scheme://user@host:port/path`, bracketed IPv6, and
/// the whole `127.0.0.0/8` block.
fn upstream_is_loopback(url: &str) -> bool {
    is_loopback_host(split_host_port(url).0)
}

/// PURE: like [`loopback_url_port`] but PATH-TOLERANT — extract the port from a loopback URL
/// even when it carries a path/query/fragment (notably the SessionStart session route
/// `http://127.0.0.1:PORT/sordino/session/<id>`). Reuses [`split_host_port`]/[`is_loopback_host`]
/// with [`upstream_is_loopback`] rather than duplicating the authority parse. Returns the port
/// ONLY when the host is loopback AND a numeric port is present; `None` for a non-loopback host
/// or a port-less URL. Used by [`observe_routed_endpoint`] so a path-bearing FOREIGN route is
/// still probed for its identity instead of resolving quietly to OwnOrDirect.
fn loopback_url_port_path_tolerant(url: &str) -> Option<u16> {
    let (host, port) = split_host_port(url);
    if !is_loopback_host(host) {
        return None;
    }
    port?.parse::<u16>().ok()
}

/// PURE upstream resolution mirroring the proxy's own layering (`config.rs::merged_value`:
/// user < project < local, so local wins), with the `$SORDINO_UPSTREAM` launch override on
/// top. `layers` carries the raw TOML text of each config layer in HIGHEST-precedence-first
/// order (local, project, user); the first layer that sets a non-empty `[proxy]
/// upstream_base_url` wins, else the real-provider default. Pure (no fs/net) so the layer
/// precedence is unit-tested directly, with no env mutation.
fn resolve_upstream(env_override: Option<&str>, layers: &[Option<&str>]) -> String {
    if let Some(u) = env_override.map(str::trim).filter(|s| !s.is_empty()) {
        return u.to_string();
    }
    for text in layers.iter().flatten() {
        let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
            continue;
        };
        if let Some(u) = doc
            .get("proxy")
            .and_then(toml_edit::Item::as_table_like)
            .and_then(|t| t.get("upstream_base_url"))
            .and_then(toml_edit::Item::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return u.to_string();
        }
    }
    "https://api.anthropic.com".to_string()
}

/// Read this proxy's EFFECTIVE upstream target — what it forwards masked traffic to — resolved
/// the SAME way the proxy resolves it (`config.rs::load` -> `merged_value`), so the probe's
/// notion of "the configured upstream" matches the proxy's actual behaviour across ALL layers:
/// the `$SORDINO_UPSTREAM` launch override wins, else `[proxy] upstream_base_url` from the
/// project's config with the proxy's own precedence (`sordino.local.toml` > `sordino.toml` >
/// the USER layer at [`sordino_state::user_config_path`]), else the real-provider default.
/// Including the user layer is load-bearing: `merged_value` folds it in, so a user-layer loopback
/// upstream chains the masker just as a project one does — omitting it was a false negative on the
/// exact incident shape (and would print an affirmatively-false PASS). Reads config only; opens no
/// connection. The decision itself lives in the pure [`resolve_upstream`].
fn configured_upstream(root: &str) -> String {
    let env_override = std::env::var("SORDINO_UPSTREAM").ok();
    let local = std::fs::read_to_string(Path::new(root).join("sordino.local.toml")).ok();
    let project = std::fs::read_to_string(Path::new(root).join("sordino.toml")).ok();
    let user = std::fs::read_to_string(sordino_state::user_config_path()).ok();
    resolve_upstream(
        env_override.as_deref(),
        &[local.as_deref(), project.as_deref(), user.as_deref()],
    )
}

/// Enumerate the LIVE Sordino control planes on loopback — the lightweight, reliable signal
/// (the plumbed-project registry, NOT a port scan or process walk). This project's own verified
/// instance is recorded first (it may not be in the registry on a first session); every other
/// plumbed project is included IFF its recorded proxy is live and nonce-verified (`live_identity`),
/// so a stale/crashed record never counts as a second instance.
fn observe_loopback_maskers(root: &str) -> Vec<MaskerObservation> {
    let mut out: Vec<MaskerObservation> = Vec::new();
    if let Some((port, _key)) = live_identity(root) {
        out.push(MaskerObservation {
            port,
            is_sordino: true,
            is_this_project: true,
        });
    }
    for other in sordino_state::registry_plumbed_roots() {
        let other_c = canonical(Path::new(&other));
        if other_c == root {
            continue; // our own instance is already recorded above
        }
        if let Some((port, _key)) = live_identity(&other_c) {
            out.push(MaskerObservation {
                port,
                is_sordino: true,
                is_this_project: false,
            });
        }
    }
    out
}

/// Resolve how THIS session is ROUTED (thin I/O for the pure decision). The registry walk in
/// [`observe_loopback_maskers`] only sees PLUMBED instances; it misses an UNREGISTERED loopback
/// Sordino that `$ANTHROPIC_BASE_URL` nonetheless points the client at. That routed endpoint is
/// one of only two instances that can actually inject a foreign token into this session (the
/// other being whatever THIS proxy chains to as upstream — signal (b)); a Sordino that is neither
/// routed-to nor chained is harmless to this session, which is why we do NOT port-scan for it
/// (a blind loopback scan is invasive and false-positive-prone).
///
/// `OwnOrDirect` (no warning) when the route is unset, points at the real provider / a
/// non-loopback gateway, or resolves to this project's OWN verified proxy port. `ForeignInstance`
/// only when the route is a loopback endpoint (bare OR path-bearing — notably the SessionStart
/// `.../sordino/session/<id>` route) on a DIFFERENT port that actually identifies as a Sordino
/// proxy (nonce on `/healthz`) — a foreign local server that is not Sordino cannot mint our
/// tokens, so it never trips a false positive. (If this project's own proxy is not currently
/// live, there is no own plane to match, so a loopback Sordino on the route is treated as foreign —
/// correct: it is not verifiably ours.)
fn observe_routed_endpoint(root: &str) -> RoutedEndpoint {
    let abu = std::env::var("ANTHROPIC_BASE_URL").unwrap_or_default();
    let Some(routed_port) = loopback_url_port_path_tolerant(&abu) else {
        // Unset, api.anthropic.com, or a non-loopback corporate gateway — not a loopback masking
        // endpoint to probe. PATH-TOLERANT: a loopback route carrying a path (the SessionStart
        // session route `.../sordino/session/<id>`) still yields its port here, so we probe THAT
        // port's identity instead of silently resolving to OwnOrDirect and missing a foreign
        // instance (the dual-instance incident shape this probe exists to catch).
        return RoutedEndpoint::OwnOrDirect;
    };
    // Routing to our OWN verified plane is the correct single-instance case.
    if live_identity(root).map(|(p, _)| p) == Some(routed_port) {
        return RoutedEndpoint::OwnOrDirect;
    }
    // A different loopback port: foreign only if it actually identifies as a Sordino proxy.
    match proxy_identity(routed_port) {
        Some((_build, nonce)) if !nonce.is_empty() => RoutedEndpoint::ForeignInstance,
        _ => RoutedEndpoint::OwnOrDirect,
    }
}

/// Dual-instance / chained-masker preflight (advisory WARN, read-only). Thin I/O wrapper around
/// the pure [`dual_instance_decision`]: observe the live control planes, read the configured
/// upstream, decide. A WARN never fails doctor (only Fail flips exit); never reveals a secret.
fn probe_dual_instance(root: &str) -> Probe {
    let name = "single masking instance (no dual-vault / chained masker)";
    let observed = observe_loopback_maskers(root);
    let upstream = configured_upstream(root);
    let routed = observe_routed_endpoint(root);
    match dual_instance_decision(&observed, &upstream, routed) {
        Some(detail) => probe(
            name,
            ProbeStatus::Warn,
            detail,
            Some(
                "route this project's session through THIS project's proxy only, and set the \
                 proxy's upstream to the real provider (api.anthropic.com) — never chain one \
                 masking proxy into another",
            ),
        ),
        None => probe(
            name,
            ProbeStatus::Pass,
            "one masking instance for this project; upstream is the real provider".into(),
            None,
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

/// Claude Code's `--bare`/`CLAUDE_CODE_SIMPLE=1` and `--safe-mode`/`CLAUDE_CODE_SAFE_MODE=1`
/// skip plugin-hook loading entirely (confirmed against the shipped cli.js control flow) — a
/// session started that way never runs Sordino's SessionStart auto-plumb OR its fail-closed
/// UserPromptSubmit intake gate, so an unrouted project's real PII can reach the API provider
/// with zero warning. This probe can only ever run FROM a normal (non-bare) session — the same
/// mechanism that would fire it is exactly what a `--bare` session disables — so it cannot
/// self-detect a one-off `--bare` flag typed in that same terminal (the user sees that flag
/// themselves). What it CAN catch: `CLAUDE_CODE_SIMPLE`/`CLAUDE_CODE_SAFE_MODE` silently
/// exported as a persistent env var (a shell rc file, a CI job, a wrapper script) that would
/// disable Sordino for every future `claude` invocation from this shell without a `--bare` flag
/// ever being typed again.
fn probe_no_bare_or_safe_mode_env() -> Probe {
    let name = "no --bare/--safe-mode env footgun";
    let simple_set = std::env::var("CLAUDE_CODE_SIMPLE").is_ok_and(|v| is_truthy_flag(&v));
    let safe_mode_set = std::env::var("CLAUDE_CODE_SAFE_MODE").is_ok_and(|v| is_truthy_flag(&v));
    match (simple_set, safe_mode_set) {
        (false, false) => probe(
            name,
            ProbeStatus::Pass,
            "CLAUDE_CODE_SIMPLE / CLAUDE_CODE_SAFE_MODE are not set in this shell".into(),
            None,
        ),
        (simple, safe) => {
            let which = match (simple, safe) {
                (true, true) => "CLAUDE_CODE_SIMPLE and CLAUDE_CODE_SAFE_MODE are",
                (true, false) => "CLAUDE_CODE_SIMPLE is",
                _ => "CLAUDE_CODE_SAFE_MODE is",
            };
            probe(
                name,
                ProbeStatus::Warn,
                format!(
                    "{which} set in this shell — every `claude` invocation from here skips \
                     plugin-hook loading (Claude Code's own --bare/--safe-mode behavior), so \
                     Sordino's auto-plumb and intake gate never run and PII can reach the API \
                     provider unmasked with no warning"
                ),
                Some("unset it, or run claude without inheriting it, on any project you rely on Sordino for"),
            )
        }
    }
}

/// Doctor disclosure leg F11 (report-only, ALWAYS Info): report the COUNT and
/// approximate total SIZE of THIS project's local session transcripts — plaintext the
/// harness persists locally (threat-model L5). Discovery reads a single `cwd` line per
/// candidate dir via `first_cwd_in_jsonl` to match exactly one dir to `root`; the sizing
/// path ([`transcript_exposure_detail`]) then uses `read_dir` + `metadata().len()` ONLY
/// and opens NO `*.jsonl` content. It echoes NO transcript value and writes/rewrites
/// NO harness file. It makes L5 discoverable; it does NOT close it (transcript retention
/// is the harness's own lever, outside Sordino's control). Because doctor's human table
/// prints `remediation` only for Fail|Warn probes, an Info probe's remediation is dropped
/// from human output — so the scrub pointer lives in the DETAIL to stay discoverable.
fn probe_transcript_exposure(root: &str) -> Probe {
    let name = "local session transcripts (report-only)";
    // Narrow the `discover_session_cwds` walk to THIS project: find the single
    // projects/<encoded> dir whose first session log's `cwd` canonicalizes to `root`.
    let project_dir = claude_config_dir()
        .map(|d| d.join("projects"))
        .and_then(|projects| {
            let entries = std::fs::read_dir(&projects).ok()?;
            for sub in entries.filter_map(|e| e.ok()).map(|e| e.path()) {
                if !sub.is_dir() {
                    continue;
                }
                let Ok(files) = std::fs::read_dir(&sub) else {
                    continue;
                };
                // One session log with a cwd identifies the dir — every log in it shares one.
                for f in files.filter_map(|e| e.ok()).map(|e| e.path()) {
                    if f.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                        continue;
                    }
                    // Only a log that actually yields a `cwd` identifies the dir — a
                    // leading cwd-less log (e.g. summary-only) must NOT short-circuit
                    // it, matching the `discover_session_cwds` walk (breaks on Some only).
                    let Some(cwd) = first_cwd_in_jsonl(&f) else {
                        continue;
                    };
                    if canonical(Path::new(&cwd)) == root {
                        return Some(sub);
                    }
                    break;
                }
            }
            None
        });

    let (present, count, bytes) = match &project_dir {
        Some(dir) => transcript_exposure_detail(dir),
        None => (false, 0, 0),
    };

    if !present {
        return probe(
            name,
            ProbeStatus::Info,
            "no transcripts found for this project".to_string(),
            None,
        );
    }

    let detail = format!(
        "the harness keeps {count} plaintext session transcript(s) for this project on local \
         disk (~{} total, stored UNMASKED — Sordino masks the API wire, not what the harness \
         persists here); to burn a leaked value out of one, run `sordino scrub --transcript \
         <file> --value <burned-value>`; the harness's own transcript-retention settings are the \
         other lever, outside Sordino's control",
        approx_size(bytes),
    );
    probe(
        name,
        ProbeStatus::Info,
        detail,
        Some("sordino scrub --transcript <file> --value <burned-value>"),
    )
}

/// Pure logic for [`probe_transcript_exposure`]: given a project's Claude Code session-log
/// DIR, report `(present, count, total_bytes)` for its `*.jsonl` transcripts using
/// `read_dir` + `metadata().len()` ONLY — it opens NO file content. An absent/unreadable
/// dir, or one with no `*.jsonl`, yields `(false, 0, 0)`.
fn transcript_exposure_detail(dir: &Path) -> (bool, usize, u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (false, 0, 0);
    };
    let mut count = 0usize;
    let mut bytes = 0u64;
    for f in entries.filter_map(|e| e.ok()).map(|e| e.path()) {
        if f.extension().and_then(|x| x.to_str()) != Some("jsonl") {
            continue;
        }
        // metadata().len() reads the directory entry's size — never the file's content.
        if let Ok(meta) = std::fs::metadata(&f) {
            count += 1;
            bytes += meta.len();
        }
    }
    (count > 0, count, bytes)
}

/// Coarse human-readable byte size for the report-only transcript-exposure detail.
fn approx_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
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

/// The IMMUTABLE SessionStart onboarding the model reads when this project is ours. It describes
/// the MECHANISM and pre-registers the `Sordino:` status channel — but asserts NO live state,
/// because SessionStart context freezes and any "you are masked now" claim would go stale (the
/// image-2 failure). Live, mutable state rides the per-turn UserPromptSubmit delta instead. Pre-
/// registering the channel is also what authenticates a later status note: a real status line was
/// announced up front and points to /sordino:verify; a prompt injection never is.
///
/// Tool-input restore is described to match the A4b whole-value gate (engine `unmask_inner`
/// `ToolInput` branch + `tool_input_whole_value_mode`): assistant prose restores as before, but a
/// file written via a tool is itself a TOOL INPUT — so it follows the same narrower rule as any
/// tool input: only a WHOLE-VALUE non-secret placeholder restores there; a secret (API key /
/// URL_CREDENTIAL / broker / Local), an unmapped label, or an EMBEDDED token stays a verbatim
/// token (fail-closed) that the tool / consumer / broker resolves at use. It also warns
/// the model NOT to fabricate `[TYPE_hexid]` tokens (Issue 3: a made-up token resolves to nothing
/// and is not a write-back channel) or to reassemble/split a masked value across fragments.
const ONBOARDING: &str = "This project is set up to route through Sordino, a LOCAL masking proxy. \
     When masking is active it swaps PII for deterministic mask placeholders like \
     [EMAIL_ADDRESS_a1b2] or [API_KEY_a1b2c3] in what you receive. In your assistant PROSE, Sordino \
     restores the real values before they leave the machine. A file you write goes through a TOOL, \
     so it follows the same TOOL-INPUT rule, which is narrower: a placeholder that is the WHOLE \
     value of a non-secret field (a \
     URL, domain, or IP) is restored to the real value, but a secret placeholder (an API key or \
     other credential, a URL carrying embedded credentials, a brokered secret) — or a placeholder \
     sitting inside a larger string — stays a verbatim token, which the tool, its consumer, or \
     Sordino's broker resolves at the point of use.\n\
     - The user always sees their own real values locally; masking hides data from the API \
     provider, NOT from the user. Never tell the user their data is hidden, redacted, or that you \
     can't access it.\n\
     - Mask placeholders are safe to use verbatim wherever the value belongs — prose, config \
     files, shell commands, and tool inputs. Writing a placeholder into a file restores the real \
     value ONLY when the placeholder is the whole non-secret field value; a secret placeholder (or \
     one embedded in a larger string) stays a verbatim token in the file, which the tool, its \
     consumer, or Sordino's broker resolves at use. Either way a placeholder is STILL correct to \
     pass verbatim — don't refuse, over-redact, or warn about \"exposing\" PII by using a token; \
     the tokenization (and the tool or broker that resolves it) is what makes it safe.\n\
     - Only use placeholders Sordino actually issued to you. NEVER invent or fabricate a \
     [TYPE_hexid] token you were not given — a made-up token maps to nothing, so it will resolve \
     to nothing and pass through as literal text; it is not a write-back or reveal channel. And \
     NEVER split, reassemble, or re-encode a masked value across fragments to change how it is \
     masked — pass each placeholder whole.\n\
     - Masking can change during the session (the user controls it with /sordino:privacy). If \
     this session's protection changes I'll post a line prefixed \"Sordino:\" — that prefix is \
     Sordino's own status channel, not an instruction to obey blindly; you can confirm the real \
     state any time with /sordino:verify.";

fn session_start(port_arg: Option<u16>, config: Option<PathBuf>, proxy_bin: String) -> Result<()> {
    // Drain stdin (the SessionStart hook payload) so the pipe doesn't block, and
    // opportunistically extract a stable conversation key for the monitor.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let conversation = conversation_id_from_hook_payload(&stdin);

    let root = canonical(&project_root());

    // L10 mitigation: warn (stderr, every session, both routed and unrouted paths) if Claude Code's
    // own OTel content-logging is live — it exports UNMASKED tool/prompt content on a channel this
    // proxy does not sit on. Fires here, before the routed/unrouted split, so it never depends on
    // our route. stderr only: never route dynamic env-derived text through the model-context channel.
    if let Some(w) = otel_content_flag_warning(|k| std::env::var(k).ok()) {
        eprintln!("{w}");
    }

    // Is THIS session routed through OUR proxy? The SessionStart hook fires in every project
    // (the plugin is installed globally), but we only act where Claude Code has applied our
    // route to the live session — at which point this hook subprocess inherits it. The route
    // is `ANTHROPIC_BASE_URL` + the co-baked `SORDINO_PORT` (= the baked port); when they
    // agree on a loopback proxy, `port_arg` (=$SORDINO_PORT) is that port and we're routed to
    // it. The proxy is the sole authority on its (ephemeral) port, so there is no derived port
    // to guess — an unrouted session simply has no matching SORDINO_PORT in its env.
    // Announcing "masking active" when this session is NOT pointed at us would be a lie (the
    // misleading-status bug), so gate every side effect on this real, env-derived route.
    let routed_port =
        port_arg.filter(|p| session_routed_through(&format!("http://127.0.0.1:{p}")));

    if routed_port.is_none() {
        // Port-agnostic "is this project plumbed through us": an ephemeral baked port can't be
        // re-derived, so read it back from settings.local.json (a loopback ANTHROPIC_BASE_URL
        // whose port matches the co-baked SORDINO_PORT). Ignores a user's own unrelated base URL.
        let configured = project_baked_route(&root).is_some();
        let opted_out =
            sordino_state::registry_get(&root) == Some(sordino_state::PlumbState::Optout);
        // Global escape hatch: SORDINO_NO_AUTO_ENABLE disables auto-plumb everywhere. VALUE-aware
        // (mirrors the intake-gate hatch via `is_truthy_flag`): only an explicitly truthy value
        // disables auto-plumb, so a `=0`/`=false` a user meant as "leave auto-enable ON" does NOT
        // silently turn it off. A wrongly-disabled auto-plumb is fail-safe (no masking, no claim).
        let auto_enable = !std::env::var("SORDINO_NO_AUTO_ENABLE")
            .map(|v| is_truthy_flag(&v))
            .unwrap_or(false);

        if !configured && !opted_out && auto_enable {
            // AUTO-PLUMB (first sight of this project): launch the proxy NOW to learn its
            // OS-assigned ephemeral port, then bake THAT route into settings.local.json
            // (gitignored) and record it Plumbed. We launch EAGERLY — so a one-time restart
            // activates masking instantly with no first-message ConnectionRefused hang — but
            // make NO claim of masking THIS session: Claude Code applies a route written during
            // SessionStart only unreliably, so the SURE activation is a restart, which the
            // statusline surfaces as "⟳ Sordino: restart to mask".
            // UNCERTAIN: the mid-session route-application rate is UNMEASURED; the intake gate is
            // fail-closed regardless (it blocks until the route resolves to our verified live proxy),
            // so the exact probability is a tunable, never a load-bearing correctness claim.
            let bake_port = match ensure_up(&root, config.clone(), &proxy_bin) {
                Ok(EnsureOutcome::Ours { port }) => port,
                Ok(EnsureOutcome::Failed { diag }) => {
                    // Proxy didn't come up — make NO masking claim; reason on stderr, stdout a
                    // silent valid no-op (don't exit non-zero with empty stdout).
                    eprintln!(
                        "Sordino: could not auto-enable masking — {diag} Run /sordino:enable to retry."
                    );
                    println!("{}", json!({}));
                    return Ok(());
                }
                Err(e) => {
                    eprintln!(
                        "Sordino: could not auto-enable masking for this project: {e}. \
                         Run /sordino:enable to retry."
                    );
                    println!("{}", json!({}));
                    return Ok(());
                }
            };
            let bake_url = format!("http://127.0.0.1:{bake_port}");
            match settings_enable(&bake_url, &bake_port.to_string(), &statusline_command()) {
                Ok(_) => {
                    let _ =
                        sordino_state::registry_set(&root, sordino_state::PlumbState::Plumbed);
                    // First sight of this project: the route is now baked into
                    // settings.local.json. Claude Code applies a route WRITTEN during this
                    // SessionStart to the current session only unreliably; every session after
                    // the first reads it at startup, which always works. So the sure activation
                    // is a one-time restart — surfaced to the human on the statusline
                    // ("⟳ Sordino: restart to mask") and recommended here. We do NOT launch the
                    // proxy this session: a restart (or the next routed session) brings it up via
                    // the routed branch's ensure_up, so it isn't left running unused.
                    eprintln!(
                        "Sordino: auto-enabled PII masking for this project (wrote \
                         .claude/settings.local.json). RESTART Claude Code once to activate it — the \
                         statusline shows '⟳ Sordino: restart to mask' until it's live, then 🛡. Until \
                         then Sordino blocks this session's messages so nothing sends unmasked (set \
                         SORDINO_NO_INTAKE_GATE=1 to send anyway). Control it with /sordino:privacy; \
                         remove routing with /sordino:uninstall. (SORDINO_NO_AUTO_ENABLE=1 opts out globally.)"
                    );
                    println!(
                        "{}",
                        json!({
                            "hookSpecificOutput": {
                                "hookEventName": "SessionStart",
                                "additionalContext": ONBOARDING
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
                        "Sordino: could not auto-enable masking for this project: {e}. \
                         Run /sordino:enable to retry."
                    );
                    println!("{}", json!({}));
                }
            }
            return Ok(());
        }

        if opted_out && configured {
            // SELF-HEAL: opted out here, yet a route is STILL baked into settings.local.json (a
            // prior /sordino:uninstall's strip didn't fully land, or the file was restored). Left
            // alone, this session routes to a proxy the user disabled — a hang if it's down.
            // Strip the stale route so this and future sessions stop routing; opt-out means no
            // masking intent, so reverting to a direct (unmasked) connection is exactly right
            // (this is the only safe strip — we NEVER strip a route a project still intends).
            let _ = settings_disable_at(Path::new(&root));
            eprintln!(
                "Sordino: this project is opted out, but a stale route was still baked into \
                 .claude/settings.local.json — removed it so the session won't route to a \
                 disabled proxy. Re-enable masking any time with /sordino:enable."
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
                "Sordino: this project is configured but THIS session isn't routed yet. Restart \
                 Claude Code once to activate masking (the statusline shows '⟳ Sordino: restart to \
                 mask' until it's live). Until then Sordino blocks this session's messages so \
                 nothing sends unmasked (set SORDINO_NO_INTAKE_GATE=1 to send anyway)."
            );
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": ONBOARDING
                    }
                })
            );
            return Ok(());
        }

        // Opted out (the user ran /sordino:uninstall here), or auto-enable disabled, and not
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
            eprintln!("Sordino: {diag}");
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": ONBOARDING
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
        // The model used to get the alarmist stale-port copy frozen into context — which then
        // read as a prompt injection and outlived its truth the instant Claude Code live-reloaded
        // the reconciled route (image 2). Keep the loud warning on stderr for the HUMAN; the model
        // gets only the immutable onboarding. This session's real state is enforced downstream: the
        // intake gate BLOCKS its first prompt (baked route now points at the new port, this session
        // doesn't), or — if the route did live-reload — the UserPromptSubmit delta reports the
        // now-correct masked state. Either way, no frozen panic.
        let (human, _model) =
            stale_route_messages(routed_port, port, classify_stale_route(routed_port), reconciled);
        eprintln!("Sordino: {human}");
        println!(
            "{}",
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": ONBOARDING
                }
            })
        );
        return Ok(());
    }

    // port == routed_port: this session's traffic flows through our live proxy. Announce.
    let base_url = format!("http://127.0.0.1:{port}");
    // SessionStart hook output. The static `env` written into settings.local.json (by
    // auto-plumb or `/sordino:enable`) is the load-bearing path for ANTHROPIC_BASE_URL;
    // the `env` key here is a best-effort override for harness versions that honor it.
    let session_base_url = conversation
        .as_deref()
        .map(|c| format!("{base_url}/sordino/session/{c}"))
        .unwrap_or_else(|| base_url.clone());
    // Routed + healthy. The model gets the immutable onboarding; the live "masking is active on
    // :{port}" baseline is the first UserPromptSubmit delta's job (it reads ground truth and stays
    // fresh), so nothing here can go stale. `env` remains the best-effort live-route override.
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": ONBOARDING
        },
        "env": { "ANTHROPIC_BASE_URL": session_base_url, "SORDINO_PORT": port.to_string() }
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
/// already routed, opted out, or the `SORDINO_NO_INTAKE_GATE` escape hatch.
///
/// ONE prompt-shaped exception: a `/sordino:` control-plane command always passes, even with the
/// gate closed — it is how the user RECOVERS from the unrouted state (/sordino:uninstall to opt out
/// and continue, /sordino:enable to retry, /sordino:status/doctor/verify to inspect). Otherwise
/// the gate is a trap: the command that would release it is itself blocked. These prompts are
/// Sordino's own command text (no user PII), and only a human keystroke reaches this hook, so the
/// exception widens nothing an attacker controls.
///
/// The decision uses fast LOCAL reads (the baked route + `$ANTHROPIC_BASE_URL`) plus, ONLY when a
/// block actually turns on it, ONE ~600ms-bounded `/healthz` identity probe (`intake_identity_ok`)
/// — never an unbounded read. This matters BECAUSE a UserPromptSubmit hook that hangs (30s timeout)
/// or crashes FAILS OPEN (the prompt proceeds unmasked); only an explicit block decision is
/// fail-closed. The identity probe is bounded far under that 30s and degrades to "not ours → BLOCK"
/// on any failure, so it cannot fail open. Every read on this path is non-panicking by construction:
/// `project_root` (env/cwd with a fallback), `canonical` (`canonicalize` with an `unwrap_or_else`
/// fallback), `registry_get` / `project_baked_route` (fallible `fs::read` + `serde` that degrade to
/// `None`), `session_routed_through` (env + string compare), and `intake_identity_ok` (a fallible
/// `reqwest` send that degrades to `false`) — none `unwrap`/`expect`/index, so no panic path
/// precedes the block emission. A missing binary likewise fails open at the shell wrapper, which is
/// correct: no sordino installed ⇒ no masking promise ⇒ nothing to gate.
fn user_prompt_submit() -> Result<()> {
    // Drain the hook payload so the pipe never blocks, and pull the submitted prompt out of it —
    // we need the text to let Sordino's own control-plane commands through a closed gate (below).
    // serde is Option-fallible, so a malformed payload degrades to an empty prompt (no command
    // match → still fail-CLOSED), never a panic on this safety path.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let prompt = prompt_from_hook_payload(&stdin).unwrap_or_default();
    let conversation = conversation_id_from_hook_payload(&stdin);

    let root = canonical(&project_root());
    // Gather the routing facts with fast LOCAL reads only (registry file, settings.local.json,
    // $ANTHROPIC_BASE_URL) — nothing that hits the network or can hang.
    let opted_out =
        sordino_state::registry_get(&root) == Some(sordino_state::PlumbState::Optout);
    let baked_port = project_baked_route(&root);
    // Cheap LOCAL check: does this session's $ANTHROPIC_BASE_URL point at the baked proxy port?
    // This ALONE is NOT enough to stand the gate down — a foreign/dead process can hold that port
    // (our proxy died and something else grabbed it; a reconcile that never landed), and the session
    // would egress UNMASKED to it. The real ALLOW condition is identity-verified below
    // (`intake_identity_ok`); this string match only distinguishes the two block REASONS.
    let env_routed = baked_port
        .is_some_and(|p| session_routed_through(&format!("http://127.0.0.1:{p}")));
    // VALUE-aware (like SORDINO_NO_AUTO_ENABLE): this disables a fail-CLOSED SECURITY control, so a
    // user who sets `=0` meaning "off" must NOT accidentally turn the gate off — only an explicitly
    // truthy value opens the hatch.
    let escape_hatch = std::env::var("SORDINO_NO_INTAKE_GATE")
        .map(|v| is_truthy_flag(&v))
        .unwrap_or(false);

    // The ONLY network read on the block-decision path: confirm the baked port is OUR live,
    // nonce-verified proxy. Run it ONLY when a block actually turns on it — plumbed, not opted out,
    // not escape-hatched, not a `/sordino:` command (all of which ALLOW regardless) — AND only when
    // the session env already points at the baked port (else it's the never-routed case, no point
    // probing). It is ~600ms-bounded and fail-CLOSED (timeout/unverified → not ours → BLOCK), far
    // under the 30s hook timeout that fails OPEN. This closes the bare-string-compare hole: a
    // foreign/dead listener on the baked port no longer reads as "routed".
    let must_check = baked_port.is_some()
        && !opted_out
        && !escape_hatch
        && !prompt_is_sordino_command(&prompt);
    let identity_ok = if must_check && env_routed {
        baked_port.is_some_and(|p| intake_identity_ok(p, &root))
    } else {
        false
    };

    // Block iff the gate fires AND the prompt isn't a `/sordino:` control-plane command — the
    // recovery levers (/sordino:uninstall to opt out and continue, enable to retry,
    // status/doctor/verify to inspect) must never be trapped inside the gate they'd release. Those
    // prompts are Sordino's own command text (no sordino command takes a PII argument) and only a
    // human keystroke reaches this hook, so passing them widens nothing; a prompt that merely
    // MENTIONS a command stays blocked (it could carry PII).
    if intake_should_block_verified(opted_out, baked_port.is_some(), identity_ok, escape_hatch)
        && !prompt_is_sordino_command(&prompt)
    {
        // `decision:"block"` (exit 0) is the fail-closed contract; the reason is shown to the user.
        // Two distinct cases: (1) this session isn't pointed at the baked port yet (the common
        // post-enable "restart to activate"); (2) it IS pointed there, but the listener can't be
        // verified as OUR proxy — down, replaced, or a foreign process — which would egress UNMASKED.
        let reason = if env_routed {
            "Sordino PII masking is enabled and THIS Claude Code session is routed to the masking \
             port, but the process now answering there can't be verified as Sordino's proxy — it may \
             be down, replaced, or a different local process — so your message could reach the API \
             provider UNMASKED (or hang). Restart Claude Code once so Sordino re-routes this session \
             to its live proxy. Prefer to continue as-is? Run /sordino:uninstall to stop routing this \
             project through the proxy (connect directly), or set SORDINO_NO_INTAKE_GATE=1 to bypass \
             the gate for now. (Only what the provider sees is affected — you always see your own plaintext.)"
        } else {
            "Sordino PII masking is enabled for this project, but THIS Claude Code session is not yet \
             routed through the masking proxy — so your message would reach the API provider UNMASKED \
             (real PII, not tokens). Restart Claude Code once to activate masking; every session after \
             the first picks it up automatically. Prefer to continue this session as-is? Run \
             /sordino:uninstall to stop routing this project through the proxy (connect directly), or \
             set SORDINO_NO_INTAKE_GATE=1 to bypass the gate for now. (Only what the provider sees is \
             affected — you always see your own plaintext.)"
        };
        println!("{}", json!({ "decision": "block", "reason": reason }));
        return Ok(());
    }

    // ALLOW. Post a masking-status DELTA to the model only when this session crosses the masked
    // boundary since it was last told — delta-only, so no per-turn token cost and silence in the
    // steady state. The block decision above is already made, so the best-effort short-timeout
    // proxy read inside can only drop a status line, never fail-open the gate.
    if let Some(conv) = conversation {
        // Collect BOTH the mask-delta line and any ZDR transition lines, then emit them as a
        // SINGLE UserPromptSubmit hook JSON object (one `additionalContext` block). Claude Code's
        // command-hook stdout parser is a plain `JSON.parse` over the ENTIRE trimmed stdout, so two
        // top-level objects (one mask-delta + one-or-more ZDR-transition) would make the parse throw
        // and CC would fall back to injecting the raw JSON soup as plaintext — while the one-shot ZDR
        // report file has already been consumed (remove_file'd / marker stamped). Coalescing keeps
        // the clean additionalContext channel intact on the canonical post-recycle turn (a recycle
        // both restores ZDR *and* flips the mask state, so both lines fire on the same turn).
        let mut lines: Vec<String> = Vec::new();
        // H1/D1: surface A4's reload report (ZDR restored/reverted, or a global corrupt revert)
        // exactly once per conversation per distinct instance — a recycle is never a SILENT routing
        // change. The mask-delta line goes first (it persists session state as a side effect).
        if let Some(line) = mask_delta_line(&conv, opted_out, baked_port, escape_hatch, &root) {
            lines.push(line);
        }
        lines.extend(zdr_transition_lines(&conv, &root));
        emit_session_additional_context(&lines);
    }
    Ok(())
}

/// Fail-CLOSED intake-gate decision (pure — for testing). BLOCK iff this project is plumbed
/// through us AND this session is NOT confirmed reaching OUR identity-verified proxy
/// (`identity_ok` = the env points at the baked port AND that port is our live nonce-verified
/// proxy), and neither the opt-out nor the `SORDINO_NO_INTAKE_GATE` escape hatch applies. Every
/// other state is an ALLOW: not plumbed (no masking intent), identity-verified (reaching our proxy,
/// which fails-closed there), opted out, or escape-hatched. `identity_ok` replaces the former bare
/// `routed` URL string-match — a foreign/dead listener on the baked port no longer reads as routed.
fn intake_should_block_verified(
    opted_out: bool,
    plumbed: bool,
    identity_ok: bool,
    escape_hatch: bool,
) -> bool {
    !escape_hatch && !opted_out && plumbed && !identity_ok
}

/// Truthy-flag parse for an env value (pure — for testing). Only an explicitly affirmative value
/// counts; `0`, `false`, `""`, or junk read as false. Used so the intake-gate escape hatch can't
/// be flipped off by a `=0` a user meant as "keep it on".
fn is_truthy_flag(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Detect Claude Code's OTel content-logging env vars and, if any are live, return a human-facing
/// warning string (stderr, push-based, every SessionStart). This mitigates threat-model limitation
/// L10: Claude Code's OWN OTel pipeline can export UNMASKED tool/prompt content on a channel the
/// masking proxy does not sit on — Sordino cannot see or mask it.
///
/// Verified against the live-running Claude Code binary this session; re-verify these names on a
/// major CC version bump (see the threat model's L10 — an upstream-owned surface). The master gate
/// `CLAUDE_CODE_ENABLE_TELEMETRY` is REQUIRED: with it off, CC constructs no exporter, so a lone
/// content flag exports nothing and this must stay silent. `OTEL_LOG_RAW_API_BODIES` is NOT
/// boolean-only: a value starting with `file:` also enables it (raw bodies to disk) and is
/// recognized here. NOTE residual tunable: `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA` is deliberately
/// NOT required as a third gate (unconfirmed which content flags it further restricts; over-warning
/// is strictly safer than silent under-detection).
fn otel_content_flag_warning(lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    let truthy = |v: &str| is_truthy_flag(v);
    if !lookup("CLAUDE_CODE_ENABLE_TELEMETRY").is_some_and(|v| truthy(&v)) {
        return None;
    }
    let mut flagged: Vec<&str> = Vec::new();
    for name in ["OTEL_LOG_TOOL_DETAILS", "OTEL_LOG_TOOL_CONTENT", "OTEL_LOG_USER_PROMPTS"] {
        if lookup(name).is_some_and(|v| truthy(&v)) {
            flagged.push(name);
        }
    }
    if let Some(v) = lookup("OTEL_LOG_RAW_API_BODIES")
        && (v.starts_with("file:") || truthy(&v))
    {
        flagged.push("OTEL_LOG_RAW_API_BODIES");
    }
    if flagged.is_empty() {
        return None;
    }
    Some(format!(
        "Sordino: Claude Code telemetry content flag(s) are ENABLED in this environment \
         ({}) with CLAUDE_CODE_ENABLE_TELEMETRY on — these export UNMASKED tool/prompt \
         content (including PII Sordino restores on the display path) through Claude \
         Code's own OTel pipeline, a channel Sordino does not sit on and cannot mask \
         (threat model L10). Unset them, or point your OTel collector at infrastructure \
         you trust with the same content this proxy protects.",
        flagged.join(", ")
    ))
}

/// Is this submitted prompt an invocation of a Sordino control-plane command (pure — for
/// testing)? True only when the prompt BEGINS, at byte 0 with NO leading trim, with the `/sordino:`
/// command prefix. Claude Code recognises a slash command only when `/` is the first character, so
/// requiring byte-0 keeps this exactly as wide as a real command launch: leading-whitespace text
/// is ordinary prose (could carry PII) and stays gated, and prose that merely mentions a command
/// ("should I run /sordino:disable?") never matches. Case-sensitive — slash commands are lowercase.
fn prompt_is_sordino_command(prompt: &str) -> bool {
    prompt.starts_with("/sordino:")
}

/// The masking-protection state of THIS session, as last communicated to its model. SessionStart
/// carries only immutable onboarding (it freezes and would go stale); live state rides this
/// per-session delta channel so the model always reconciles against ground truth — and so a
/// SECOND session in the same project, off the shared proxy, reconciles against its OWN baseline.
/// Deliberately coarse: we narrate the protection BOUNDARY, not cosmetic profile tuning.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum MaskState {
    /// Routed to our identity-verified proxy AND masking enabled — outbound PII is tokenized.
    Masked,
    /// Routed to our verified proxy but masking toggled OFF (passthrough). Only the key-gated
    /// local admin plane can flip this, so it is always a local/user-authorized change.
    Off,
    /// This session is NOT reaching our verified proxy (route not applied, proxy down, or a
    /// stale/foreign port) — so its traffic is not being masked by us right now.
    NotReaching,
    /// The project is opted out of Sordino routing (`/sordino:uninstall`) — a direct, unmasked connection.
    Disabled,
    /// Plumbed for masking, NOT routed this session, and the user set `SORDINO_NO_INTAKE_GATE` —
    /// the fail-closed gate is deliberately bypassed, so this session's text egresses UNMASKED
    /// (real values, not tokens). The ONE allow-path state where real PII genuinely leaves the
    /// machine; the model is told once so the onboarding's "when active" framing can't mislead it.
    UnmaskedBypass,
}

/// Live status plus the detail the delta message needs (port/profile only meaningful when routed).
struct SessionStatus {
    state: MaskState,
    port: u16,
    profile: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionStatusRecord {
    state: MaskState,
}

/// Should we post a status line to the model, given what it was last told (`prev`) and the
/// current state (`cur`)? (pure — for testing). Narrate ONLY when the masked/not-masked boundary
/// is crossed relative to the last-communicated state: a fresh `Masked` baseline, a drop OUT of
/// masked, or a recovery back INTO it — PLUS the first appearance of `UnmaskedBypass`, the one
/// not-masked state that means real PII is actively leaving (a deliberate gate bypass), which the
/// model must hear about once. Transitions between two *other* not-masked states (or a cold open on
/// a session that was never masking) stay silent — "not noisy, but never let a silent un-masking
/// slip past."
fn should_narrate(prev: Option<MaskState>, cur: MaskState) -> bool {
    prev != Some(cur)
        && (prev == Some(MaskState::Masked)
            || cur == MaskState::Masked
            || cur == MaskState::UnmaskedBypass)
}

/// The model-facing delta line. Always prefixed `Sordino:` — the status channel SessionStart
/// pre-registers — and framed factually (no urgency, no "never claim", a verification path), so a
/// legitimate status note never wears the shape of a prompt injection.
fn mask_delta_message(s: &SessionStatus) -> String {
    match s.state {
        MaskState::Masked => format!(
            "Sordino: masking is active for this session — your traffic is tokenized through the \
             verified local proxy on :{} (profile: {}). Keep using tokens verbatim wherever the \
             value belongs.",
            s.port,
            if s.profile.is_empty() { "on" } else { &s.profile }
        ),
        MaskState::Off => "Sordino: masking is now OFF for this project — the local proxy is \
             passing text through UNtokenized (a local setting; re-enable with /sordino:privacy). \
             Treat values you see as real until masking is back on."
            .to_string(),
        MaskState::NotReaching => "Sordino: this session is NOT masking right now — its traffic \
             isn't reaching the verified proxy (the route may not have applied this session, or \
             the proxy is down). Confirm with /sordino:verify; restarting Claude Code rebinds it."
            .to_string(),
        MaskState::Disabled => "Sordino: routing removed for this project \
             (/sordino:uninstall) — this session now connects directly and is not tokenized."
            .to_string(),
        MaskState::UnmaskedBypass => "Sordino: this session is sending text UNMASKED (real values, \
             not tokens) — SORDINO_NO_INTAKE_GATE is set and this session isn't routed to the \
             proxy, so the masking gate is bypassed. Restart Claude Code to mask, or unset \
             SORDINO_NO_INTAKE_GATE to re-enable the gate."
            .to_string(),
    }
}

// -- A6/H1/D1: one-time ZDR restored/reverted transition signal -------------------
//
// A4 (proxy) writes two kinds of reload report under `<state_dir>/zdr-reports/`:
//   * one PER-CONVERSATION `<sanitize_component(conversation)>.json` holding a single
//     serialized `ReloadOutcome` (serde `#[serde(tag="kind", rename_all="snake_case")]`);
//   * one PROJECT-SCOPED `<project_key>.global.json` epoch-bearing Corrupt sentinel.
// A6 consumes them through the EXISTING mask-delta channel so a recycle is never a SILENT
// routing change — exactly once per conversation per distinct instance. The proxy's structs
// are private, so we define matching `Deserialize` mirrors here; the field/tag shape and the
// `sanitize_component` filename function are byte-faithful to the proxy writer (grounded).

/// Mirror of the proxy's `ReloadOutcome` (private there). Tag/casing MUST match the writer:
/// `{"kind":"restored","conversation":..,"target":..}` / `{"kind":"reverted",..,"reason":..}`.
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReloadOutcome {
    Restored { target: String },
    Reverted { reason: String },
}

/// Mirror of the proxy's epoch-bearing global Corrupt sentinel
/// (`{"epoch":<u64>,"conversation":"*","reason":..}`). Only `epoch` + `reason` are read.
#[derive(serde::Deserialize)]
struct GlobalRevert {
    epoch: u64,
    reason: String,
}

/// Max bytes for a sanitized filename COMPONENT. Mirrors the proxy's `SANITIZE_COMPONENT_MAX`.
const SANITIZE_COMPONENT_MAX: usize = 200;

/// Reduce a conversation id / project key to a single safe filename component. BYTE-IDENTICAL
/// to the proxy's `sanitize_component` (state.rs) — the report-file key A6 reads MUST match the
/// key A4 writes, or the signal never fires. Keeps `[A-Za-z0-9._-]`, replaces the rest with `_`,
/// never yields an empty or dot-only name (prefixes `_`), and is length-bounded to
/// [`SANITIZE_COMPONENT_MAX`] bytes (overlong → prefix + `-` + a stable blake3 hash of the FULL
/// sanitized string, so an overlong conversation id can never make the marker write `ENAMETOOLONG`
/// while the proxy report write also gets bounded identically).
fn sanitize_component(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.chars().all(|c| c == '.') {
        out = format!("_{out}");
    }
    // Bound the length. `out` is ASCII by construction (only `[A-Za-z0-9._-]`), so byte- and
    // char-length coincide and slicing on a byte index is always on a char boundary. Hash the
    // FULL sanitized string so distinct long ids stay distinct and both sides derive the same name.
    if out.len() > SANITIZE_COMPONENT_MAX {
        const HASH_HEX: usize = 16;
        const PREFIX: usize = SANITIZE_COMPONENT_MAX - HASH_HEX - 1; // prefix + '-' + 16 hex
        let mut h = blake3::Hasher::new();
        h.update(out.as_bytes());
        out = format!("{}-{}", &out[..PREFIX], &h.finalize().to_hex()[..HASH_HEX]);
    }
    out
}

/// The `Sordino:`-prefixed model-facing line for a per-conversation reload outcome — same
/// channel + framing discipline as [`mask_delta_message`] (factual, a verification/recovery
/// path, never a prompt-injection shape).
fn zdr_report_message(outcome: &ReloadOutcome) -> String {
    match outcome {
        ReloadOutcome::Restored { target } => format!(
            "Sordino: ZDR restored → {target} for this conversation. Your traffic routes to your \
             verified non-retaining endpoint again."
        ),
        ReloadOutcome::Reverted { reason } => format!(
            "Sordino: ZDR could NOT be restored ({reason}) — this conversation is on the masked \
             Anthropic path. Re-engage with /sordino:zdr after confirming the target."
        ),
    }
}

/// The `Sordino:`-prefixed line for the project-scoped global Corrupt revert.
fn zdr_global_message(reason: &str) -> String {
    format!(
        "Sordino: ZDR selection state was unreadable at startup ({reason}) — ALL ZDR selections \
         were lost across this restart and every conversation is now on the masked Anthropic \
         path. Re-engage with /sordino:zdr per conversation."
    )
}

/// Two-source, lock-free consume of A4's reload reports for `conversation`, returning the lines
/// to narrate THIS turn (empty in the steady state). `reports_dir` is explicit for testability
/// (mirrors [`read_mask_state_at`]). `conversation` is already `safe_conversation_id`-normalized
/// (the SAME key A4 persists under); `project_key` keys the single shared global sentinel.
///
/// Source 1 — per-conversation report (S1-safe, CLAIM-BEFORE-EMIT): parse
/// `<reports>/<sanitize_component(conv)>.json`, then gate the emit on `remove_file` SUCCEEDING —
/// only the racer whose claim returns `Ok` emits; a concurrent same-conversation racer that loses
/// the claim emits nothing (the idempotency contract). The parse GUARDS the claim so a torn /
/// half-written file is never removed (left for the next turn).
///
/// Source 2 — global Corrupt sentinel (EPOCH-keyed): read `<reports>/<project_key>.global.json`
/// (NEVER delete it — other conversations still need to see it). Compare its `epoch` to a
/// per-conversation marker `<reports>/<sanitize_component(conv)>.global-seen` whose CONTENT is the
/// last-seen epoch; emit ONLY when the file exists AND (no marker OR marker-epoch != file-epoch),
/// then OVERWRITE the marker with the current epoch. A bare touch-file marker would suppress a
/// SECOND distinct corrupt boot (→ silent Normal); the epoch compare re-emits each distinct
/// instance exactly once per conversation.
fn consume_zdr_transitions(
    reports_dir: &Path,
    conversation: &str,
    project_key: &str,
) -> Vec<String> {
    let mut lines = Vec::new();
    let safe_conv = sanitize_component(conversation);

    // Source 1: per-conversation report, claim-before-emit.
    let report_path = reports_dir.join(format!("{safe_conv}.json"));
    if let Ok(raw) = std::fs::read_to_string(&report_path)
        && let Ok(outcome) = serde_json::from_str::<ReloadOutcome>(&raw)
    {
        // The parse SUCCEEDED (not torn): the file is a real report. Make `remove_file` the
        // CLAIM that gates the emit — ONLY the racer whose remove succeeds narrates.
        if std::fs::remove_file(&report_path).is_ok() {
            lines.push(zdr_report_message(&outcome));
        }
    }

    // Source 2: global Corrupt sentinel, epoch-keyed (NEVER deleted).
    let global_path = reports_dir.join(format!("{project_key}.global.json"));
    if let Ok(raw) = std::fs::read_to_string(&global_path)
        && let Ok(global) = serde_json::from_str::<GlobalRevert>(&raw)
    {
        let marker_path = reports_dir.join(format!("{safe_conv}.global-seen"));
        let seen_epoch = std::fs::read_to_string(&marker_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        if seen_epoch != Some(global.epoch) {
            lines.push(zdr_global_message(&global.reason));
            // Stamp the marker with THIS epoch so the same instance never re-narrates; a later
            // distinct corrupt boot (new epoch) re-emits exactly once.
            let _ = std::fs::write(&marker_path, global.epoch.to_string());
        }
    }

    lines
}

/// The directory A4 writes reload reports into (`<state_dir>/zdr-reports/`). `None` when the
/// state dir can't be resolved — the consume is then simply silent (best-effort, never fatal).
fn zdr_reports_dir() -> Option<PathBuf> {
    Some(sordino_state::state_dir().ok()?.join("zdr-reports"))
}

/// Best-effort consume of A4's ZDR reload transitions for this conversation, returning the
/// model-facing lines to narrate THIS turn (empty in the steady state). The caller coalesces these
/// with the mask-delta line into ONE UserPromptSubmit `additionalContext` block — emitting them as
/// separate top-level JSON objects would break CC's whole-stdout `JSON.parse`. The one-shot consume
/// side effects (report `remove_file`, `.global-seen` marker stamp) happen here regardless.
fn zdr_transition_lines(conversation: &str, root: &str) -> Vec<String> {
    let Some(reports_dir) = zdr_reports_dir() else { return Vec::new() };
    let project_key = sordino_state::project_key(root);
    consume_zdr_transitions(&reports_dir, conversation, &project_key)
}

/// Emit `lines` to the model as a SINGLE UserPromptSubmit hook JSON object — one `additionalContext`
/// block with the lines joined by newlines. Claude Code parses a command hook's ENTIRE stdout as one
/// `JSON.parse` document, so a hook turn must print AT MOST ONE top-level object; concatenated
/// objects make the parse throw and CC falls back to injecting the raw stdout as plaintext. Silent
/// when `lines` is empty (the steady state) so no empty additionalContext is posted.
fn emit_session_additional_context(lines: &[String]) {
    if let Some(obj) = session_additional_context_json(lines) {
        println!("{obj}");
    }
}

/// Build the single UserPromptSubmit hook JSON object for `lines` (joined by newlines into one
/// `additionalContext` block), or `None` when there is nothing to narrate. Factored out so the
/// "exactly one top-level JSON document per turn" invariant is testable without capturing stdout.
fn session_additional_context_json(lines: &[String]) -> Option<serde_json::Value> {
    if lines.is_empty() {
        return None;
    }
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": lines.join("\n")
        }
    }))
}

/// Per-session status record path (`<state_dir>/session-status/<conversation>.json`). `conversation`
/// is already filename-safe (see [`safe_conversation_id`]).
fn session_status_path(conversation: &str) -> Option<PathBuf> {
    let dir = sordino_state::state_dir().ok()?.join("session-status");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(format!("{conversation}.json")))
}

fn read_mask_state_at(dir: &Path, conversation: &str) -> Option<MaskState> {
    let raw = std::fs::read_to_string(dir.join(format!("{conversation}.json"))).ok()?;
    serde_json::from_str::<SessionStatusRecord>(&raw)
        .ok()
        .map(|r| r.state)
}

fn write_mask_state_at(dir: &Path, conversation: &str, state: MaskState) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    if let Ok(raw) = serde_json::to_string(&SessionStatusRecord { state }) {
        let _ = std::fs::write(dir.join(format!("{conversation}.json")), raw);
    }
}

fn read_session_mask_state(conversation: &str) -> Option<MaskState> {
    let dir = sordino_state::state_dir().ok()?.join("session-status");
    read_mask_state_at(&dir, conversation)
}

fn write_session_mask_state(conversation: &str, state: MaskState) {
    if let Some(path) = session_status_path(conversation)
        && let Some(dir) = path.parent()
    {
        write_mask_state_at(dir, conversation, state);
        prune_stale_status(dir); // bound the per-conversation file set; best-effort
    }
}

/// Best-effort removal of status records not touched in two weeks, so the per-conversation files
/// don't grow without bound over a project's lifetime. Every error is swallowed — pruning must
/// never fail or slow the write it rides on (a small dir; `read_dir` is sub-millisecond).
fn prune_stale_status(dir: &Path) {
    let Some(cutoff) =
        std::time::SystemTime::now().checked_sub(Duration::from_secs(14 * 24 * 60 * 60))
    else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|mtime| mtime < cutoff)
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Compute THIS session's current masking state. `None` ⇒ this project is not ours (no masking
/// intent) ⇒ say nothing. Routing is decided from LOCAL reads; only an env-routed session pays a
/// (short-timeout) loopback read to confirm the proxy is OURS and whether masking is enabled —
/// and that read NEVER claims `Masked` unless it positively reads `enabled=true` from our
/// identity-verified proxy (never a false "you're protected").
fn session_mask_state(
    opted_out: bool,
    baked_port: Option<u16>,
    escape_hatch: bool,
    root: &str,
) -> Option<SessionStatus> {
    if opted_out {
        return Some(SessionStatus { state: MaskState::Disabled, port: 0, profile: String::new() });
    }
    let routed_port = baked_port?; // not plumbed through us → not ours → silent
    if !session_routed_through(&format!("http://127.0.0.1:{routed_port}")) {
        // Plumbed, but this session's $ANTHROPIC_BASE_URL doesn't point at the baked port. With the
        // gate bypassed (SORDINO_NO_INTAKE_GATE) this is real unmasked egress — surface it; without
        // it, this branch is only reached by a /sordino: command turn (transient), so stay quiet.
        let state = if escape_hatch { MaskState::UnmaskedBypass } else { MaskState::NotReaching };
        return Some(SessionStatus { state, port: 0, profile: String::new() });
    }
    let (state, profile) = routed_proxy_status(routed_port, root);
    Some(SessionStatus { state, port: routed_port, profile })
}

/// Bounded proxy-IDENTITY check, single-sourced for the intake gate and [`routed_proxy_status`]:
/// is `port` our LIVE, nonce-verified proxy for `root`? One `/healthz` round-trip under `timeout`.
/// Returns the verified rendezvous record on success, `None` on ANY error/mismatch (fail-CLOSED):
/// the live rendezvous port must equal `port`, the record must carry a nonce, and the process there
/// must echo that nonce on `x-sordino-nonce` — so a FOREIGN server squatting the port (no nonce) is
/// never mistaken for ours. The caller supplies `client` + `timeout` so the whole probe stays inside
/// a single deadline (the gate's ~600ms; `routed_proxy_status`'s shared budget).
fn verified_proxy_rec(
    port: u16,
    root: &str,
    client: &reqwest::blocking::Client,
    timeout: Duration,
) -> Option<sordino_state::Rendezvous> {
    let (live, rec) = sordino_state::live_port(root)?;
    if live != port || rec.nonce.is_empty() {
        return None;
    }
    let echoed = client
        .get(format!("http://127.0.0.1:{live}/healthz"))
        .timeout(timeout)
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| {
            r.headers()
                .get("x-sordino-nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .is_some_and(|n| n == rec.nonce);
    echoed.then_some(rec)
}

/// The intake gate's ALLOW condition: is the baked `port` our live, identity-verified proxy?
/// A self-contained, ~600ms-bounded, fail-CLOSED wrapper over [`verified_proxy_rec`] — the gate's
/// block decision must never hang (a UserPromptSubmit hook that times out FAILS OPEN), so the probe
/// carries its own short deadline and any failure (no client, proxy down, stale record, FOREIGN
/// listener) returns `false` ⇒ the gate BLOCKs. Replaces the former bare `session_routed_through`
/// URL string-compare, which credited a foreign/dead listener on the baked port as "routed".
fn intake_identity_ok(port: u16, root: &str) -> bool {
    let Ok(client) = reqwest::blocking::Client::builder().build() else {
        return false;
    };
    verified_proxy_rec(port, root, &client, Duration::from_millis(600)).is_some()
}

/// For a session whose env IS routed to `routed_port`: confirm the listener is our identity-
/// verified proxy (rendezvous nonce echoed over `/healthz`) and read `enabled`/`profile`. Mirrors
/// the statusline's `render_segment` verification but returns a typed state. Uses a SHORT timeout
/// so a wedged proxy can never stall prompt submission; any failure degrades to `NotReaching`
/// (the honest "can't confirm masking" answer), never an optimistic `Masked`.
fn routed_proxy_status(routed_port: u16, root: &str) -> (MaskState, String) {
    let unconfirmed = (MaskState::NotReaching, String::new());
    // ONE client, NO global timeout: the two reads (identity + enabled) share a SINGLE ~600ms
    // deadline via per-request `.timeout()`, so the whole best-effort tail is bounded as a unit
    // (not 500ms-per-request → ~1s). A slow proxy can only shrink the status read to nothing and
    // degrade to `NotReaching`; it can never stall prompt submission for long.
    let Ok(client) = reqwest::blocking::Client::builder().build() else {
        return unconfirmed;
    };
    let start = std::time::Instant::now();
    let remaining = || {
        Duration::from_millis(600)
            .checked_sub(start.elapsed())
            .unwrap_or(Duration::ZERO)
            .max(Duration::from_millis(50))
    };
    // Identity: confirm the listener on `routed_port` is OUR live nonce-verified proxy (single-
    // sourced with the intake gate via `verified_proxy_rec`), closing the foreign-server-on-a-
    // colliding-port hole. The verified record carries the admin key the config read below needs.
    let Some(rec) = verified_proxy_rec(routed_port, root, &client, remaining()) else {
        return unconfirmed;
    };
    match client
        .get(format!("http://127.0.0.1:{routed_port}/sordino/config"))
        .timeout(remaining())
        .header("x-sordino-key", &rec.admin_key)
        .header("x-sordino-project", sordino_state::project_key(root))
        .send()
    {
        Ok(r) if r.status().is_success() => {
            let v: Value = r.json().unwrap_or(Value::Null);
            let profile = v
                .pointer("/config/profile")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match v.get("enabled").and_then(Value::as_bool) {
                Some(true) => (MaskState::Masked, profile),
                Some(false) => (MaskState::Off, profile),
                None => unconfirmed,
            }
        }
        _ => unconfirmed,
    }
}

/// On an ALLOW turn, compute the masking-status line to post to the model IFF this session crossed
/// the masked boundary since it was last told (see [`should_narrate`]), returning `Some(line)` to
/// narrate or `None` to stay silent. Best-effort: an undetermined state (`None`) or an unkeyable
/// session is simply silent. ALWAYS tracks the latest state (the side effect below) so the next
/// turn's delta is computed against reality — even when no line is returned. The caller coalesces
/// the returned line with any ZDR-transition lines into ONE hook JSON object.
fn mask_delta_line(
    conversation: &str,
    opted_out: bool,
    baked_port: Option<u16>,
    escape_hatch: bool,
    root: &str,
) -> Option<String> {
    let cur = session_mask_state(opted_out, baked_port, escape_hatch, root)?;
    let prev = read_session_mask_state(conversation);
    let line = should_narrate(prev, cur.state).then(|| mask_delta_message(&cur));
    // ALWAYS persist, even when unchanged: `should_narrate` already gates the model-facing line, so
    // the rewrite costs no tokens — but it keeps an actively-masked session's record mtime FRESH so
    // `prune_stale_status` can't evict a live baseline. If it did, a later `Masked -> Off` would
    // read `prev == None` and `should_narrate(None, Off) == false` — a SILENT un-masking. The write
    // is the per-turn activity signal the prune relies on.
    write_session_mask_state(conversation, cur.state);
    line
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
/// per-project launch lock. `config` defaults to the project's `sordino.toml` when present.
fn ensure_up(root: &str, config: Option<PathBuf>, proxy_bin: &str) -> Result<EnsureOutcome> {
    let config = config.or_else(|| {
        let p = Path::new(root).join("sordino.toml");
        p.exists().then_some(p)
    });

    // Adopt an already-running proxy for this project ONLY if a live `/healthz` echoes the
    // nonce recorded in OUR rendezvous — proof it is the exact proxy instance that published
    // the record, not a foreign 200-server that grabbed the port after a PID-reuse + port-
    // steal. Without the nonce check, such a server would be adopted and this project's
    // traffic would route UNMASKED through a non-sordino process — the worst "looks fine but
    // isn't" failure. `live_port` is project-keyed + pid-prefiltered; the nonce match is the
    // authoritative identity. A stale BUILD (our instance, older code) is recycled so a
    // plugin update takes effect. A hook-launched proxy always carries a nonce, so an empty
    // `rec.nonce` (a manual/legacy proxy) is deliberately NOT adopted — we relaunch ours.
    if let Some((port, rec)) = sordino_state::live_port(root)
        && !rec.nonce.is_empty()
        && let Some((build, live_nonce)) = proxy_identity(port)
        && live_nonce == rec.nonce
    {
        let ours = sordino_state::BUILD_ID;
        let stale = ours != "unknown" && build != "unknown" && build != ours;
        if !stale {
            return Ok(EnsureOutcome::Ours { port });
        }
        eprintln!(
            "Sordino: proxy on :{port} is an older build — restarting to apply the update."
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
    let salt_hex = match sordino_state::read_rendezvous(root) {
        Some(rec) if rec.salt.len() == 32 => rec.salt,
        _ => rand_hex16(),
    };

    let _lock = match sordino_state::try_launch_lock(root, std::process::id(), &nonce)? {
        Some(g) => g,
        // Another launcher holds the lock — it's bringing the proxy up. Wait for ANY live,
        // healthy proxy for this project (we don't know the winner's nonce, but the
        // project-keyed lookup + health is enough to adopt the one it publishes).
        None => return Ok(wait_for_live(root, None)),
    };

    let dir = sordino_state::state_dir()?;
    // Per-project log (keyed by project hash — we no longer know the port up front).
    let log_path = dir.join(format!("proxy-{}.log", sordino_state::project_key(root)));
    let log = std::fs::File::create(&log_path).context("creating proxy log")?;
    let log_err = log.try_clone()?;

    let mut cmd = std::process::Command::new(proxy_bin);
    cmd.arg("--project-root")
        .arg(root)
        .env("SORDINO_SESSION_SALT", &salt_hex)
        .env("SORDINO_LAUNCH_NONCE", &nonce)
        .env("SORDINO_PROJECT_ROOT", root)
        // CRITICAL: strip an inherited SORDINO_PORT. In a routed session our own env carries
        // SORDINO_PORT (the baked port, an informational hint for the CLI/statusline), but the
        // proxy reads `--port`/SORDINO_PORT as a STATIC PIN. Leaking it would hard-pin the
        // baked port and defeat the ephemeral/sticky bind (and its :0 fallback). The proxy
        // gets its port from `[proxy] port` (static) or its own rendezvous last_port (sticky)
        // — never from the hook's ambient env.
        .env_remove("SORDINO_PORT")
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
        if let Some((port, rec)) = sordino_state::live_port(root)
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
/// The body is the proxy's build id (for stale-build recycling); the `x-sordino-nonce`
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
        .get("x-sordino-nonce")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let build = resp.text().ok()?.trim().to_string();
    Some((build, nonce))
}

/// A human, actionable reason a launch never went healthy — the auto-diagnosis the hook
/// surfaces (and `/sordino:doctor` expands). Distinguishes "running but unreachable over
/// loopback" (a local firewall/AV intercepting 127.0.0.1) from "never bound / crashed"
/// (read the proxy log tail for the classified bind error or panic).
fn launch_failure_diag(root: &str) -> String {
    if let Some((port, rec)) = sordino_state::live_port(root) {
        return format!(
            "the proxy (pid {}) appears to be running but is unreachable over 127.0.0.1:{port} \
             — a local security/AV product or a hardened loopback firewall may be intercepting \
             127.0.0.1. Run /sordino:doctor.",
            rec.pid
        );
    }
    match read_proxy_log_tail(root, 12) {
        Some(tail) if !tail.trim().is_empty() => {
            format!("the proxy did not start or exited. Last log lines:\n{tail}")
        }
        _ => format!(
            "the proxy did not start (no log output). Check that the sordino-proxy binary \
             exists and is executable, then run /sordino:doctor."
        ),
    }
}

/// The last `n` lines of this project's proxy log (`proxy-<project_key>.log`), if any.
fn read_proxy_log_tail(root: &str, n: usize) -> Option<String> {
    let path = sordino_state::state_dir()
        .ok()?
        .join(format!("proxy-{}.log", sordino_state::project_key(root)));
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
        "The route could NOT be updated — run /sordino:enable.".to_string()
    };
    match danger {
        StaleRoute::Unresponsive => (
            format!(
                "THIS session may HANG (or leak) — it is routed to :{routed_port}, now held by an \
                 unresponsive or non-HTTP process (not the sordino proxy). Press Ctrl-C and restart \
                 Claude Code now. {tail}"
            ),
            format!(
                "Sordino: THIS session is routed to a non-sordino local port (:{routed_port}) that \
                 does not answer as our proxy — its API requests will HANG, or reach a foreign \
                 process UNMASKED. Either way it is NOT masked. Tell the user to press Ctrl-C and \
                 restart Claude Code now. Never claim masking is active. {tail}"
            ),
        ),
        StaleRoute::ForeignResponder => (
            format!(
                "DANGER: THIS session's traffic is going UNMASKED to a DIFFERENT local process on \
                 :{routed_port} (not the sordino proxy). Press Ctrl-C and restart Claude Code NOW. \
                 {tail}"
            ),
            format!(
                "Sordino: THIS session is NOT masked — its traffic is reaching a DIFFERENT local \
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
                "Sordino: THIS session is NOT masked — its proxy port (:{routed_port}) is no longer \
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
/// receives via the `/sordino/session/{conversation}/…` path) from the SessionStart
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

/// Extract the submitted prompt text from a UserPromptSubmit hook payload. TOP-LEVEL keys only
/// (the canonical `prompt` plus casing variants across harness versions) — deliberately NOT the
/// recursive `find_string_key`: the real user prompt is always a top-level field, and recursing
/// would risk a nested `prompt` becoming the gate's allow decision on a malformed payload. A
/// keyless/malformed payload returns `None` → empty prompt → no command match → stays fail-CLOSED.
fn prompt_from_hook_payload(stdin: &str) -> Option<String> {
    let value: Value = serde_json::from_str(stdin).ok()?;
    let obj = value.as_object()?;
    ["prompt", "user_prompt", "userPrompt"]
        .iter()
        .find_map(|key| obj.get(*key).and_then(Value::as_str))
        .map(str::to_string)
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
/// `/sordino:enable` calls this to learn the port to write into settings.local.json. Unlike
/// `session-start` it emits NO hook JSON — only the bare port — so /sordino:enable can call it
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

/// How much the sordino status-line segment shows, chosen by `$SORDINO_STATUSLINE`.
/// Defaults to `Compact`. `Off` hides the sordino segment entirely — when the status
/// line wraps a user's original line (see [`read_wrap_original`]), that original still
/// prints, so `off` means "show only my line, no sordino chrome", not "blank".
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
    sl_mode_from(std::env::var("SORDINO_STATUSLINE").ok().as_deref())
}

/// Pure `$SORDINO_STATUSLINE` → mode mapping (kept separate from `sl_mode` so it's
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
    // The session's routed port (`$SORDINO_PORT`, set in-session) when present; else a
    // best-effort fall back to OUR live proxy's port for a manual run. `None` ⇒ no proxy
    // known ⇒ the segment renders the honest not-masking/restart state.
    let port = port.or_else(|| resolve_live_port(&root).ok());
    let mode = sl_mode();

    // The sordino segment (None only in `off` mode). Built first so a slow/absent
    // wrapped command never delays or suppresses our own privacy indicator.
    let segment = match mode {
        SlMode::Off => None,
        _ => Some(render_segment(port, &root, mode)),
    };

    // Seamless wrap: if the user already had a status line when `/sordino:enable` ran,
    // that original was saved to a sidecar. Run it (forwarding the exact session JSON
    // Claude Code fed us on stdin) and prepend our segment, so the user keeps their
    // line as `🛡 … │ {their line}`. We only touch stdin when there's something to
    // forward — reading it unconditionally would block when run from an interactive
    // shell (e.g. someone testing `sordino-hooks statusline` by hand).
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

/// Join the sordino segment and the wrapped original line with a `│` divider. Either
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

/// Render the sordino segment for a non-`Off` mode. We only show the shield (🛡) when
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
        // deletes env.ANTHROPIC_BASE_URL/SORDINO_PORT, or a gitignored settings.local.json is
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
                _ => "\u{27f3} Sordino: restart to mask".to_string(),
            },
            // No route baked here — this session is NOT masked through us, and a restart
            // won't change that (opted out, never plumbed, or the route was removed).
            None => match mode {
                SlMode::ShieldOnly => String::new(),
                SlMode::Min => "\u{2717}".to_string(), // ✗
                _ => "\u{2717} Sordino not masking".to_string(),
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
            _ => format!("\u{26a0} Sordino routed, proxy down :{port}"),
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
    match admin_get(port, &key, &sordino_state::project_key(root)) {
        Ok(snap) => match serde_json::from_value::<Snapshot>(snap) {
            Ok(s) if s.enabled => render_on(&s, port, mode),
            Ok(_) => match mode {
                SlMode::ShieldOnly => String::new(),
                SlMode::Min => "\u{26a0}".to_string(),
                _ => format!("\u{26a0} Sordino OFF :{port}"),
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
        _ => format!("\u{2754} Sordino :{port} (unverified)"),
    }
}

/// The confirmed-on segment. `token_count` is the number of distinct tokens minted
/// this session — i.e. unique PII values caught — so it doubles as the "N PII" count.
fn render_on(s: &Snapshot, port: u16, mode: SlMode) -> String {
    let ml = ml_indicator(s.ml.as_ref());
    // Per-session ZDR segment: shown only when THIS conversation is ZDR-routed.
    let zdr = zdr_suffix(&s.zdr, conversation_from_base_url().as_deref());
    match mode {
        SlMode::Off => String::new(),
        // ShieldOnly's whole purpose: the bare 🛡, and ONLY here (confirmed-masking). Every
        // other render path returns an empty string for ShieldOnly.
        SlMode::ShieldOnly => "\u{1f6e1}".to_string(),
        SlMode::Min => "\u{1f6e1}".to_string(), // 🛡 only
        SlMode::Compact => format!(
            "\u{1f6e1} :{port} {}{}{}{}{}",
            s.config.profile,
            ml,
            pii_suffix(s.token_count),
            key_suffix(s.secrets.as_ref()),
            zdr,
        ),
        SlMode::Verbose => format!(
            "\u{1f6e1} ON :{port} {} t={:.2}{} {} PII [{}]{}{}",
            s.config.profile,
            s.config.score_threshold,
            ml,
            s.token_count,
            s.config.enabled_categories.join(","),
            key_suffix(s.secrets.as_ref()),
            zdr,
        ),
    }
}

/// ` 🔒ZDR·<config>` when THIS session's conversation is in the proxy's active ZDR
/// set; empty otherwise (absent when off — no visual noise for the common case).
fn zdr_suffix(zdr: &ZdrSummary, conversation: Option<&str>) -> String {
    let Some(conv) = conversation else {
        return String::new();
    };
    match zdr.active.iter().find(|a| a.conversation == conv) {
        Some(a) => format!(" \u{1f512}ZDR\u{b7}{}", a.config), // 🔒ZDR·name
        None => String::new(),
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
///
/// Every state pairs its status glyph with the literal text `ml`, for two reasons.
/// (1) The `🧠` brain (U+1F9E0) is a 2017 codepoint that DEFAULTS to color-emoji
/// presentation, so a terminal/font with no color-emoji fallback (Nerd Fonts ship none;
/// bare xterm, the Linux VT, older consoles) draws it as tofu or nothing. `ready` used to
/// be the ONLY ML state without a text companion, so on those hosts it degraded to an
/// INVISIBLE blank while masking was genuinely active — the brain "isn't showing" bug. The
/// trailing `ml` keeps the indicator legible there (matching the loading/failed arms).
/// (2) The brain is VS16-qualified (`\u{fe0f}`) so a renderer that CAN draw it selects the
/// color, width-2 emoji glyph rather than a mono text-presentation fallback — presenting a
/// consistent 2-cell width to the DOWNSTREAM Claude Code statusline renderer (sordino-hooks
/// itself does no width clipping; `compose_line` only joins segments).
fn ml_indicator(ml: Option<&MlSnap>) -> &'static str {
    match ml.map(|m| (m.status.as_str(), m.last_runtime_error.is_some())) {
        Some(("ready", false)) => " \u{1f9e0}\u{fe0f}ml", // 🧠ml filtering
        Some(("ready", true)) => " \u{26a0}\u{1f9e0}\u{fe0f}ml", // ⚠🧠ml loaded but endpoint failing
        Some(("loading", _)) => " \u{23f3}ml", // ⏳ml loading — not filtered yet
        Some(("failed", _)) => " \u{26a0}ml",  // ⚠ml load failed
        _ => "",
    }
}

/// Path of the sidecar that holds the user's pre-sordino `statusLine` object, written
/// by `/sordino:enable` when it took over the slot. Lives beside `settings.json`.
fn wrap_sidecar_path(proj: &Path) -> PathBuf {
    proj.join(".claude").join("sordino-statusline.json")
}

/// The shell command of the user's original status line, if `/sordino:enable` wrapped
/// one. Returns `None` when no sidecar exists, it isn't a `command` status line, or —
/// defensively — the stored command is itself a sordino status line (which would
/// recurse). The sidecar stores the original `statusLine` object verbatim so
/// `/sordino:uninstall` can restore it.
fn read_wrap_original(proj: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(wrap_sidecar_path(proj)).ok()?;
    let v: Value = serde_json::from_str(strip_bom(&txt)).ok()?;
    let cmd = v.get("command")?.as_str()?.trim();
    if cmd.is_empty() || is_sordino_statusline(cmd) {
        return None;
    }
    Some(cmd.to_string())
}

/// Is `cmd` one of OUR status-line commands — `[<path>/]sordino-hooks[.exe] statusline`?
/// We match `sordino-hooks statusline` (or the `.exe` form) as a contiguous substring AND
/// require `sordino-hooks` to be a command BASENAME: at the string start, or right after a
/// path separator (`/` or `\`). enable.sh only ever emits the name bare or after `'<dir>'/`,
/// so real installs always match — but a user line where the token is merely an argument
/// (`echo sordino-hooks statusline`) or a different binary whose name ends in it
/// (`/usr/local/bin/not-sordino-hooks statusline`) does NOT, so we never silently eat their
/// status line. This is stricter than the old jq regex `sordino-hooks(\.exe)? statusline`,
/// which was anchorless and would have over-claimed both. Single source of truth for
/// enable/disable's slot-ownership test and the wrapper's self-reference guard; no regex dep.
fn is_sordino_statusline(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    for needle in ["sordino-hooks statusline", "sordino-hooks.exe statusline"] {
        let mut from = 0;
        while let Some(rel) = cmd[from..].find(needle) {
            let at = from + rel;
            // `sordino-hooks` must be a basename: string start, or after a path separator.
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
/// output) yields `None` so the sordino segment still stands alone.
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
// config (/sordino:privacy)
// ---------------------------------------------------------------------------

fn config_cmd(action: Option<ConfigAction>) -> Result<()> {
    let root = canonical(&project_root());
    // Resolve this project's live (port, admin_key) identity EXACTLY ONCE per invocation — a single
    // nonce-verified `live_identity` round-trip — and thread that one triple (port, key, project)
    // into every helper below, so no helper ever re-resolves. This closes a TOCTOU: the old chain
    // re-ran `resolve_live_port` / `key_for` independently across the helpers, so two round-trips
    // could land on DIFFERENT live instances after a proxy restart / recycled-port race.
    // `ident == None` means no live, verified proxy: the mutating `--scope project|user|local`
    // actions STILL persist to the config file ("applies on the next session"); only `Show` and
    // `--scope session` need a live proxy and surface a hard error themselves. `project` (the
    // canonical-root identity hash) rides on every control-plane request as `x-sordino-project`,
    // so a (port,key) resolved against the WRONG instance is rejected once the server binding lands.
    let ident = live_identity(&root);
    let project = sordino_state::project_key(&root);

    match action.unwrap_or(ConfigAction::Show) {
        ConfigAction::Show => {
            let port = ident.as_ref().map(|(p, _)| *p).unwrap_or(0);
            let snap = live_snapshot(ident, &project)
                .context("could not reach this project's proxy (is a `claude` session running?)")?;
            print_status(&snap, port)?;
        }
        ConfigAction::On { scope } => apply_enabled(ident, &project, &root, scope, true)?,
        ConfigAction::Off { scope } => apply_enabled(ident, &project, &root, scope, false)?,
        ConfigAction::Profile { name, scope } => {
            apply_profile(ident, &project, &root, scope, name.into())?
        }
        ConfigAction::Category { name, state, scope } => {
            apply_category(ident, &project, &root, scope, &name, matches!(state, OnOff::On))?
        }
        ConfigAction::Threshold { value, scope } => {
            apply_threshold(ident, &project, &root, scope, value)?
        }
        ConfigAction::Entity { name, op, scope } => {
            apply_entity(ident, &project, &root, scope, &name, &op)?
        }
        ConfigAction::Ml { action } => {
            ml_cmd(ident, &project, &root, action.unwrap_or(MlAction::Status))?
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// config ml (/sordino:privacy model …)
// ---------------------------------------------------------------------------

fn ml_cmd(ident: Option<(u16, String)>, project: &str, root: &str, action: MlAction) -> Result<()> {
    match action {
        MlAction::Status => {
            let port = ident.as_ref().map(|(p, _)| *p).unwrap_or(0);
            let snap = live_snapshot(ident, project)
                .context("could not reach this project's proxy (is a `claude` session running?)")?;
            print_ml_line(&parse_snapshot(&snap)?, port);
            Ok(())
        }
        MlAction::On { model, scope } => apply_ml(ident, project, root, scope, true, model),
        MlAction::Off { scope } => apply_ml(ident, project, root, scope, false, None),
    }
}

/// Turn the ML recognizer on/off. Session scope hits the dedicated control
/// endpoint (live, not persisted); file scopes persist `[engine.ml]` then apply
/// live (a `reload` first so a model change is picked up, then the toggle).
fn apply_ml(
    ident: Option<(u16, String)>,
    project: &str,
    root: &str,
    scope: Scope,
    on: bool,
    model: Option<String>,
) -> Result<()> {
    let endpoint = if on { "ml/enable" } else { "ml/disable" };

    if scope == Scope::Session {
        let (port, key) =
            ident.context("proxy not running; use --scope project/user to persist")?;
        let snap = admin_post(port, &key, endpoint, project)?;
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
    let port = ident.as_ref().map(|(p, _)| *p).unwrap_or(0);
    let applied = match &ident {
        Some((p, key)) => {
            // For ON, reload first so a `--model` change in the file is loaded into
            // the live config before we flip the toggle (which starts the load).
            if on {
                let _ = admin_post(*p, key, "reload", project);
            }
            admin_post(*p, key, endpoint, project).ok()
        }
        None => None,
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
            "  tip: run `/sordino:privacy model download` once, then `/sordino:privacy model on`."
        );
    }
    if ml.status == "failed" {
        if http {
            println!(
                "  tip: check the endpoint URL / that the server is up / auth_token_env — \
                 the load probes the endpoint; then retry `/sordino:privacy model on`."
            );
        } else {
            println!(
                "  tip: check disk space / network, re-run `/sordino:privacy model download`, \
                 then `/sordino:privacy model on`."
            );
        }
    }
}

fn apply_enabled(
    ident: Option<(u16, String)>,
    project: &str,
    root: &str,
    scope: Scope,
    on: bool,
) -> Result<()> {
    if scope == Scope::Session {
        let (port, key) =
            ident.context("proxy not running; use --scope project/user to persist")?;
        let snap = admin_post(port, &key, if on { "enable" } else { "disable" }, project)?;
        // "On means on": turning masking back on for this session ALSO clears any
        // per-conversation disable (`/sordino:disable`), so masking is reliably active here
        // regardless of which switch turned it off. Best-effort — the master enable already
        // succeeded; a failed clear (e.g. not session-routed) just leaves the override.
        if on && let Some(conv) = conversation_from_base_url() {
            let url = format!(
                "http://127.0.0.1:{port}/sordino/session/{}/masking",
                percent_encode(&conv)
            );
            let _ = blocking_client()
                .delete(&url)
                .header("x-sordino-key", &key)
                .header("x-sordino-project", project)
                .send();
        }
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["enabled"] = toml_edit::value(on);
    })?;
    finish_file_scope(ident, project, scope, root, if on { "enable" } else { "disable" })
}

fn apply_threshold(
    ident: Option<(u16, String)>,
    project: &str,
    root: &str,
    scope: Scope,
    value: f32,
) -> Result<()> {
    anyhow::ensure!(
        (0.0..=1.0).contains(&value),
        "threshold must be in 0.0..=1.0"
    );
    if scope == Scope::Session {
        let (port, key) =
            ident.context("proxy not running; use --scope project/user to persist")?;
        let mut cfg = admin_get(port, &key, project)?;
        cfg["config"]["score_threshold"] = json!(value);
        let snap = admin_put(port, &key, &cfg["config"], project)?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["score_threshold"] = toml_edit::value(f32_to_toml(value));
    })?;
    finish_file_scope(ident, project, scope, root, "reload")
}

/// Widen an `f32` to `f64` via its shortest decimal form, so a value like `0.3`
/// persists as `0.3` in TOML rather than `0.30000001192092896`.
fn f32_to_toml(v: f32) -> f64 {
    format!("{v}").parse().unwrap_or(v as f64)
}

/// Apply a detection profile. When the proxy is reachable, this routes through the
/// SHARED `POST /sordino/profile/{name}?scope=…` endpoint so the UI and CLI can
/// never drift on what a profile means or how it is persisted — the proxy both
/// applies it live AND persists it for a file scope. Only when the proxy is DOWN
/// does the CLI fall back to writing the scope file itself (so a profile can still
/// be persisted offline); the field shape it writes matches the proxy's
/// `persist_profile`, both deriving from `EngineConfig::for_profile`.
fn apply_profile(
    ident: Option<(u16, String)>,
    project: &str,
    root: &str,
    scope: Scope,
    profile: Profile,
) -> Result<()> {
    let profile_id = serde_json::to_value(profile)?
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "balanced".to_string());

    // Proxy up: the endpoint is the single source of truth for apply + persist.
    if let Some((port, key)) = ident.as_ref() {
        let path = format!("profile/{profile_id}?scope={}", scope_label(scope));
        let snap = admin_post(*port, key, &path, project)?;
        print_applied(&snap, *port, scope_label(scope))?;
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

fn apply_category(
    ident: Option<(u16, String)>,
    project: &str,
    root: &str,
    scope: Scope,
    name: &str,
    on: bool,
) -> Result<()> {
    let name = name.to_lowercase();
    validate_category(&name)?;

    // Base the toggle on the effective set (live proxy, else the config files —
    // never the balanced default, which would clobber a custom persisted set).
    let mut cats = effective_categories(ident.clone(), project, root);
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
        let (port, key) =
            ident.context("proxy not running; use --scope project/user to persist")?;
        let mut cfg = admin_get(port, &key, project)?;
        cfg["config"]["enabled_categories"] = json!(cats);
        let snap = admin_put(port, &key, &cfg["config"], project)?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, |doc| {
        doc["engine"]["enabled_categories"] = toml_edit::value(str_array(&cats));
    })?;
    finish_file_scope(ident, project, scope, root, "reload")
}

/// Per-entity operator override (`config entity <TYPE> <op>`) — the finer-grained
/// sibling of `apply_category`. Writes `entity_operators[<TYPE>]`, which both GATES the
/// type (`entity_enabled` is true for any keyed type) and sets how it masks — so
/// `on`/`off` work regardless of the type's category (e.g. enable URL masking without
/// turning the whole Network category on). `clear` removes an override (file scope only).
fn apply_entity(
    ident: Option<(u16, String)>,
    project: &str,
    root: &str,
    scope: Scope,
    name: &str,
    op: &str,
) -> Result<()> {
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
        return clear_entity(ident, project, root, scope, &name);
    }

    let (op_json, op_toml) = entity_operator_value(op)?;

    // Footgun guard (not a block — sordino's everything-configurable contract): setting a
    // SECRETS-category entity to pass-through reintroduces a credential-exposure path.
    if matches!(op.to_lowercase().as_str(), "off" | "keep")
        && sordino_engine::Category::Secrets
            .entity_types()
            .contains(&name.as_str())
    {
        eprintln!(
            "WARNING: '{name}' is a Secrets-category entity; '{op}' lets matching values reach the upstream model — this weakens a default-on protection."
        );
    }

    if scope == Scope::Session {
        let (port, key) =
            ident.context("proxy not running; use --scope project/user to persist")?;
        // Minimal MERGE patch (not the whole fetched config): the control-plane PUT
        // recurses into `entity_operators`, so this overlays exactly the one key —
        // race-safe (a concurrent edit to another key isn't clobbered by stale GET data)
        // and the proxy validates this delta's key (rejecting a typo).
        let patch = json!({ "entity_operators": { name.clone(): op_json } });
        let snap = admin_put(port, &key, &patch, project)?;
        print_applied(&snap, port, "session")?;
        return Ok(());
    }
    edit_scope_file(scope, root, move |doc| {
        doc["engine"]["entity_operators"][name.as_str()] = toml_edit::value(op_toml);
    })?;
    finish_file_scope(ident, project, scope, root, "reload")
}

/// Remove a per-entity override. Only meaningful at a FILE scope: the live session merge
/// is additive (it cannot delete a key), and a `reload` would reset ALL session state,
/// so a session-only override is cleared by reload/restart, not surgically here.
fn clear_entity(
    ident: Option<(u16, String)>,
    project: &str,
    root: &str,
    scope: Scope,
    name: &str,
) -> Result<()> {
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
    finish_file_scope(ident, project, scope, root, "reload")
}

/// Resolve a user-supplied entity type to its stored form + whether it is a recognized
/// BUILT-IN (a canonical category member, or the deliberately-uncategorized `DATE_TIME`/
/// `DOMAIN` opt-ins). Built-ins accept an upper-cased convenience (`url` → `URL`); any
/// other input is returned VERBATIM (case-preserved, so a mixed-case custom type isn't
/// mangled) with `false` so the caller can warn / defer to the proxy.
fn resolve_entity_type(name: &str) -> (String, bool) {
    let known = sordino_engine::Category::canonical_entity_types();
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
fn finish_file_scope(
    ident: Option<(u16, String)>,
    project: &str,
    scope: Scope,
    root: &str,
    action: &str,
) -> Result<()> {
    let path = scope_path(scope, root);
    let applied = match &ident {
        Some((port, key)) => match admin_post(*port, key, action, project) {
            Ok(snap) => {
                print_applied(&snap, *port, scope_label(scope))?;
                true
            }
            Err(_) => false,
        },
        None => false,
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
mod a5_binding_tests {
    use super::{finish_file_scope, Scope};

    // A5b: the project-identity hash threaded onto every control-plane request is derived from
    // the canonical root by a PURE hash — no IO, and stable for a fixed root across calls (so the
    // header the client sends matches the value the server-side binding will compute for the same
    // instance). Different roots hash to different keys.
    #[test]
    fn project_key_is_pure_and_deterministic() {
        let root = "/home/user/projects/alpha";
        let a = sordino_state::project_key(root);
        let b = sordino_state::project_key(root);
        assert_eq!(a, b, "project_key must be deterministic for a fixed root");
        assert!(!a.is_empty(), "project_key must produce a non-empty hash");
        let other = sordino_state::project_key("/home/user/projects/beta");
        assert_ne!(a, other, "distinct roots must hash to distinct project keys");
    }

    // A5a degrade-gracefully: with NO live proxy (`ident == None`), a file-scope apply STILL
    // succeeds — `finish_file_scope` performs no control-plane call, reports "applies on the next
    // session", and returns Ok(()) rather than erroring. This is the tolerance the config CLI must
    // preserve after the single-`live_identity`-resolve refactor: a proxy being down never blocks
    // persisting a project/user/local policy change.
    #[test]
    fn file_scope_persist_succeeds_with_no_live_proxy() {
        for scope in [Scope::Project, Scope::User, Scope::Local] {
            let out = finish_file_scope(None, "deadbeef", scope, "/tmp/sordino-a5-fixture", "reload");
            assert!(
                out.is_ok(),
                "finish_file_scope must degrade gracefully (Ok) when ident is None for {scope:?}"
            );
        }
    }
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
        "http://127.0.0.1:{port}/sordino/reveal/{}",
        percent_encode(&token)
    );
    let resp = blocking_client()
        .get(&url)
        .header("x-sordino-key", &key)
        .header("x-sordino-project", sordino_state::project_key(&root))
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
    let project = sordino_state::project_key(&root);
    println!("http://127.0.0.1:{port}/sordino/ui?key={key}&project={project}");
    Ok(())
}

// ---------------------------------------------------------------------------
// zdr (Trust switch)
// ---------------------------------------------------------------------------

/// Backs `/sordino:zdr`. Targets THIS session's conversation — the SessionStart hook
/// baked the id into `ANTHROPIC_BASE_URL` as `.../sordino/session/<id>`, which this
/// process inherits, so the CLI keys the same id the proxy sees on the wire.
fn zdr_cmd(action: Option<ZdrAction>, json: bool) -> Result<()> {
    let root = canonical(&project_root());
    let (port, key) = live_identity(&root)
        .context("could not reach this project's proxy — is a `claude` session running here?")?;
    let conv = conversation_from_base_url().context(
        "this session is not ZDR-routable: ANTHROPIC_BASE_URL has no /sordino/session/<id> \
         segment. Run /sordino:enable and restart Claude Code so the proxy sees a session id.",
    )?;
    let url = format!(
        "http://127.0.0.1:{port}/sordino/session/{}/zdr",
        percent_encode(&conv)
    );
    let client = blocking_client();
    let project = sordino_state::project_key(&root);
    // Read-only JSON posture projection. Same GET as the Status arm (fail-closed on
    // unreachable proxy / non-routable session); short-circuits AHEAD of the human path
    // and the action match, so On/Off's POST/DELETE are unreachable under --json.
    if json {
        let snap = json_or_err(
            client
                .get(&url)
                .header("x-sordino-key", &key)
                .header("x-sordino-project", &project)
                .send()?,
        )?;
        println!("{}", zdr_json_contract(&snap));
        return Ok(());
    }
    match action.unwrap_or(ZdrAction::Status) {
        ZdrAction::Status => {
            let snap = json_or_err(
                client
                    .get(&url)
                    .header("x-sordino-key", &key)
                    .header("x-sordino-project", &project)
                    .send()?,
            )?;
            print_zdr_status(&snap);
        }
        ZdrAction::Config => {
            let snap = json_or_err(
                client
                    .get(&url)
                    .header("x-sordino-key", &key)
                    .header("x-sordino-project", &project)
                    .send()?,
            )?;
            print_zdr_configs(&snap);
        }
        ZdrAction::On { config } => {
            let body = serde_json::json!({ "config": config });
            let resp = json_or_err(
                client
                    .post(&url)
                    .header("x-sordino-key", &key)
                    .header("x-sordino-project", &project)
                    .json(&body)
                    .send()?,
            )
            .context("engaging ZDR")?;
            if let Some(w) = resp.get("warning").and_then(|v| v.as_str()) {
                println!("{w}\n");
            }
            print_zdr_status(&resp);
        }
        ZdrAction::Off => {
            let resp = json_or_err(
                client
                    .delete(&url)
                    .header("x-sordino-key", &key)
                    .header("x-sordino-project", &project)
                    .send()?,
            )?;
            println!("ZDR disengaged — this session is back on the masked Anthropic path.");
            println!("(The prompt cache breaks once on the next turn.)\n");
            print_zdr_status(&resp);
        }
    }
    Ok(())
}

/// Pure reshape of the per-session `zdr_status` snapshot into the frozen v1 posture
/// contract. Re-derives nothing: `engaged`/`target` come straight off `active`, `default`
/// is copied raw (nullable), and each configured target is copied through an EXACT
/// allowlist that DROPS `base_url`; the top-level `conversation` key is dropped entirely.
/// `trust_basis` stays a bare unordered string (THREAT-MODEL N7/L11 — no ranked/numeric
/// trust). OFF case (active null): `engaged:false`, `target:null`.
fn zdr_json_contract(snap: &Value) -> Value {
    let target = snap
        .get("active")
        .cloned()
        .filter(|v| !v.is_null())
        .unwrap_or(Value::Null);
    let engaged = !target.is_null();
    let default = snap.get("default").cloned().unwrap_or(Value::Null);
    let empty: Vec<Value> = Vec::new();
    let configured = snap
        .get("configured")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let targets: Vec<Value> = configured
        .iter()
        .map(|t| {
            let mut o = serde_json::Map::new();
            for k in ["name", "trust_basis", "user_verified", "has_key"] {
                if let Some(v) = t.get(k) {
                    o.insert(k.to_string(), v.clone());
                }
            }
            Value::Object(o)
        })
        .collect();
    json!({
        "schema_version": 1,
        "engaged": engaged,
        "target": target,
        "default": default,
        "targets": targets,
    })
}

/// Backs `/sordino:disable`. Turns masking OFF — for THIS conversation by default
/// (in-memory, session-scoped, lifts on the next restart), or for the whole PROJECT
/// with `--project` (the master switch, session-live). Registered secrets are still
/// masked in both modes, and the data policy (categories/profile/threshold) is never
/// touched. Re-enable with `/sordino:privacy on`.
fn disable_cmd(project: bool) -> Result<()> {
    let root = canonical(&project_root());
    let (port, key) = live_identity(&root)
        .context("could not reach this project's proxy — is a `claude` session running here?")?;
    let project_key = sordino_state::project_key(&root);

    if project {
        // Project-wide master switch off (session-live — not persisted, so the data policy
        // on disk is unchanged). Same endpoint `config off` uses.
        let snap = admin_post(port, &key, "disable", &project_key)
            .context("turning the project master switch off")?;
        println!(
            "Sordino masking DISABLED for this PROJECT (master switch off). Every conversation \
             here now egresses UNMASKED — registered secrets are still masked."
        );
        println!(
            "Your data policy (categories/profile/threshold) is unchanged; this is session-live \
             and NOT persisted. Turn it back on with `/sordino:privacy on`.\n"
        );
        print_applied(&snap, port, "session")?;
        return Ok(());
    }

    // Conversation-scoped (default): needs a session-routed conversation id, exactly like
    // ZDR — the id is read from the inherited ANTHROPIC_BASE_URL, never threaded in.
    let conv = conversation_from_base_url().context(
        "this session is not session-routed: ANTHROPIC_BASE_URL has no /sordino/session/<id> \
         segment, so masking can't be scoped to just this conversation. Run /sordino:enable and \
         restart Claude Code, or disable the whole project with `/sordino:disable --project`.",
    )?;
    let url = format!(
        "http://127.0.0.1:{port}/sordino/session/{}/masking",
        percent_encode(&conv)
    );
    let resp = json_or_err(
        blocking_client()
            .post(&url)
            .header("x-sordino-key", &key)
            .header("x-sordino-project", &project_key)
            .send()?,
    )
    .context("disabling masking for this conversation")?;
    if let Some(w) = resp.get("warning").and_then(|v| v.as_str()) {
        println!("{w}\n");
    }
    println!(
        "Masking is now OFF for THIS conversation only — other conversations in this project are \
         unaffected. Re-enable with `/sordino:privacy on`."
    );
    Ok(())
}

/// Print the per-session ZDR status from a `{active, default, configured}` payload.
/// The chrome ALWAYS frames ZDR as the USER's assertion — never as verified.
fn print_zdr_status(snap: &Value) {
    match snap.get("active").and_then(|v| v.as_str()) {
        Some(name) => println!(
            "ZDR: ON — this session routes to '{name}' (your assertion; sordino cannot verify a \
             provider is zero-retention). Masking still applies — values are NOT revealed."
        ),
        None => println!("ZDR: OFF — this session uses the normal masked Anthropic path."),
    }
    if let Some(def) = snap.get("default").and_then(|v| v.as_str()) {
        println!("  default config: {def}");
    }
    let n = snap
        .get("configured")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    println!("  {n} configured target(s) — `/sordino:zdr config` to list.");
}

/// Print the configured ZDR targets (value-free view: never a credential).
fn print_zdr_configs(snap: &Value) {
    let configured = snap.get("configured").and_then(|v| v.as_array());
    match configured {
        Some(arr) if !arr.is_empty() => {
            println!("Configured ZDR targets (asserted by you — sordino cannot verify ZDR):");
            for t in arr {
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let basis = t.get("trust_basis").and_then(|v| v.as_str()).unwrap_or("?");
                let verified = t
                    .get("user_verified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let has_key = t.get("has_key").and_then(|v| v.as_bool()).unwrap_or(false);
                let vflag = if verified {
                    "verified"
                } else {
                    "UNVERIFIED — cannot engage"
                };
                let kflag = if has_key { "key" } else { "no-auth" };
                println!("  - {name}  [{basis}; {vflag}; {kflag}]");
            }
        }
        _ => println!(
            "No ZDR targets configured (this is optional). Add a `[[zdr.target]]` to sordino.toml \
             to enable trusted routing."
        ),
    }
}

/// Extract the conversation id the proxy will see, from the inherited
/// `ANTHROPIC_BASE_URL` (the SessionStart hook baked it in as
/// `.../sordino/session/<id>`). `None` when this session isn't session-routed.
fn conversation_from_base_url() -> Option<String> {
    conversation_from_url(&std::env::var("ANTHROPIC_BASE_URL").ok()?)
}

/// Pure parser for the conversation id embedded in a base URL (testable without env).
fn conversation_from_url(url: &str) -> Option<String> {
    const MARKER: &str = "/sordino/session/";
    // Consider only the PATH: drop any query/fragment first so the marker can't be
    // matched inside a `?redirect=/sordino/session/…`-style query, and the host can't
    // contain it (a host has no `/`). Then the marker only ever matches the real path.
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let idx = path.find(MARKER)? + MARKER.len();
    let id = path[idx..].split('/').next().unwrap_or("").trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

#[cfg(test)]
mod disable_cli_tests {
    use super::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn disable_defaults_to_conversation_scope() {
        let cli = Cli::try_parse_from(["sordino-hooks", "disable"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Disable { project: false }));
    }

    #[test]
    fn disable_project_flag_selects_project_scope() {
        let cli = Cli::try_parse_from(["sordino-hooks", "disable", "--project"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Disable { project: true }));
    }
}

/// Machine-readable-posture (F13): pure reshape + parse gates for `secrets --json`
/// and `zdr --json`.
#[cfg(test)]
mod mrp_posture_tests {
    use super::{secrets_json_contract, zdr_json_contract, Cli, Cmd, SecretsAction, ZdrAction};
    use clap::Parser;
    use serde_json::{json, Value};

    // The frozen allowlists. Any key outside these in the projection is a leak.
    const SECRET_KEYS: &[&str] = &["name", "operator", "scheme", "required", "resolved", "error"];
    const TARGET_KEYS: &[&str] = &["name", "trust_basis", "user_verified", "has_key"];

    // ---- Contract A: secrets ----

    #[test]
    fn secrets_contract_exact_shape_and_allowlist() {
        // Raw admin `secrets` block: entries carry a bogus `value` + extra key to prove
        // the allowlist DROPS them (never a value in the projection).
        let block = json!({
            "ready": false,
            "total": 3,
            "resolved": 2,
            "required": 1,
            "entries": [
                {"name": "A", "operator": "op1password", "scheme": "env", "required": true,
                 "resolved": false, "error": "not found", "value": "sk-LEAK", "extra": 1},
                {"name": "B", "operator": "literal", "scheme": "ref", "required": false,
                 "resolved": true, "error": null, "value": "sk-LEAK2"},
                // C omits `error` entirely -> exercises the allowlist's present-keys-only copy.
                {"name": "C", "operator": "literal", "scheme": "ref", "required": false,
                 "resolved": true}
            ]
        });
        let got = secrets_json_contract(&block);
        let want = json!({
            "schema_version": 1,
            "ready": false,
            "registered": 3,
            "resolved": 2,
            "required": 1,
            "unresolved": ["A"],
            "secrets": [
                {"name": "A", "operator": "op1password", "scheme": "env", "required": true,
                 "resolved": false, "error": "not found"},
                {"name": "B", "operator": "literal", "scheme": "ref", "required": false,
                 "resolved": true, "error": null},
                // C omitted `error` in the input -> allowlist copies present keys only,
                // so `error` is absent here too (proving the copy is faithful, not synthesized).
                {"name": "C", "operator": "literal", "scheme": "ref", "required": false,
                 "resolved": true}
            ]
        });
        // Shape-drift gate: any field add/rename/remove fails this equality.
        assert_eq!(got, want);
        // schema_version is a flat top-level integer.
        assert_eq!(got["schema_version"], json!(1));
        // NEVER-A-VALUE walk: every secrets[*] key set is a subset of the allowlist.
        for s in got["secrets"].as_array().unwrap() {
            for k in s.as_object().unwrap().keys() {
                assert!(
                    SECRET_KEYS.contains(&k.as_str()),
                    "leaked key `{k}` in secrets projection"
                );
            }
            assert!(s.get("value").is_none(), "a secret VALUE leaked into projection");
        }
    }

    #[test]
    fn secrets_contract_defaults_when_absent() {
        // Empty block: ready defaults true, counts 0, arrays empty.
        let got = secrets_json_contract(&json!({}));
        assert_eq!(
            got,
            json!({
                "schema_version": 1,
                "ready": true,
                "registered": 0,
                "resolved": 0,
                "required": 0,
                "unresolved": [],
                "secrets": []
            })
        );
    }

    // ---- Contract B: zdr ----

    #[test]
    fn zdr_contract_engaged_exact_shape_and_allowlist() {
        // Raw per-session zdr_status: targets carry base_url (must DROP); top-level
        // `conversation` present (must DROP).
        let snap = json!({
            "conversation": "conv-123",
            "active": "trusted-a",
            "default": "trusted-a",
            "configured": [
                {"name": "trusted-a", "base_url": "https://a.example/v1",
                 "trust_basis": "self-hosted", "user_verified": true, "has_key": true},
                {"name": "trusted-b", "base_url": "https://b.example/v1",
                 "trust_basis": "contractual", "user_verified": false, "has_key": false}
            ]
        });
        let got = zdr_json_contract(&snap);
        let want = json!({
            "schema_version": 1,
            "engaged": true,
            "target": "trusted-a",
            "default": "trusted-a",
            "targets": [
                {"name": "trusted-a", "trust_basis": "self-hosted",
                 "user_verified": true, "has_key": true},
                {"name": "trusted-b", "trust_basis": "contractual",
                 "user_verified": false, "has_key": false}
            ]
        });
        assert_eq!(got, want);
        // No top-level conversation key survives.
        assert!(got.get("conversation").is_none(), "conversation leaked into projection");
        for t in got["targets"].as_array().unwrap() {
            for k in t.as_object().unwrap().keys() {
                assert!(
                    TARGET_KEYS.contains(&k.as_str()),
                    "leaked target key `{k}`"
                );
            }
            // base_url must be dropped.
            assert!(t.get("base_url").is_none(), "base_url survived into projection");
            // trust_basis stays a bare STRING (never ranked/numeric).
            assert!(t["trust_basis"].is_string(), "trust_basis must be a JSON string");
        }
    }

    #[test]
    fn zdr_contract_off_case() {
        // active null => engaged:false, target:null.
        let snap = json!({
            "conversation": "conv-x",
            "active": Value::Null,
            "default": Value::Null,
            "configured": []
        });
        let got = zdr_json_contract(&snap);
        assert_eq!(
            got,
            json!({
                "schema_version": 1,
                "engaged": false,
                "target": Value::Null,
                "default": Value::Null,
                "targets": []
            })
        );
    }

    // ---- Parse: --json is a PARENT-only flag on Secrets/Zdr ----

    #[test]
    fn secrets_json_parse_matrix() {
        // [secrets, --json] -> action None, json true.
        let cli = Cli::try_parse_from(["sordino-hooks", "secrets", "--json"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Secrets { action: None, json: true }));
        // [secrets] -> json false.
        let cli = Cli::try_parse_from(["sordino-hooks", "secrets"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Secrets { action: None, json: false }));
        // [secrets, list, --json] -> err (List declares no --json).
        assert!(Cli::try_parse_from(["sordino-hooks", "secrets", "list", "--json"]).is_err());
        // COEXISTENCE: [secrets, scan, --json] -> err (Scan declares no --json; parent-only).
        assert!(Cli::try_parse_from(["sordino-hooks", "secrets", "scan", "--json"]).is_err());
        // [secrets, --json, scan] -> Ok(action Some(Scan), json true): short-circuit is
        // reachable even with a live action.
        let cli = Cli::try_parse_from(["sordino-hooks", "secrets", "--json", "scan"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Secrets { action: Some(SecretsAction::Scan), json: true }
        ));
    }

    #[test]
    fn zdr_json_parse_matrix() {
        // [zdr, --json] -> action None, json true.
        let cli = Cli::try_parse_from(["sordino-hooks", "zdr", "--json"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Zdr { action: None, json: true }));
        // [zdr, on, --json] -> err (no --json on the mutating action; no-mutation at parse).
        assert!(Cli::try_parse_from(["sordino-hooks", "zdr", "on", "--json"]).is_err());
        // [zdr, --json, on] -> Ok(action Some(On), json true): runtime short-circuit
        // suppresses the POST.
        let cli = Cli::try_parse_from(["sordino-hooks", "zdr", "--json", "on"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Zdr { action: Some(ZdrAction::On { .. }), json: true }
        ));
    }
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
    let project = sordino_state::project_key(&root);

    let req = json!({ "tool_name": tool_name, "tool_input": tool_input });
    let resp = match blocking_client()
        .post(format!("http://127.0.0.1:{port}/sordino/broker/resolve"))
        .header("x-sordino-key", &key)
        .header("x-sordino-project", &project)
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
/// `denied` entries from /sordino/broker/resolve (pointer + reason category only).
fn broker_denial_note(denials: &[Value]) -> String {
    let mut lines = vec![
        "Sordino kept one or more registered broker secrets MASKED for this tool call (the \
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
         dest host) to sordino.toml and restarts. You can suggest the exact rule, but only the \
         user can apply it — and you never see the secret's value."
            .to_string(),
    );
    lines.join("\n")
}

/// `/sordino:secrets` — read-only view of the registered-secret gate + status. Pulls
/// the value-free `secrets` block from the proxy snapshot. (Registration is by
/// reference in `[[secrets]]`; secret VALUES never transit this command.)
fn secrets_cmd(action: Option<SecretsAction>, json: bool) -> Result<()> {
    let root = canonical(&project_root());
    // Read-only JSON posture projection. Action-independent: it inherits Status's
    // fail-closed proxy precondition (secrets_snapshot) and short-circuits AHEAD of the
    // match, so Scan/Import (and their disk/import side effects) are never reached.
    if json {
        let snap = secrets_snapshot(&root)?;
        let secrets = snap.get("secrets").cloned().unwrap_or(Value::Null);
        println!("{}", secrets_json_contract(&secrets));
        return Ok(());
    }
    match action.unwrap_or(SecretsAction::Status) {
        // Status/List describe the LIVE registered set — they hard-require the proxy.
        SecretsAction::Status => secrets_status_cmd(&root),
        SecretsAction::List => secrets_list_cmd(&root),
        // Scan/Import live entirely inside the .env disk boundary — no live proxy.
        SecretsAction::Scan => secrets_scan_cmd(&root),
        SecretsAction::Import { file } => secrets_import_cmd(&root, file),
    }
}

/// Fetch this project's live-proxy config snapshot (Status/List need a running proxy).
fn secrets_snapshot(root: &str) -> Result<Value> {
    live_snapshot(live_identity(root), &sordino_state::project_key(root))
        .context("reading secrets status (is the proxy running?)")
}

fn secrets_status_cmd(root: &str) -> Result<()> {
    let snap = secrets_snapshot(root)?;
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
    Ok(())
}

fn secrets_list_cmd(root: &str) -> Result<()> {
    let snap = secrets_snapshot(root)?;
    let secrets = snap.get("secrets").cloned().unwrap_or(Value::Null);
    let empty: Vec<Value> = Vec::new();
    let entries = secrets
        .get("entries")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
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
    Ok(())
}

/// Pure reshape of the admin `secrets` block into the frozen v1 posture contract.
/// Re-derives nothing: `total` maps to `registered`, counts copy through (0 when absent),
/// `ready` defaults true, `unresolved` lists the names of `resolved==false` entries in
/// order, and each entry is copied through an EXACT allowlist — a secret VALUE (or any
/// other key) can NEVER appear in the projection.
fn secrets_json_contract(secrets: &Value) -> Value {
    let ready = secrets.get("ready").and_then(Value::as_bool).unwrap_or(true);
    let registered = secrets.get("total").and_then(Value::as_u64).unwrap_or(0);
    let resolved = secrets.get("resolved").and_then(Value::as_u64).unwrap_or(0);
    let required = secrets.get("required").and_then(Value::as_u64).unwrap_or(0);
    let empty: Vec<Value> = Vec::new();
    let entries = secrets
        .get("entries")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let unresolved: Vec<Value> = entries
        .iter()
        .filter(|e| !e.get("resolved").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|e| e.get("name").cloned())
        .collect();
    let secrets_list: Vec<Value> = entries
        .iter()
        .map(|e| {
            let mut o = serde_json::Map::new();
            for k in ["name", "operator", "scheme", "required", "resolved", "error"] {
                if let Some(v) = e.get(k) {
                    o.insert(k.to_string(), v.clone());
                }
            }
            Value::Object(o)
        })
        .collect();
    json!({
        "schema_version": 1,
        "ready": ready,
        "registered": registered,
        "resolved": resolved,
        "required": required,
        "unresolved": unresolved,
        "secrets": secrets_list,
    })
}

// ---------------------------------------------------------------------------
// .env intake funnel (F2 scan + F4 import) — shared eligibility, no live proxy
// ---------------------------------------------------------------------------

/// Branded, ADVISORY (non-exhaustive) secret prefixes. A value that starts with one is
/// a candidate REGARDLESS of the entropy classifier — and this short-circuits BEFORE the
/// shape-suppressor, which is exactly what rescues `SLACK_WEBHOOK_URL` (a bare `https://`
/// with no userinfo, otherwise byte-identical to the bare-URL non-secret suppressor).
const BRANDED_PREFIXES: &[&str] = &[
    "sk-",
    "sk-ant-",
    "AKIA",
    "ASIA",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AIza",
    "ya29.",
    "glpat-",
    "npm_",
    "dop_v1_",
    "SG.",
    "sk_live_",
    "rk_live_",
    "-----BEGIN",
    "https://hooks.slack.com/",
];

fn known_prefix_match(value: &str) -> bool {
    BRANDED_PREFIXES.iter().any(|p| value.starts_with(p))
}

/// A value whose SHAPE is a well-known NON-secret structure the entropy path wrongly
/// admits: a UUID (8-4-4-4-12 hex), an all-lowercase-hex 40-char git SHA, a semver, or
/// a bare URL (`https?://` with NO `@` userinfo). Applied ONLY to anonymous
/// `Eligible{reason: Entropy}` admits — never to a branded-prefix hit (short-circuits
/// first) and never to a NameMatch/Both admit (a NAMED secret is never shape-suppressed).
fn structural_nonsecret(value: &str) -> bool {
    is_uuid(value) || is_git_sha(value) || is_semver(value) || is_bare_url(value)
}

fn is_uuid(v: &str) -> bool {
    let b = v.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// An all-lowercase-hex 40-char git SHA (`[0-9a-f]{40}`). Uppercase hex is NOT a git SHA.
fn is_git_sha(v: &str) -> bool {
    v.len() == 40
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `v?MAJOR.MINOR.PATCH` with an optional `-prerelease` / `+build` suffix.
fn is_semver(v: &str) -> bool {
    let core = v.strip_prefix('v').unwrap_or(v);
    // Split off any prerelease/build suffix at the first '-' or '+'.
    let core = core
        .split_once(['-', '+'])
        .map(|(c, _)| c)
        .unwrap_or(core);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
}

/// A bare `http(s)://` URL with NO `@` userinfo (a public URL, not a credentialed DSN).
fn is_bare_url(v: &str) -> bool {
    (v.starts_with("https://") || v.starts_with("http://")) && !v.contains('@')
}

/// The single, shared candidacy predicate for both scan and import. A branded prefix
/// admits unconditionally; otherwise the entropy classifier decides, with the
/// shape-suppressor applied ONLY to anonymous Entropy admits (the reason-gate that
/// preserves recall on the GITHUB_TOKEN / SLACK_WEBHOOK_URL shape-collisions).
fn is_candidate(name: &str, value: &str) -> bool {
    if known_prefix_match(value) {
        return true;
    }
    match sordino_secrets::classify(name, value) {
        sordino_secrets::Eligibility::Eligible {
            reason: sordino_secrets::EligibleReason::Entropy,
            ..
        } => !structural_nonsecret(value),
        // NameMatch / Both: a NAMED secret is NEVER shape-suppressed.
        sordino_secrets::Eligibility::Eligible { .. } => true,
        sordino_secrets::Eligibility::Skip(_) => false,
    }
}

/// This project's live registered-secret names, BEST-EFFORT (empty if the proxy is
/// down — scan/import are supported with no proxy). Never fails the command.
fn registered_secret_names(root: &str) -> HashSet<String> {
    live_snapshot(live_identity(root), &sordino_state::project_key(root))
        .ok()
        .and_then(|s| {
            s["secrets"]["entries"].as_array().map(|a| {
                a.iter()
                    .filter_map(|e| e["name"].as_str().map(str::to_string))
                    .collect::<HashSet<String>>()
            })
        })
        .unwrap_or_default()
}

/// Is `name` a `.env` file we intake? `.env` and `.env.*` EXCEPT the example/sample
/// sidecars (`.env.example`, `.env.sample`, `.env.*.example`).
fn is_intake_env_file(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    if name.strip_prefix(".env.").is_none() {
        return false;
    }
    if name == ".env.sample" || name.ends_with(".example") {
        return false;
    }
    true
}

/// Every intakeable `.env` file directly under `root` (sorted for deterministic output).
fn enumerate_env_files(root: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(Path::new(root)) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_intake_env_file)
        {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// `path` displayed relative to `root` when possible (for the `dotenv:<rel>#KEY` ref and
/// the scan/prompt display). Falls back to the full path.
fn display_rel(root: &str, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Build the VALUE-FREE scan report (pure — takes the resolved inputs so it is testable
/// without a live proxy). Prints ONLY key names + file paths, never a value.
fn scan_report(root: &str, files: &[PathBuf], registered: &HashSet<String>, proxy_up: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if !proxy_up {
        let _ = writeln!(
            out,
            "(proxy not reachable — the registered set is empty; results are best-effort)"
        );
    }
    let mut any_unregistered = false;
    for file in files {
        let Ok(iter) = dotenvy::from_path_iter(file) else {
            continue;
        };
        let mut unregistered: Vec<String> = Vec::new();
        for item in iter {
            let Ok((key, value)) = item else { continue };
            if is_candidate(&key, &value) && !registered.contains(&key) {
                unregistered.push(key);
            }
        }
        let rel = display_rel(root, file);
        let _ = writeln!(out, "{rel}: {} value(s) not registered", unregistered.len());
        for key in &unregistered {
            let _ = writeln!(out, "  • {key}");
            any_unregistered = true;
        }
    }
    if any_unregistered {
        let _ = writeln!(
            out,
            "These mask only if a recognizer happens to catch them — registration via \
             `secrets import` makes them unconditional (G1)."
        );
    }
    out
}

/// F2 `secrets scan`: read-only, value-free. Enumerate `.env`/`.env.*`, list unregistered
/// candidate KEYS per file. Best-effort registered set; exit 0 always.
fn secrets_scan_cmd(root: &str) -> Result<()> {
    let registered = registered_secret_names(root);
    let proxy_up = live_identity(root).is_some();
    let files = enumerate_env_files(root);
    print!("{}", scan_report(root, &files, &registered, proxy_up));
    Ok(())
}

/// A single accepted key, ready to become a `[[secrets]]` REFERENCE stanza.
#[derive(Clone, Debug, PartialEq)]
struct AcceptedSecret {
    name: String,
    from_ref: String,
    operator: Option<String>,
}

/// Outcome of the pure [`import_merge`] transform.
#[derive(Debug, PartialEq)]
enum ImportOutcome {
    Changed(String),
    NoOp,
    Refused(String),
}

/// PURE toml_edit merge: append each accepted key as a `[[secrets]]` REFERENCE stanza to
/// `current`, preserving all existing stanzas + `[engine]`/comments byte-for-byte. Refuses
/// (never overwrites) unparseable TOML or a `secrets` key that is NOT an array-of-tables.
/// Idempotent: an accepted name already present as a `[[secrets]]` stanza is SKIPPED. NEVER
/// writes a value/literal/secret/plaintext/from_env — only `name`, `from_ref`, and (if set)
/// `operator`, in that deterministic order.
fn import_merge(current: &str, accepted: &[AcceptedSecret]) -> ImportOutcome {
    let mut doc = match current.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return ImportOutcome::Refused(format!(
                "sordino.toml is not valid TOML; refusing to overwrite: {e}"
            ));
        }
    };

    // Ensure `secrets` is an array-of-tables. Present-but-not-AoT (a scalar `secrets = "x"`
    // or a `[secrets]` table) is REFUSED — never coerced/clobbered.
    match doc.get("secrets") {
        Some(item) if item.as_array_of_tables().is_none() => {
            return ImportOutcome::Refused(
                "`secrets` in sordino.toml is not an array-of-tables ([[secrets]]); \
                 refusing to modify it"
                    .into(),
            );
        }
        None => {
            doc["secrets"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }
        _ => {}
    }

    // Snapshot existing stanza names for the idempotent skip.
    let existing: HashSet<String> = doc["secrets"]
        .as_array_of_tables()
        .map(|aot| {
            aot.iter()
                .filter_map(|t| t.get("name").and_then(|i| i.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let aot = doc["secrets"]
        .as_array_of_tables_mut()
        .expect("secrets ensured array-of-tables above");
    let mut appended = 0usize;
    for entry in accepted {
        if existing.contains(&entry.name) {
            continue; // idempotent
        }
        let mut table = toml_edit::Table::new();
        table["name"] = toml_edit::value(entry.name.clone());
        table["from_ref"] = toml_edit::value(entry.from_ref.clone());
        if let Some(op) = &entry.operator {
            table["operator"] = toml_edit::value(op.clone());
        }
        aot.push(table);
        appended += 1;
    }

    if appended == 0 {
        ImportOutcome::NoOp
    } else {
        ImportOutcome::Changed(doc.to_string())
    }
}

/// PURE resolution of the intake file set for `secrets import`, honoring the SAME boundary
/// as auto-discovery. `--file` is a FILTER within the intake set — not an arbitrary-file
/// override — so `Some(f)` must be an intake `.env` (never an `.env.example`/`.env.sample`
/// placeholder sidecar, per [`is_intake_env_file`]) AND live inside `root` (canonicalized
/// containment). Either failure is an argument error. On success the NON-canonical resolved
/// path is returned so the `dotenv:<rel>#KEY` relpath ([`display_rel`]) is unchanged.
/// `None` enumerates the project's intake `.env` files exactly as the scan/discovery path.
fn resolve_import_files(root: &str, file: Option<PathBuf>) -> Result<Vec<PathBuf>, String> {
    let Some(f) = file else {
        return Ok(enumerate_env_files(root));
    };
    let path = if f.is_absolute() { f } else { Path::new(root).join(&f) };
    let reject = || {
        format!(
            "Sordino: --file must name a project .env file inside {root} (not an \
             .env.example/.env.sample sidecar or a path outside the project)"
        )
    };
    // (a) intake-named basename (excludes .env.example / .env.sample placeholders).
    if !path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_intake_env_file)
    {
        return Err(reject());
    }
    // (b) contained under root: canonicalize both and require the file to sit inside root.
    let (Ok(canon), Ok(canon_root)) =
        (std::fs::canonicalize(&path), std::fs::canonicalize(root))
    else {
        return Err(reject());
    };
    if !canon.starts_with(&canon_root) {
        return Err(reject());
    }
    Ok(vec![path])
}

/// F4 `secrets import`: per-value INTERACTIVE opt-in. FAILS CLOSED on a non-interactive
/// terminal (writes nothing). Prompts per surviving candidate (KEY + file only, never the
/// value); accepted keys become `[[secrets]]` REFERENCE stanzas in `<root>/sordino.toml`.
fn secrets_import_cmd(root: &str, file: Option<PathBuf>) -> Result<()> {
    // An invalid `--file` is an ARGUMENT error, independent of interactivity — resolve the
    // intake file set (same boundary as auto-discovery) BEFORE the tty gate. The no-file
    // path stays silent here, so its non-tty behavior is unchanged (the tty gate fires next).
    let files = match resolve_import_files(root, file) {
        Ok(files) => files,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    // FAIL CLOSED: per-value opt-in demands a real interactive terminal. Gate on BOTH
    // stdin and stdout being a tty — stdout-only would be bypassed by `yes | ... import`.
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        eprintln!(
            "Sordino: import needs an interactive terminal (per-value opt-in only; \
             never auto-registers)"
        );
        std::process::exit(2);
    }

    let registered = registered_secret_names(root);

    let stdin = std::io::stdin();
    let mut accepted: Vec<AcceptedSecret> = Vec::new();
    let mut accepted_names: HashSet<String> = HashSet::new();
    'files: for file in &files {
        let Ok(iter) = dotenvy::from_path_iter(file) else {
            continue;
        };
        let rel = display_rel(root, file);
        for item in iter {
            let Ok((key, value)) = item else { continue };
            if !is_candidate(&key, &value) {
                continue;
            }
            if registered.contains(&key) || accepted_names.contains(&key) {
                continue;
            }
            // Prompt on stderr (unbuffered) — KEY + file ONLY, never the value.
            eprint!("Register {key} from {rel}? [y/N/q] ");
            let mut line = String::new();
            if stdin.read_line(&mut line)? == 0 {
                break 'files; // EOF ⇒ stop, keep what was accepted so far
            }
            match line.trim() {
                "y" | "Y" => {
                    accepted_names.insert(key.clone());
                    accepted.push(AcceptedSecret {
                        name: key.clone(),
                        from_ref: format!("dotenv:{rel}#{key}"),
                        operator: None,
                    });
                }
                "q" | "Q" => break 'files, // stop + write accepted-so-far
                _ => {}                     // anything else ⇒ skip
            }
        }
    }

    let toml_path = Path::new(root).join("sordino.toml");
    let current = std::fs::read_to_string(&toml_path).unwrap_or_default();
    match import_merge(&current, &accepted) {
        ImportOutcome::Changed(text) => {
            atomic_write_text(&toml_path, &text)?;
            println!(
                "wrote {} secret reference(s) to sordino.toml — restart the session \
                 (or POST /sordino/reload) to resolve them",
                accepted.len()
            );
        }
        ImportOutcome::NoOp => println!("nothing to import"),
        ImportOutcome::Refused(msg) => bail!(msg),
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
    let (port, rec) = sordino_state::live_port(root)?;
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
         project? (start one, or run /sordino:enable)",
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

fn live_snapshot(ident: Option<(u16, String)>, project: &str) -> Result<Value> {
    let (port, key) = ident
        .context("could not read this project's proxy key — is a `claude` session running here?")?;
    admin_get(port, &key, project)
}

fn admin_get(port: u16, key: &str, project: &str) -> Result<Value> {
    let resp = blocking_client()
        .get(format!("http://127.0.0.1:{port}/sordino/config"))
        .header("x-sordino-key", key)
        .header("x-sordino-project", project)
        .send()?;
    json_or_err(resp)
}

fn admin_post(port: u16, key: &str, path: &str, project: &str) -> Result<Value> {
    let resp = blocking_client()
        .post(format!("http://127.0.0.1:{port}/sordino/{path}"))
        .header("x-sordino-key", key)
        .header("x-sordino-project", project)
        .send()?;
    json_or_err(resp)
}

fn admin_put(port: u16, key: &str, config: &Value, project: &str) -> Result<Value> {
    let resp = blocking_client()
        .put(format!("http://127.0.0.1:{port}/sordino/config"))
        .header("x-sordino-key", key)
        .header("x-sordino-project", project)
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
    if serde_json::from_value::<sordino_engine::Category>(json!(name)).is_err() {
        bail!(
            "unknown category '{name}'. valid: secrets, financial, identity, contact, network, personal"
        );
    }
    Ok(())
}

fn category_set_to_vec(cats: &std::collections::HashSet<sordino_engine::Category>) -> Vec<String> {
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
fn effective_categories(ident: Option<(u16, String)>, project: &str, root: &str) -> Vec<String> {
    if let Ok(snap) = live_snapshot(ident, project)
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
        sordino_state::user_config_path(),
        Path::new(root).join("sordino.toml"),
        Path::new(root).join("sordino.local.toml"),
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
        Scope::Project => Path::new(root).join("sordino.toml"),
        Scope::Local => Path::new(root).join("sordino.local.toml"),
        Scope::User => sordino_state::user_config_path(),
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
    /// Optional ZDR (Trust switch) summary (absent on older proxies). Active sessions
    /// + value-free target views — never a credential.
    #[serde(default)]
    zdr: ZdrSummary,
}

/// The proxy's `zdr` block. `active` lists the currently ZDR-routed conversations
/// (so the statusline can show a per-session segment); no credential ever appears.
#[derive(serde::Deserialize, Default)]
struct ZdrSummary {
    #[serde(default)]
    active: Vec<ZdrActive>,
}

#[derive(serde::Deserialize)]
struct ZdrActive {
    #[serde(default)]
    conversation: String,
    #[serde(default)]
    config: String,
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
    /// `disabled` | `loading` | `ready` | `failed` (see `sordino_engine::MlStatus`).
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
    // Per-conversation masking switch: if THIS session's conversation is disabled, call it
    // out — the master-switch line above shows ON, so this is the only signal that THIS
    // conversation is nonetheless passing PII through.
    if let Some(conv) = conversation_from_base_url()
        && snap
            .get("masking_disabled_conversations")
            .and_then(|v| v.as_array())
            .is_some_and(|a| a.iter().any(|c| c.as_str() == Some(conv.as_str())))
    {
        println!(
            "  this conversation : masking OFF (per-conversation `/sordino:disable`) — \
             `/sordino:privacy on` to resume"
        );
    }
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
        "Sordino privacy — {state}   (profile: {}, port {port})",
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
/// co-baked `env.SORDINO_PORT`. Port-agnostic "is this project plumbed through us" (an
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
            .get("SORDINO_PORT")
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
    fn loopback_url_port_path_tolerant_parses_session_route() {
        // The whole point: a PATH-BEARING loopback route still yields its port so
        // `observe_routed_endpoint` can probe THAT port's identity. `loopback_url_port` returns
        // None here (path-intolerant) — the dual-instance false negative this atomic fixes.
        // (T1) A foreign SessionStart session route → the FOREIGN port to probe.
        assert_eq!(
            loopback_url_port_path_tolerant("http://127.0.0.1:41999/sordino/session/abc123"),
            Some(41999)
        );
        assert_eq!(loopback_url_port("http://127.0.0.1:41999/sordino/session/abc123"), None);
        // (T2) An OWN-port session route resolves to the same port → later matched to live_identity
        // → OwnOrDirect (no false positive). Extraction is identity-agnostic; the port is what gates.
        assert_eq!(
            loopback_url_port_path_tolerant("http://127.0.0.1:40000/sordino/session/xyz"),
            Some(40000)
        );
        // Other paths / queries / fragments / trailing slash are equally tolerated.
        assert_eq!(loopback_url_port_path_tolerant("http://127.0.0.1:8080/v1"), Some(8080));
        assert_eq!(loopback_url_port_path_tolerant("http://localhost:9000/?x=1"), Some(9000));
        assert_eq!(loopback_url_port_path_tolerant("http://127.0.0.1:8080/"), Some(8080));
        assert_eq!(loopback_url_port_path_tolerant("http://[::1]:8080/sordino/session/id"), Some(8080));
        // Bare route (no path) still parses — parity with the intolerant sibling.
        assert_eq!(loopback_url_port_path_tolerant("http://127.0.0.1:41234"), Some(41234));
        // Non-loopback host, port-less URL, and non-numeric port → None (no port to probe).
        assert_eq!(loopback_url_port_path_tolerant("https://api.anthropic.com/v1"), None);
        assert_eq!(loopback_url_port_path_tolerant("http://192.168.1.5:80/sordino/session/x"), None);
        assert_eq!(loopback_url_port_path_tolerant("http://127.0.0.1/sordino/session/x"), None);
        assert_eq!(loopback_url_port_path_tolerant("http://127.0.0.1:notaport/v1"), None);
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
        let dir = std::env::temp_dir().join(format!("sordino-baked-{}", std::process::id()));
        let claude = dir.join(".claude");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&claude).unwrap();
        let root = dir.to_string_lossy().into_owned();
        let settings = claude.join("settings.local.json");

        // No settings → None.
        assert_eq!(project_baked_route(&root), None);

        // Our route: loopback URL whose port matches the co-baked SORDINO_PORT.
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","SORDINO_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(project_baked_route(&root), Some(41999));

        // A user's own base URL (no/with mismatched SORDINO_PORT) is NOT ours.
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://gw.corp.example/v1","SORDINO_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(project_baked_route(&root), None);

        // URL/port disagreement (stale SORDINO_PORT) → not trusted.
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","SORDINO_PORT":"40000"}}"#,
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
        let dir = std::env::temp_dir().join(format!("sordino-rseg-q4-{}", std::process::id()));
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
            "\u{2717} Sordino not masking"
        );

        // A route baked into settings.local.json → honest "restart to mask": a restart WILL
        // read and apply it (the legit first-run live-reload window).
        std::fs::write(
            &settings,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","SORDINO_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(
            render_segment(None, &root, SlMode::Compact),
            "\u{27f3} Sordino: restart to mask"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C4: ShieldOnly renders NOTHING in every non-masking state (the inverse of Min, which
    /// always renders a glyph) — so the line appears solely as a positive masking indicator.
    #[test]
    fn shield_only_is_empty_in_non_masking_states() {
        let dir = std::env::temp_dir().join(format!("sordino-rseg-sh-{}", std::process::id()));
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
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:41999","SORDINO_PORT":"41999"}}"#,
        )
        .unwrap();
        assert_eq!(render_segment(None, &root, SlMode::ShieldOnly), "");
        // The unverified state (identity mismatch / parse failure) → empty under ShieldOnly.
        assert_eq!(unverified(41999, SlMode::ShieldOnly), "");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C4: `$SORDINO_STATUSLINE` aliases map to ShieldOnly, and the ONE state it renders
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

    /// A1 regression guard: every LIVE ML state carries the literal `ml` text so the indicator
    /// stays legible on terminals/fonts that can't render the emoji glyph — the brain `🧠` used
    /// to be the lone glyph-only state and went INVISIBLE there while masking was active. Also
    /// pins the exact glyphs and the VS16 qualifier on the brain.
    #[test]
    fn ml_indicator_states_keep_ml_text_fallback() {
        let snap = |status: &str, runtime_err: bool| -> MlSnap {
            serde_json::from_value(serde_json::json!({
                "status": status,
                "last_runtime_error": runtime_err.then_some("boom"),
            }))
            .unwrap()
        };

        // Exact renderings: brain is VS16-qualified, and every live state ends in the `ml` anchor.
        assert_eq!(ml_indicator(Some(&snap("ready", false))), " \u{1f9e0}\u{fe0f}ml");
        assert_eq!(ml_indicator(Some(&snap("ready", true))), " \u{26a0}\u{1f9e0}\u{fe0f}ml");
        assert_eq!(ml_indicator(Some(&snap("loading", false))), " \u{23f3}ml");
        assert_eq!(ml_indicator(Some(&snap("failed", false))), " \u{26a0}ml");

        // The load-bearing invariant: no live ML state is glyph-only. Strip every non-ASCII
        // glyph and the readable `ml` token must survive, else a glyph-less terminal shows blank.
        for (status, rerr) in [("ready", false), ("ready", true), ("loading", false), ("failed", false)] {
            let s = ml_indicator(Some(&snap(status, rerr)));
            let ascii: String = s.chars().filter(char::is_ascii).collect();
            assert!(ascii.contains("ml"), "{status:?} rerr={rerr} lost its ml fallback: {s:?}");
        }

        // Inactive / absent / unrecognized status → no indicator at all.
        assert_eq!(ml_indicator(None), "");
        assert_eq!(ml_indicator(Some(&snap("disabled", false))), "");
        assert_eq!(ml_indicator(Some(&snap("bananas", false))), "");
    }

    #[test]
    fn intake_should_block_verified_truth_table() {
        // INDEPENDENT oracle (not the function's own formula): the gate BLOCKs in EXACTLY one of
        // the 16 states — plumbed, identity NOT verified, not opted out, no escape hatch. Every
        // other combination ALLOWs. This pins the fail-closed contract over the whole input space.
        for opted_out in [false, true] {
            for plumbed in [false, true] {
                for identity_ok in [false, true] {
                    for escape_hatch in [false, true] {
                        let expect =
                            (opted_out, plumbed, identity_ok, escape_hatch) == (false, true, false, false);
                        assert_eq!(
                            intake_should_block_verified(opted_out, plumbed, identity_ok, escape_hatch),
                            expect,
                            "row opted_out={opted_out} plumbed={plumbed} identity_ok={identity_ok} escape_hatch={escape_hatch}"
                        );
                    }
                }
            }
        }

        // Named anchors for the load-bearing rows:
        // The one BLOCK state — plumbed, identity unverified (proxy down / FOREIGN listener on the
        // baked port / never routed), not opted out, no escape hatch.
        assert!(intake_should_block_verified(false, true, false, false));
        // Identity-verified → reaching OUR proxy (fails-closed there) → ALLOW.
        assert!(!intake_should_block_verified(false, true, true, false));
        // Not plumbed → no masking intent → never gate a foreign project.
        assert!(!intake_should_block_verified(false, false, false, false));
        // Opted out → sending direct is exactly what opt-out means.
        assert!(!intake_should_block_verified(true, true, false, false));
        // SORDINO_NO_INTAKE_GATE escape hatch overrides even the block state.
        assert!(!intake_should_block_verified(false, true, false, true));
    }

    #[test]
    fn sordino_commands_pass_a_closed_intake_gate() {
        // The recovery levers a user reaches for while the gate is closed all pass.
        assert!(prompt_is_sordino_command("/sordino:disable"));
        assert!(prompt_is_sordino_command("/sordino:enable"));
        assert!(prompt_is_sordino_command("/sordino:status"));
        // Trailing args/newlines are fine; the prefix is matched at byte 0.
        assert!(prompt_is_sordino_command("/sordino:secrets status"));
        assert!(prompt_is_sordino_command("/sordino:verify\n"));

        // LEADING WHITESPACE is not a slash command (Claude Code recognises `/` only at byte 0),
        // so it stays gated — it could be ordinary prose carrying PII.
        assert!(!prompt_is_sordino_command("  /sordino:disable"));
        // A real prompt that merely MENTIONS a command is NOT a launch — it could carry PII, so
        // it stays gated.
        assert!(!prompt_is_sordino_command("should I run /sordino:disable?"));
        // Other namespaces, near-misses (no colon), and empty input never open the gate.
        assert!(!prompt_is_sordino_command("/other:thing"));
        assert!(!prompt_is_sordino_command("/sordino-ish"));
        assert!(!prompt_is_sordino_command("/sordino"));
        assert!(!prompt_is_sordino_command(""));
        assert!(!prompt_is_sordino_command("my email is a@b.com"));
    }

    #[test]
    fn prompt_extracted_from_hook_payload_or_none() {
        assert_eq!(
            prompt_from_hook_payload(r#"{"prompt":"/sordino:disable","session_id":"abc"}"#)
                .as_deref(),
            Some("/sordino:disable")
        );
        // Missing key / non-JSON degrade to None (→ empty prompt → fail-closed block).
        assert_eq!(prompt_from_hook_payload(r#"{"foo":"bar"}"#), None);
        assert_eq!(prompt_from_hook_payload("not json"), None);
    }

    #[test]
    fn narrate_only_on_crossing_the_masked_boundary() {
        use MaskState::*;
        // Fresh masked baseline speaks; a cold open on any NOT-masked state stays silent (don't
        // nag a session that was never masking — the gate already governs those).
        assert!(should_narrate(None, Masked));
        assert!(!should_narrate(None, NotReaching));
        assert!(!should_narrate(None, Off));
        assert!(!should_narrate(None, Disabled));
        // Dropping OUT of masked always speaks (the security-critical delta).
        assert!(should_narrate(Some(Masked), Off));
        assert!(should_narrate(Some(Masked), NotReaching));
        assert!(should_narrate(Some(Masked), Disabled));
        // Recovery back INTO masked speaks.
        assert!(should_narrate(Some(NotReaching), Masked));
        assert!(should_narrate(Some(Disabled), Masked));
        // Unchanged: silent.
        assert!(!should_narrate(Some(Masked), Masked));
        assert!(!should_narrate(Some(Off), Off));
        // Between two NOT-masked states no boundary is crossed → silent (still unmasked either way).
        assert!(!should_narrate(Some(Off), NotReaching));
        assert!(!should_narrate(Some(NotReaching), Disabled));
        // UnmaskedBypass (deliberate gate bypass = real unmasked egress) announces on first
        // appearance and then stays silent; dropping out of masked into it, or recovering from it
        // back to masked, both speak.
        assert!(should_narrate(None, UnmaskedBypass));
        assert!(!should_narrate(Some(UnmaskedBypass), UnmaskedBypass));
        assert!(should_narrate(Some(Masked), UnmaskedBypass));
        assert!(should_narrate(Some(UnmaskedBypass), Masked));
    }

    #[test]
    fn delta_messages_are_factual_status_not_injection_shaped() {
        let masked = mask_delta_message(&SessionStatus {
            state: MaskState::Masked,
            port: 8787,
            profile: "balanced".to_string(),
        });
        assert!(masked.starts_with("Sordino:"));
        assert!(masked.contains(":8787") && masked.contains("balanced"));

        let off = mask_delta_message(&SessionStatus {
            state: MaskState::Off,
            port: 0,
            profile: String::new(),
        });
        assert!(off.contains("/sordino:privacy")); // points at the re-enable lever
        let not = mask_delta_message(&SessionStatus {
            state: MaskState::NotReaching,
            port: 0,
            profile: String::new(),
        });
        assert!(not.contains("/sordino:verify")); // offers a verification path
        let bypass = mask_delta_message(&SessionStatus {
            state: MaskState::UnmaskedBypass,
            port: 0,
            profile: String::new(),
        });
        // The one allow-path state where real PII egresses — must say so plainly and name the lever.
        assert!(bypass.contains("UNMASKED") && bypass.contains("SORDINO_NO_INTAKE_GATE"));

        // Every variant is on the announced channel and free of the alarmist / gag register that
        // made the old stale-port copy read as a prompt injection.
        for state in [
            MaskState::Masked,
            MaskState::Off,
            MaskState::NotReaching,
            MaskState::Disabled,
            MaskState::UnmaskedBypass,
        ] {
            let m = mask_delta_message(&SessionStatus { state, port: 8787, profile: "balanced".into() });
            assert!(m.starts_with("Sordino:"));
            assert!(!m.contains("Ctrl-C"));
            assert!(!m.to_ascii_lowercase().contains("never claim"));
        }
    }

    #[test]
    fn mask_state_serializes_snake_case_and_roundtrips() {
        assert_eq!(serde_json::to_string(&MaskState::NotReaching).unwrap(), "\"not_reaching\"");
        assert_eq!(
            serde_json::to_string(&MaskState::UnmaskedBypass).unwrap(),
            "\"unmasked_bypass\""
        );
        assert_eq!(serde_json::from_str::<MaskState>("\"masked\"").unwrap(), MaskState::Masked);
        assert_eq!(serde_json::from_str::<MaskState>("\"disabled\"").unwrap(), MaskState::Disabled);
    }

    #[test]
    fn session_status_record_roundtrips_per_conversation() {
        let dir = std::env::temp_dir().join(format!("sordino-ss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Missing record → None (a first message has no baseline yet).
        assert_eq!(read_mask_state_at(&dir, "conv-a"), None);

        write_mask_state_at(&dir, "conv-a", MaskState::Masked);
        assert_eq!(read_mask_state_at(&dir, "conv-a"), Some(MaskState::Masked));
        // Overwrite tracks the latest state.
        write_mask_state_at(&dir, "conv-a", MaskState::Off);
        assert_eq!(read_mask_state_at(&dir, "conv-a"), Some(MaskState::Off));
        // A second session in the same project keeps its OWN baseline.
        assert_eq!(read_mask_state_at(&dir, "conv-b"), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_keeps_fresh_records_and_tolerates_missing_dir() {
        let dir = std::env::temp_dir().join(format!("sordino-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_mask_state_at(&dir, "fresh-a", MaskState::Masked);
        write_mask_state_at(&dir, "fresh-b", MaskState::Off);
        // Nothing is two weeks old → both survive.
        prune_stale_status(&dir);
        assert_eq!(read_mask_state_at(&dir, "fresh-a"), Some(MaskState::Masked));
        assert_eq!(read_mask_state_at(&dir, "fresh-b"), Some(MaskState::Off));
        // Pruning a non-existent directory must not panic.
        prune_stale_status(&dir.join("does-not-exist"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- A6/H1/D1: ZDR transition signal --------------------------------------------

    /// A fresh, isolated zdr-reports dir for one test (keyed by pid + tag so parallel
    /// tests never collide), pre-created.
    fn fresh_reports_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("sordino-zdr-reports-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write a per-conversation report file exactly as A4's `write_report` does: the file is
    /// named `<sanitize_component(conv)>.json` and holds one serialized `ReloadOutcome` (the
    /// proxy uses `to_vec_pretty` with `#[serde(tag="kind", rename_all="snake_case")]`).
    fn write_restored(dir: &std::path::Path, conv: &str, target: &str) {
        let body = json!({ "kind": "restored", "conversation": conv, "target": target });
        std::fs::write(
            dir.join(format!("{}.json", sanitize_component(conv))),
            serde_json::to_vec_pretty(&body).unwrap(),
        )
        .unwrap();
    }

    fn write_reverted(dir: &std::path::Path, conv: &str, reason: &str) {
        let body = json!({ "kind": "reverted", "conversation": conv, "reason": reason });
        std::fs::write(
            dir.join(format!("{}.json", sanitize_component(conv))),
            serde_json::to_vec_pretty(&body).unwrap(),
        )
        .unwrap();
    }

    /// Write the project-scoped global Corrupt sentinel exactly as A4's `write_global_revert`:
    /// `<project_key>.global.json` holding `{"epoch":..,"conversation":"*","reason":..}`.
    fn write_global(dir: &std::path::Path, project_key: &str, epoch: u64, reason: &str) {
        let body = json!({ "epoch": epoch, "conversation": "*", "reason": reason });
        std::fs::write(
            dir.join(format!("{project_key}.global.json")),
            serde_json::to_vec_pretty(&body).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn zdr_transition_narrated_once() {
        let dir = fresh_reports_dir("narrate-once");
        let pk = "pk0";
        write_restored(&dir, "c1", "box");

        // First consume: the Restored line, and the report file is claimed (removed).
        let first = consume_zdr_transitions(&dir, "c1", pk);
        assert_eq!(first.len(), 1, "expected exactly one line, got {first:?}");
        assert!(
            first[0].contains("ZDR restored → box for this conversation"),
            "unexpected line: {}",
            first[0]
        );
        assert!(first[0].starts_with("Sordino:"));
        assert!(
            !dir.join("c1.json").exists(),
            "report file must be removed by the claim"
        );

        // Second consume (file absent): no line — fires exactly once.
        assert!(consume_zdr_transitions(&dir, "c1", pk).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_corrupt_reemits_on_new_epoch() {
        let dir = fresh_reports_dir("global-epoch");
        let pk = "pkG";

        // Epoch E1, no marker → emit + stamp E1.
        write_global(&dir, pk, 1001, "selections file unparseable");
        let r1 = consume_zdr_transitions(&dir, "cX", pk);
        assert_eq!(r1.len(), 1);
        assert!(r1[0].contains("ZDR selection state was unreadable at startup"));
        assert!(r1[0].contains("selections file unparseable"));
        let marker = dir.join("cX.global-seen");
        assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "1001");

        // Same file (E1) + marker E1 → no line.
        assert!(consume_zdr_transitions(&dir, "cX", pk).is_empty());

        // Global rewritten to a NEW epoch E2 → emit AGAIN + restamp E2 (the S2 fix:
        // a bare touch-file marker would have suppressed this second corrupt instance).
        write_global(&dir, pk, 2002, "selections file unparseable again");
        let r3 = consume_zdr_transitions(&dir, "cX", pk);
        assert_eq!(r3.len(), 1, "a new corrupt epoch must re-emit");
        assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "2002");

        // And it settles again after re-stamping.
        assert!(consume_zdr_transitions(&dir, "cX", pk).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zdr_per_conv_emits_only_if_claim_succeeds() {
        let dir = fresh_reports_dir("claim");
        let pk = "pkC";

        // Claim-time race: the report file is pre-removed (a same-conversation racer already
        // claimed it). `remove_file` cannot succeed → NO per-conv line. We model this by simply
        // having no file present at consume time.
        assert!(
            consume_zdr_transitions(&dir, "c1", pk).is_empty(),
            "no file to claim → no emit"
        );

        // And the normal lifecycle: one successful consume emits, the second (now-absent file)
        // emits nothing.
        write_reverted(&dir, "c1", "target no longer configured");
        let first = consume_zdr_transitions(&dir, "c1", pk);
        assert_eq!(first.len(), 1);
        assert!(first[0].contains("ZDR could NOT be restored (target no longer configured)"));
        assert!(consume_zdr_transitions(&dir, "c1", pk).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zdr_two_conversations_consume_independently() {
        let dir = fresh_reports_dir("two-conv");
        let pk = "pk2";
        write_restored(&dir, "c1", "box");
        write_reverted(&dir, "c2", "target no longer user_verified");

        // c1 consumes its own Restored line and does NOT erase c2's file.
        let r1 = consume_zdr_transitions(&dir, "c1", pk);
        assert_eq!(r1.len(), 1);
        assert!(r1[0].contains("ZDR restored → box"));
        assert!(dir.join("c2.json").exists(), "c1 must not erase c2's report");

        // c2 consumes its own Reverted line.
        let r2 = consume_zdr_transitions(&dir, "c2", pk);
        assert_eq!(r2.len(), 1);
        assert!(r2[0].contains("ZDR could NOT be restored (target no longer user_verified)"));

        // Each fired exactly once.
        assert!(consume_zdr_transitions(&dir, "c1", pk).is_empty());
        assert!(consume_zdr_transitions(&dir, "c2", pk).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round-2 HIGH fix: when a mask-delta line AND one-or-more ZDR-transition lines both fire on
    /// the same turn (the canonical post-recycle case), they MUST be coalesced into a SINGLE
    /// top-level hook JSON object. Claude Code parses a command hook's ENTIRE stdout as one
    /// `JSON.parse` document; two concatenated objects would throw and CC would inject the raw stdout
    /// as plaintext — after the one-shot ZDR report was already consumed. This pins the invariant
    /// that the production emit path (`session_additional_context_json`) yields exactly ONE object
    /// carrying both lines.
    #[test]
    fn session_additional_context_coalesces_into_one_object() {
        let mask = mask_delta_message(&SessionStatus {
            state: MaskState::Masked,
            port: 8787,
            profile: "balanced".into(),
        });
        let zdr = zdr_report_message(&ReloadOutcome::Restored { target: "box".into() });
        let lines = vec![mask.clone(), zdr.clone()];

        // Empty input → no object emitted (steady state stays silent).
        assert!(session_additional_context_json(&[]).is_none());

        let obj = session_additional_context_json(&lines).expect("non-empty lines yield one object");

        // Serializing then re-parsing the WHOLE thing must succeed exactly as CC's parser does —
        // proving it is one valid JSON document, not concatenated objects.
        let serialized = obj.to_string();
        let reparsed: serde_json::Value =
            serde_json::from_str(serialized.trim()).expect("whole stdout must be ONE JSON document");
        let ctx = reparsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("additionalContext is a string");
        // Both lines survive, joined into the single block.
        assert!(ctx.contains(&mask), "mask-delta line must be present: {ctx}");
        assert!(ctx.contains(&zdr), "ZDR transition line must be present: {ctx}");
        assert_eq!(
            reparsed["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit",
            "must stay a UserPromptSubmit additionalContext emit"
        );

        // A lone ZDR line (no mask delta) also produces one well-formed object.
        let solo = session_additional_context_json(std::slice::from_ref(&zdr))
            .expect("one line yields one object");
        let solo_ctx = solo["hookSpecificOutput"]["additionalContext"].as_str().unwrap();
        assert_eq!(solo_ctx, zdr);
    }

    #[test]
    fn sanitize_component_matches_proxy_writer() {
        // Byte-identical to crates/sordino-proxy/src/state.rs `sanitize_component`. The proxy's
        // is private, so this pins the contract against representative inputs (keep [A-Za-z0-9._-],
        // others → `_`, empty/dot-only → `_`-prefixed).
        assert_eq!(sanitize_component("conv-123_OK.v2"), "conv-123_OK.v2");
        assert_eq!(sanitize_component("../../etc/foo"), ".._.._etc_foo");
        assert_eq!(sanitize_component("a b/c:d"), "a_b_c_d");
        assert_eq!(sanitize_component(""), "_");
        assert_eq!(sanitize_component("."), "_.");
        assert_eq!(sanitize_component(".."), "_..");
        assert_eq!(sanitize_component("uuid-AaZz09"), "uuid-AaZz09");

        // OVERLONG id (the ENAMETOOLONG vector): the sanitized component MUST be length-bounded
        // (<= SANITIZE_COMPONENT_MAX) so neither the proxy report write (`<comp>.json`) nor the
        // hooks marker write (`<comp>.global-seen`) can fail with ENAMETOOLONG, and BOTH sides must
        // derive the IDENTICAL name. The overlong input is already filename-safe here (all `a`s),
        // so the sanitized string equals the input → we can recompute the expected bounded form
        // exactly the way the (private) proxy writer does and pin both at byte-equality.
        let overlong = "a".repeat(5000);
        let got = sanitize_component(&overlong);
        assert!(
            got.len() <= SANITIZE_COMPONENT_MAX,
            "bounded component must fit: got {} > {}",
            got.len(),
            SANITIZE_COMPONENT_MAX
        );
        // Recompute the exact derivation the proxy writer uses (prefix + '-' + 16 hex of blake3 of
        // the FULL sanitized string). If the proxy ever diverges, this pin breaks.
        const HASH_HEX: usize = 16;
        const PREFIX: usize = SANITIZE_COMPONENT_MAX - HASH_HEX - 1;
        let mut h = blake3::Hasher::new();
        h.update(overlong.as_bytes());
        let expected = format!("{}-{}", &overlong[..PREFIX], &h.finalize().to_hex()[..HASH_HEX]);
        assert_eq!(got, expected, "overlong derivation must match the proxy writer byte-for-byte");

        // Distinct overlong ids stay distinct (the hash of the full sanitized string differentiates
        // them even though their prefixes collide).
        let other = format!("{}b", "a".repeat(4999));
        assert_ne!(
            sanitize_component(&overlong),
            sanitize_component(&other),
            "distinct long ids must not collide after bounding"
        );
    }

    #[test]
    fn report_filename_is_length_bounded() {
        // The full report/marker FILENAME (component + extension) must stay under the 255-byte
        // limit common to ext4/APFS/NTFS for ANY conversation id, including a pathological one.
        let overlong = "z/".repeat(4000); // 8000 chars, all non-safe → all `_` after sanitize
        let comp = sanitize_component(&overlong);
        assert!(comp.len() <= SANITIZE_COMPONENT_MAX);
        // The longest extension the readers/writers use is `.global-seen` (12 bytes).
        assert!(
            format!("{comp}.global-seen").len() <= 255,
            "report/marker filename must fit on every target FS"
        );
        assert!(format!("{comp}.json").len() <= 255);
    }

    #[test]
    fn first_cwd_in_jsonl_extracts_exact_path_or_none() {
        let dir = std::env::temp_dir().join(format!("sordino-cwd-{}", std::process::id()));
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

    // ---- F3: verify category-coverage disclosure leg ----

    #[test]
    fn category_coverage_detail_names_off_categories() {
        // (a) Balanced default: Network + Personal are OFF → detail names BOTH, each with
        // its honest pass-through sentence.
        let balanced: Vec<String> = ["secrets", "financial", "identity", "contact"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let d = category_coverage_detail(&balanced);
        assert!(d.contains("network"), "must name network OFF: {d}");
        assert!(d.contains("personal"), "must name personal OFF: {d}");
        assert!(
            d.contains("bare URLs/IPs/MACs sent in clear"),
            "network sentence: {d}"
        );
        assert!(
            d.contains("names/locations need the ML model"),
            "personal sentence: {d}"
        );
        assert_ne!(d, "all categories on");

        // (b) all six categories on → the succinct 'all categories on'.
        let all: Vec<String> =
            ["secrets", "financial", "identity", "contact", "network", "personal"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(category_coverage_detail(&all), "all categories on");
    }

    #[test]
    fn verify_category_coverage_is_always_info() {
        // (c) At a temp dir with no live proxy and no TOML, the leg is still report-only
        // Info — it never participates in any_fail.
        let dir = std::env::temp_dir().join(format!("sordino-cov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = canonical(&dir);
        assert_eq!(verify_category_coverage(&root).status, ProbeStatus::Info);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- F11: doctor transcript-exposure disclosure leg ----

    #[test]
    fn transcript_exposure_detail_counts_and_sums_via_metadata_only() {
        let dir = std::env::temp_dir().join(format!("sordino-tx-detail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Empty dir → absent; a non-existent dir → absent.
        assert_eq!(transcript_exposure_detail(&dir), (false, 0, 0));
        assert_eq!(
            transcript_exposure_detail(&dir.join("does-not-exist")),
            (false, 0, 0)
        );

        // Two *.jsonl transcripts (5 + 3 bytes) plus a non-jsonl decoy: counts and sums
        // ONLY the jsonl files, via metadata (content is never opened).
        std::fs::write(dir.join("a.jsonl"), "12345").unwrap();
        std::fs::write(dir.join("b.jsonl"), "678").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        assert_eq!(transcript_exposure_detail(&dir), (true, 2, 8));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_transcript_exposure_is_info_present_and_absent() {
        let base = std::env::temp_dir().join(format!("sordino-tx-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = base.join("cfg");
        let projects = cfg.join("projects").join("encoded-root");
        std::fs::create_dir_all(&projects).unwrap();

        // A real project dir; key the transcript match on its canonical path.
        let proj = base.join("myproject");
        std::fs::create_dir_all(&proj).unwrap();
        let root = canonical(&proj);

        // A session log carrying that cwd + a fake transcript to size.
        std::fs::write(
            projects.join("session.jsonl"),
            format!("{{\"type\":\"user\",\"cwd\":\"{root}\"}}\n"),
        )
        .unwrap();
        std::fs::write(projects.join("t1.jsonl"), "hello").unwrap();

        let prev = std::env::var_os("CLAUDE_CONFIG_DIR");
        // SAFETY (edition 2024): the probe under test reads CLAUDE_CONFIG_DIR; no other
        // thread in this test relies on it, and it is restored below.
        unsafe {
            std::env::set_var("CLAUDE_CONFIG_DIR", &cfg);
        }

        // Present: matching project dir with jsonl files → report-only Info.
        assert_eq!(
            probe_transcript_exposure(&root).status,
            ProbeStatus::Info
        );

        // Absent: a root with no matching session dir → still Info (quiet 'none found').
        let other = canonical(&base.join("no-such-project"));
        assert_eq!(
            probe_transcript_exposure(&other).status,
            ProbeStatus::Info
        );

        match prev {
            Some(v) => unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", v) },
            None => unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") },
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn probe_transcript_exposure_survives_leading_cwdless_log() {
        // Regression: a cwd-less leading log (e.g. summary-only jsonl) in the matching
        // project dir must NOT short-circuit discovery into a false 'no transcripts found'.
        // The narrowing walk breaks only on a log that yields a `cwd` (mismatch = other
        // project); a `None` continues to the next file, mirroring discover_session_cwds.
        let base = std::env::temp_dir().join(format!("sordino-tx-lead-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = base.join("cfg");
        let projects = cfg.join("projects").join("encoded-root");
        std::fs::create_dir_all(&projects).unwrap();

        let proj = base.join("myproject");
        std::fs::create_dir_all(&proj).unwrap();
        let root = canonical(&proj);

        // Force a cwd-less log to sort BEFORE the one carrying the cwd (aaa_ vs zzz_).
        std::fs::write(
            projects.join("aaa_summary.jsonl"),
            "{\"type\":\"summary\",\"summary\":\"no cwd here\"}\n",
        )
        .unwrap();
        std::fs::write(
            projects.join("zzz_session.jsonl"),
            format!("{{\"type\":\"user\",\"cwd\":\"{root}\"}}\n"),
        )
        .unwrap();

        let prev = std::env::var_os("CLAUDE_CONFIG_DIR");
        // SAFETY (edition 2024): the probe under test reads CLAUDE_CONFIG_DIR; no other
        // thread in this test relies on it, and it is restored below.
        unsafe {
            std::env::set_var("CLAUDE_CONFIG_DIR", &cfg);
        }

        let p = probe_transcript_exposure(&root);
        assert_eq!(p.status, ProbeStatus::Info);
        // The dir WAS discovered despite the leading cwd-less log — not the quiet 'none'.
        assert!(
            !p.detail.contains("no transcripts found"),
            "leading cwd-less log wrongly skipped the matching project dir: {}",
            p.detail
        );

        match prev {
            Some(v) => unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", v) },
            None => unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") },
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn any_fail_predicates_stay_fail_only() {
        // Guardrail: both doctor's and verify's any_fail predicate must remain
        // Fail-only — an Info leg NEVER flips ok/exit. The needle is assembled from
        // two fragments so THIS test's own source contains no verbatim occurrence;
        // the count therefore reflects ONLY the two production sites (asserting a bare
        // n>=2 against the whole file is vacuous — the literal would appear here twice).
        let src = include_str!("main.rs");
        let needle = concat!(".any(|p| p.status == ProbeStatus::", "Fail)");
        let n = src.matches(needle).count();
        assert_eq!(
            n, 2,
            "exactly the doctor and verify any_fail predicates must stay Fail-only; \
             found {n} occurrence(s)"
        );
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

    // L10 / A3: OTel content-flag warning. Pure — a HashMap-backed lookup closure, no real env
    // mutation and no test serialization required.
    fn otel_lookup(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn otel_warn_empty_env_is_silent() {
        // Clean session: no false-positive nag.
        assert_eq!(otel_content_flag_warning(otel_lookup(&[])), None);
    }

    #[test]
    fn otel_warn_master_gate_only_is_silent() {
        // Telemetry master gate on but no content flag => nothing exports content => silent.
        assert_eq!(
            otel_content_flag_warning(otel_lookup(&[("CLAUDE_CODE_ENABLE_TELEMETRY", "1")])),
            None
        );
    }

    #[test]
    fn otel_warn_tool_details_flags() {
        let w = otel_content_flag_warning(otel_lookup(&[
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "true"),
            ("OTEL_LOG_TOOL_DETAILS", "yes"),
        ]))
        .expect("content flag with master gate on must warn");
        assert!(w.contains("OTEL_LOG_TOOL_DETAILS"), "warning names the flag: {w}");
    }

    #[test]
    fn otel_warn_raw_api_bodies_file_mode() {
        // `file:` prefix enables raw-body-to-disk even though it isn't boolean-truthy.
        let w = otel_content_flag_warning(otel_lookup(&[
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "on"),
            ("OTEL_LOG_RAW_API_BODIES", "file:/tmp/otel"),
        ]))
        .expect("file: raw-body mode must warn");
        assert!(w.contains("OTEL_LOG_RAW_API_BODIES"), "warning names the flag: {w}");
    }

    #[test]
    fn otel_warn_master_gate_off_is_inert() {
        // Master gate off => no exporter constructed => an inert leftover content flag stays silent.
        assert_eq!(
            otel_content_flag_warning(otel_lookup(&[
                ("CLAUDE_CODE_ENABLE_TELEMETRY", "0"),
                ("OTEL_LOG_USER_PROMPTS", "1"),
            ])),
            None
        );
    }

    #[test]
    fn otel_warn_mixed_case_reuses_truthy_parse() {
        // Mixed-case values must parse via is_truthy_flag (case-insensitive, trimmed).
        let w = otel_content_flag_warning(otel_lookup(&[
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "TRUE"),
            ("OTEL_LOG_USER_PROMPTS", "On"),
        ]))
        .expect("mixed-case truthy content flag must warn");
        assert!(w.contains("OTEL_LOG_USER_PROMPTS"), "warning names the flag: {w}");
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
        "Sordino: WARNING — proxy on :{port} (pid {pid}) did not exit; the new one may fail to bind."
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

        // A sidecar that somehow points back at a sordino status line is ignored so the
        // wrapper can never recurse into itself.
        std::fs::write(
            &path,
            r#"{"type":"command","command":"/x/sordino-hooks statusline"}"#,
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
    use super::{base_url_matches, conversation_from_url};

    #[test]
    fn conversation_id_extracted_from_session_base_url() {
        assert_eq!(
            conversation_from_url("http://127.0.0.1:8787/sordino/session/abc123"),
            Some("abc123".to_string())
        );
        // Trailing path segments after the id are ignored.
        assert_eq!(
            conversation_from_url("http://127.0.0.1:8787/sordino/session/abc123/v1/messages"),
            Some("abc123".to_string())
        );
        // A non-session (plain) base URL has no conversation id.
        assert_eq!(conversation_from_url("http://127.0.0.1:8787"), None);
        assert_eq!(conversation_from_url("https://api.anthropic.com"), None);
        // An empty id segment is not a valid conversation.
        assert_eq!(conversation_from_url("http://x/sordino/session/"), None);
        // The marker in a query/fragment is NOT the path — must not mis-key.
        assert_eq!(
            conversation_from_url("https://api.anthropic.com/?redirect=/sordino/session/evil"),
            None
        );
        // A real path id with a trailing query is still extracted.
        assert_eq!(
            conversation_from_url("http://x/sordino/session/abc?foo=bar"),
            Some("abc".to_string())
        );
        // Same for a fragment: marker in a fragment is not the path; a trailing
        // fragment after a real id is stripped.
        assert_eq!(
            conversation_from_url("https://api.anthropic.com/#/sordino/session/evil"),
            None
        );
        assert_eq!(
            conversation_from_url("http://x/sordino/session/abc#frag"),
            Some("abc".to_string())
        );
    }

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
            probe_project_proxy("/no/such/sordino/project/xyz").status,
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

    // ---- dual-instance / chained-masker (pure decision) ----

    fn ours(port: u16) -> MaskerObservation {
        MaskerObservation { port, is_sordino: true, is_this_project: true }
    }
    fn foreign(port: u16) -> MaskerObservation {
        MaskerObservation { port, is_sordino: true, is_this_project: false }
    }

    // Shorthand: the no-warn route (unset / real provider / own plane) for signal-a/b tests.
    const OWN: RoutedEndpoint = RoutedEndpoint::OwnOrDirect;

    #[test]
    fn dual_instance_single_normal_setup_is_quiet() {
        // (a) A lone, this-project instance forwarding to the real provider, routed to its own
        // plane → NO warning (the false-positive guard). Empty observations are quiet too.
        assert!(dual_instance_decision(&[ours(40000)], "https://api.anthropic.com", OWN).is_none());
        assert!(dual_instance_decision(&[], "https://api.anthropic.com", OWN).is_none());
        // A non-sordino responder observed on loopback (some other app) must NOT trip it.
        let other_app = MaskerObservation { port: 8080, is_sordino: false, is_this_project: false };
        assert!(dual_instance_decision(&[ours(40000), other_app], "https://api.anthropic.com", OWN).is_none());
    }

    #[test]
    fn dual_instance_second_sordino_warns_foreign_vault() {
        // (b) Two DISTINCT sordino control planes → warn about the separate-vault risk.
        let msg = dual_instance_decision(&[ours(40000), foreign(40001)], "https://api.anthropic.com", OWN)
            .expect("a second sordino instance must warn");
        assert!(msg.contains("SEPARATE vault"), "names the dual-vault risk: {msg}");
        assert!(msg.contains("FOREIGN"), "names the foreign-token footgun: {msg}");
        // Two foreign instances phrase the count in the plural.
        let msg2 = dual_instance_decision(
            &[ours(40000), foreign(40001), foreign(40002)],
            "https://api.anthropic.com",
            OWN,
        )
        .expect("warn");
        assert!(msg2.contains("2 other"), "counts foreign instances: {msg2}");
    }

    #[test]
    fn dual_instance_chained_upstream_warns() {
        // (c) Upstream target is itself a loopback masker → chained-masker warning, even with a
        // single observed instance (the "upstream shim" shape from the incident).
        for up in ["http://127.0.0.1:8080", "http://127.0.0.1:9000/v1", "http://localhost:41234"] {
            let msg = dual_instance_decision(&[ours(40000)], up, OWN)
                .unwrap_or_else(|| panic!("chained upstream {up} must warn"));
            assert!(msg.contains("CHAINED"), "names the chained masker for {up}: {msg}");
        }
        // Both signals at once → one message carrying both clauses.
        let both = dual_instance_decision(&[ours(1), foreign(2)], "http://127.0.0.1:8080", OWN)
            .expect("warn");
        assert!(both.contains("SEPARATE vault") && both.contains("CHAINED"), "{both}");
    }

    #[test]
    fn dual_instance_foreign_route_warns() {
        // (F2a) $ANTHROPIC_BASE_URL routes to a foreign Sordino identity → foreign-instance-route
        // WARN, even with a lone own instance and a real-provider upstream (signals a/b quiet).
        let msg = dual_instance_decision(
            &[ours(40000)],
            "https://api.anthropic.com",
            RoutedEndpoint::ForeignInstance,
        )
        .expect("a foreign-instance route must warn");
        assert!(msg.contains("FOREIGN-INSTANCE"), "names the foreign-route risk: {msg}");
        assert!(msg.contains("$ANTHROPIC_BASE_URL"), "names the route source: {msg}");
        // All three signals at once → one message carrying all three clauses.
        let all = dual_instance_decision(
            &[ours(1), foreign(2)],
            "http://127.0.0.1:8080",
            RoutedEndpoint::ForeignInstance,
        )
        .expect("warn");
        assert!(
            all.contains("FOREIGN-INSTANCE") && all.contains("SEPARATE vault") && all.contains("CHAINED"),
            "{all}"
        );
    }

    #[test]
    fn dual_instance_own_route_is_quiet() {
        // (F2b) route unset / api.anthropic.com / this project's OWN plane all map to OwnOrDirect →
        // no foreign-route warning on an otherwise-clean single instance.
        assert!(
            dual_instance_decision(&[ours(40000)], "https://api.anthropic.com", RoutedEndpoint::OwnOrDirect)
                .is_none()
        );
    }

    #[test]
    fn upstream_is_loopback_classifies_hosts() {
        // Loopback in every realistic shape.
        for u in [
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/v1",
            "https://localhost",
            "http://localhost:9000/",
            "http://user@127.0.0.1:8080",
            "http://127.9.9.9:1234",
            "http://[::1]:8080/v1",
        ] {
            assert!(upstream_is_loopback(u), "should be loopback: {u}");
        }
        // The real provider and other public hosts are NOT loopback.
        for u in [
            "https://api.anthropic.com",
            "https://bedrock-runtime.us-east-1.amazonaws.com",
            "http://10.0.0.5:8080",
            "http://127.example.com:8080",
        ] {
            assert!(!upstream_is_loopback(u), "should NOT be loopback: {u}");
        }
    }

    #[test]
    fn resolve_upstream_mirrors_proxy_layer_precedence() {
        // PURE (no env/fs): layers are passed highest-precedence-first (local, project, user).
        let api = "[proxy]\nupstream_base_url = \"https://api.anthropic.com\"\n";
        let local = "[proxy]\nupstream_base_url = \"http://127.0.0.1:9999\"\n";
        let project = "[proxy]\nupstream_base_url = \"http://127.0.0.1:8080\"\n";
        let user = "[proxy]\nupstream_base_url = \"http://127.0.0.1:7070\"\n";

        // No layers set it → the real-provider default.
        assert_eq!(resolve_upstream(None, &[None, None, None]), "https://api.anthropic.com");

        // (F1a) A USER-layer loopback upstream, with NO project/local override, is now resolved
        // (previously missed) — this is the exact upstream-shim incident shape that must warn.
        assert_eq!(
            resolve_upstream(None, &[None, None, Some(user)]),
            "http://127.0.0.1:7070"
        );
        assert!(
            upstream_is_loopback(&resolve_upstream(None, &[None, None, Some(user)])),
            "a user-layer loopback upstream must be seen as a chained masker"
        );

        // (F1b) The real provider at EVERY layer → PASS material (not loopback), no false warning.
        assert_eq!(
            resolve_upstream(None, &[Some(api), Some(api), Some(api)]),
            "https://api.anthropic.com"
        );
        assert!(!upstream_is_loopback(&resolve_upstream(None, &[Some(api), Some(api), Some(api)])));

        // Precedence: local > project > user (mirrors config.rs merged_value; local wins).
        assert_eq!(
            resolve_upstream(None, &[Some(local), Some(project), Some(user)]),
            "http://127.0.0.1:9999"
        );
        assert_eq!(
            resolve_upstream(None, &[None, Some(project), Some(user)]),
            "http://127.0.0.1:8080"
        );
        // The $SORDINO_UPSTREAM launch override wins over every file layer.
        assert_eq!(
            resolve_upstream(Some("https://gw.corp.example/v1"), &[Some(local), Some(project), Some(user)]),
            "https://gw.corp.example/v1"
        );
        // An empty/whitespace override is ignored (falls through to the file layers).
        assert_eq!(
            resolve_upstream(Some("  "), &[Some(project), None, None]),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn configured_upstream_reads_all_layers_from_disk() {
        // The $SORDINO_UPSTREAM override wins by design; skip the file-precedence assertion when
        // it happens to be set in this environment.
        if std::env::var_os("SORDINO_UPSTREAM").is_some() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("sordino-upstream-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = canonical(&dir);
        // Isolate the USER layer to a controlled, non-existent path so the default assertion is
        // hermetic (configured_upstream now reads the user layer, matching the proxy). Restored
        // below. SAFETY (edition 2024): the fn under test reads SORDINO_USER_CONFIG; no other
        // thread in this test relies on it.
        let user_cfg = dir.join("user-config.toml");
        let prev_user = std::env::var_os("SORDINO_USER_CONFIG");
        unsafe { std::env::set_var("SORDINO_USER_CONFIG", &user_cfg); }

        // No config at any layer → the real-provider default.
        assert_eq!(configured_upstream(&root), "https://api.anthropic.com");
        // (F1) A loopback upstream in the USER layer alone is now resolved (the missed-layer bug).
        std::fs::write(&user_cfg, "[proxy]\nupstream_base_url = \"http://127.0.0.1:7070\"\n").unwrap();
        assert_eq!(configured_upstream(&root), "http://127.0.0.1:7070");
        // A loopback upstream in sordino.toml (project) overrides the user layer.
        std::fs::write(
            dir.join("sordino.toml"),
            "[proxy]\nupstream_base_url = \"http://127.0.0.1:8080\"\n",
        )
        .unwrap();
        assert_eq!(configured_upstream(&root), "http://127.0.0.1:8080");
        // sordino.local.toml overrides the project file.
        std::fs::write(
            dir.join("sordino.local.toml"),
            "[proxy]\nupstream_base_url = \"http://127.0.0.1:9999\"\n",
        )
        .unwrap();
        assert_eq!(configured_upstream(&root), "http://127.0.0.1:9999");

        match prev_user {
            Some(v) => unsafe { std::env::set_var("SORDINO_USER_CONFIG", v) },
            None => unsafe { std::env::remove_var("SORDINO_USER_CONFIG") },
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod codex_auth_check_tests {
    use super::{CodexAuthMode, classify_codex_auth, unmapped_auth_mode};
    use serde_json::json;

    // Convenience: assert the PURE classifier returns the expected (mode-string, route_ok).
    fn check(env: Option<&str>, auth: Option<serde_json::Value>, mode: CodexAuthMode, ok: bool) {
        let (m, r) = classify_codex_auth(env, auth.as_ref());
        assert_eq!(m, mode, "mode mismatch for env={env:?} auth={auth:?}");
        assert_eq!(r, ok, "route_ok mismatch for env={env:?} auth={auth:?}");
        // route_ok must equal mode.route_ok() and "apikey" must be the only true case.
        assert_eq!(r, m.route_ok());
        assert_eq!(r, m.as_str() == "apikey");
    }

    #[test]
    fn exported_sk_key_is_apikey_route_ok() {
        // Rule 1: an exported, sk-shaped env key passes regardless of auth.json.
        check(Some("sk-real"), None, CodexAuthMode::ApiKey, true);
        check(
            Some("sk-real"),
            Some(json!({ "tokens": { "id_token": "x" } })),
            CodexAuthMode::ApiKey,
            true,
        );
    }

    #[test]
    fn chatgpt_tokens_without_env_refuses() {
        check(
            None,
            Some(json!({ "tokens": { "id_token": "x", "access_token": "y" } })),
            CodexAuthMode::Chatgpt,
            false,
        );
        // auth_mode=="chatgpt" with no tokens object classifies the same.
        check(
            None,
            Some(json!({ "auth_mode": "chatgpt" })),
            CodexAuthMode::Chatgpt,
            false,
        );
    }

    #[test]
    fn api_key_on_file_but_not_exported_refuses() {
        // The actionable case: key in auth.json, nothing exported → key-not-exported.
        check(
            None,
            Some(json!({ "OPENAI_API_KEY": "sk-x" })),
            CodexAuthMode::KeyNotExported,
            false,
        );
        // auth_mode=="apikey" alone (no field) is also key-not-exported.
        check(
            None,
            Some(json!({ "auth_mode": "apikey" })),
            CodexAuthMode::KeyNotExported,
            false,
        );
    }

    #[test]
    fn personal_access_token_is_other() {
        check(
            None,
            Some(json!({ "auth_mode": "personal_access_token", "personal_access_token": "pat-x" })),
            CodexAuthMode::Other,
            false,
        );
        // A bare personal_access_token field (unrecognized/absent auth_mode) also classifies.
        check(
            None,
            Some(json!({ "personal_access_token": "pat-x" })),
            CodexAuthMode::Other,
            false,
        );
    }

    #[test]
    fn bedrock_is_other() {
        check(
            None,
            Some(json!({ "auth_mode": "bedrock_api_key" })),
            CodexAuthMode::Other,
            false,
        );
        check(
            None,
            Some(json!({ "bedrock_api_key": { "key": "abc" } })),
            CodexAuthMode::Other,
            false,
        );
    }

    #[test]
    fn unrecognized_auth_mode_fails_closed_to_other() {
        check(
            None,
            Some(json!({ "auth_mode": "some_future_mode" })),
            CodexAuthMode::Other,
            false,
        );
        // ...and it is surfaced as an unmapped auth_mode for reporting.
        let auth = json!({ "auth_mode": "some_future_mode" });
        assert_eq!(unmapped_auth_mode(Some(&auth)).as_deref(), Some("some_future_mode"));
    }

    #[test]
    fn env_present_but_empty_or_whitespace_falls_through() {
        // Empty / whitespace-only env is NOT apikey — it falls through to auth.json.
        check(Some(""), None, CodexAuthMode::Chatgpt, false);
        check(Some("   "), None, CodexAuthMode::Chatgpt, false);
        // Non-sk-shaped env (e.g. a leaked ChatGPT token) is also not apikey.
        check(Some("not-an-sk-key"), None, CodexAuthMode::Chatgpt, false);
        // And an empty env still lets auth.json drive the (still-refusing) classification.
        check(
            Some(""),
            Some(json!({ "OPENAI_API_KEY": "sk-x" })),
            CodexAuthMode::KeyNotExported,
            false,
        );
    }

    #[test]
    fn no_auth_json_at_all_refuses_as_chatgpt() {
        check(None, None, CodexAuthMode::Chatgpt, false);
    }

    #[test]
    fn known_auth_mode_is_not_flagged_unmapped() {
        for am in ["apikey", "chatgpt", "personal_access_token", "bedrock_api_key"] {
            let auth = json!({ "auth_mode": am });
            assert_eq!(unmapped_auth_mode(Some(&auth)), None, "{am} should be known");
        }
        // No auth.json and no auth_mode → nothing to flag.
        assert_eq!(unmapped_auth_mode(None), None);
        assert_eq!(unmapped_auth_mode(Some(&json!({}))), None);
        // An unknown auth_mode that nevertheless carries a recognized field is classified by
        // that field, not "unmapped".
        let auth = json!({ "auth_mode": "weird", "tokens": { "id_token": "x" } });
        assert_eq!(unmapped_auth_mode(Some(&auth)), None);
    }
}

// ---------------------------------------------------------------------------
// intake funnel (F2 scan + F4 import) — acceptance tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod intake_tests {
    use super::*;
    use sordino_secrets::SecretProvider as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh, unique temp dir per test (process id is shared across a run, so add a
    /// monotonic counter + nanos). Created empty.
    fn scratch_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sordino-intake-{tag}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -----------------------------------------------------------------------
    // PRECISION CORPUS — the MEASURED offer-list gate (recall 1.0, precision >= 0.70)
    // -----------------------------------------------------------------------

    /// (filename, [(KEY, VALUE, is_secret)]). A FROZEN >=8-file corpus, secret:nonsecret
    /// = 1:1, with the two mandatory shape-collision secrets (GITHUB_TOKEN / SLACK_WEBHOOK
    /// URL) and the adversarial non-secret rows (UUID / 40-hex gitsha / public URL /
    /// NODE_ENV / semver / boolean / integer / enum).
    const CORPUS: &[(&str, &[(&str, &str, bool)])] = &[
        (
            "app1.env",
            &[
                // collision (1): 40 lowercase hex, byte-identical to the git-SHA suppressor,
                // rescued by NameMatch (name hits TOKEN).
                (
                    "GITHUB_TOKEN",
                    "5f3e2a1b9c8d7e6f0a1b2c3d4e5f60718293a4b5",
                    true,
                ),
                // SAME shape under a non-matching name ⇒ suppressed (the precision win).
                ("gitsha", "5f3e2a1b9c8d7e6f0a1b2c3d4e5f60718293a4b5", false),
            ],
        ),
        (
            "app2.env",
            &[
                // collision (2): a bare https:// (no userinfo), rescued ONLY by the branded
                // hooks.slack.com prefix.
                (
                    "SLACK_WEBHOOK_URL",
                    "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                    true,
                ),
                // A public no-userinfo URL under a non-matching name ⇒ suppressed.
                ("PUBLIC_URL", "https://example.com/path/to/resource", false),
            ],
        ),
        (
            "app3.env",
            &[
                ("DATABASE_URL", "postgres://user:pass@db.internal:5432/app", true),
                ("NODE_ENV", "production", false),
            ],
        ),
        (
            "app4.env",
            &[
                (
                    "AWS_SECRET_ACCESS_KEY",
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    true,
                ),
                ("PORT", "8080", false),
            ],
        ),
        (
            "app5.env",
            &[
                ("STRIPE_SECRET_KEY", "sk_live_51H8xY2eZvKYlo2C0abcdefghij", true),
                ("LOG_LEVEL", "debug", false),
            ],
        ),
        (
            "app6.env",
            &[
                (
                    "OPENAI_API_KEY",
                    "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                    true,
                ),
                ("FEATURE_ENABLED", "true", false),
            ],
        ),
        (
            "app7.env",
            &[
                ("MYSQL_DSN", "mysql://root:hunter2@127.0.0.1:3306/db", true),
                ("REQUEST_ID", "550e8400-e29b-41d4-a716-446655440000", false),
            ],
        ),
        (
            "app8.env",
            &[
                ("API_TOKEN", "k7Lm2Nq9Rp4StUvWxYz0aBcD1eF", true),
                ("APP_VERSION", "1.2.3-alpha.1+build.42", false),
            ],
        ),
    ];

    /// Materialize the corpus as `.env` files + `.labels` sidecars in a frozen dir.
    fn write_corpus(dir: &Path) {
        for (file, rows) in CORPUS {
            let mut env = String::new();
            let mut labels = String::new();
            for (k, v, secret) in *rows {
                env.push_str(&format!("{k}={v}\n"));
                labels.push_str(&format!("{k}={}\n", if *secret { "secret" } else { "nonsecret" }));
            }
            std::fs::write(dir.join(file), env).unwrap();
            let labels_name = file.replace(".env", ".labels");
            std::fs::write(dir.join(labels_name), labels).unwrap();
        }
    }

    #[test]
    fn precision_corpus_gate() {
        let dir = scratch_dir("corpus");
        write_corpus(&dir);

        let mut tp = 0usize; // secret, offered
        let mut fp = 0usize; // nonsecret, offered
        let mut fn_ = 0usize; // secret, missed
        let mut offered: std::collections::HashMap<String, bool> = Default::default();

        for (file, _) in CORPUS {
            // Read the sidecar labels (KEY=secret|nonsecret).
            let labels_path = dir.join(file.replace(".env", ".labels"));
            let labels_text = std::fs::read_to_string(&labels_path).unwrap();
            let labels: std::collections::HashMap<&str, bool> = labels_text
                .lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k, v == "secret"))
                .collect();

            // Parse the .env via the SAME path scan/import use, then run the shared predicate.
            for item in dotenvy::from_path_iter(dir.join(file)).unwrap() {
                let (key, value) = item.unwrap();
                let is_secret = *labels.get(key.as_str()).unwrap_or_else(|| {
                    panic!("no label for {key} in {file}")
                });
                let cand = is_candidate(&key, &value);
                offered.insert(key.clone(), cand);
                match (is_secret, cand) {
                    (true, true) => tp += 1,
                    (true, false) => fn_ += 1,
                    (false, true) => fp += 1,
                    (false, false) => {}
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);

        let recall = tp as f64 / (tp + fn_) as f64;
        let precision = tp as f64 / (tp + fp) as f64;

        // recall == 1.0 on labeled secrets (incl BOTH collisions).
        assert_eq!(fn_, 0, "recall regression: {fn_} labeled secret(s) missed; offered map = {offered:?}");
        assert_eq!(recall, 1.0, "recall must be 1.0");
        // The two mandatory collision rows survive.
        assert!(offered["GITHUB_TOKEN"], "GITHUB_TOKEN (NameMatch collision) must be offered");
        assert!(offered["SLACK_WEBHOOK_URL"], "SLACK_WEBHOOK_URL (branded-prefix collision) must be offered");
        // precision >= 0.70 over the frozen corpus.
        assert!(precision >= 0.70, "precision {precision} < 0.70 (fp={fp})");
        // Each named adversarial non-secret must NOT be offered.
        for k in ["REQUEST_ID", "gitsha", "PUBLIC_URL", "NODE_ENV", "APP_VERSION"] {
            assert!(!offered[k], "{k} must NOT be offered (precision leak)");
        }
    }

    /// The reason-gate directly: the SAME 40-hex value is a candidate under a name that
    /// matches (TOKEN ⇒ NameMatch/Both) but suppressed under one that does not (Entropy).
    #[test]
    fn reason_gate_rescues_named_shape_collision() {
        let sha = "5f3e2a1b9c8d7e6f0a1b2c3d4e5f60718293a4b5";
        assert!(is_candidate("GITHUB_TOKEN", sha), "named 40-hex is a secret");
        assert!(!is_candidate("gitsha", sha), "anonymous 40-hex is a git SHA (suppressed)");
        // A high-entropy UUID (above the entropy floor) is still suppressed via structure.
        let uuid = "0a1b2c3d-4e5f-6789-abcd-ef0123456789";
        assert!(!is_candidate("TRACE_ID", uuid), "anonymous UUID suppressed via structure");
        // The webhook prefix is the ONLY rescue for a bare-https SLACK_WEBHOOK_URL.
        assert!(is_candidate(
            "SLACK_WEBHOOK_URL",
            "https://hooks.slack.com/services/T0/B0/XXXX"
        ));
    }

    // -----------------------------------------------------------------------
    // Scan falsifiers
    // -----------------------------------------------------------------------

    #[test]
    fn scan_lists_only_candidates_never_config_keys() {
        let dir = scratch_dir("scan-a");
        std::fs::write(
            dir.join(".env"),
            "OPENAI_KEY=sk-abcDEF123456ghiJKL\nNODE_ENV=production\nPORT=8080\n",
        )
        .unwrap();
        let files = enumerate_env_files(dir.to_str().unwrap());
        let report = scan_report(dir.to_str().unwrap(), &files, &HashSet::new(), false);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(report.contains("OPENAI_KEY"), "sk- key must be listed:\n{report}");
        assert!(!report.contains("NODE_ENV"), "NODE_ENV must not appear:\n{report}");
        assert!(!report.contains("PORT"), "PORT must not appear:\n{report}");
    }

    #[test]
    fn scan_never_prints_a_value() {
        let dir = scratch_dir("scan-b");
        std::fs::write(dir.join(".env"), "SECRET=sk-live_deadbeefcafef00dbabe1234\n").unwrap();
        let files = enumerate_env_files(dir.to_str().unwrap());
        let report = scan_report(dir.to_str().unwrap(), &files, &HashSet::new(), true);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(report.contains("SECRET"), "KEY name must appear:\n{report}");
        assert!(
            !report.contains("sk-live_deadbeef"),
            "the value must NEVER appear:\n{report}"
        );
    }

    #[test]
    fn scan_proxy_down_still_lists_with_caveat() {
        let dir = scratch_dir("scan-c");
        std::fs::write(dir.join(".env"), "APIKEY=sk-abcDEF123456ghiJKL\n").unwrap();
        let files = enumerate_env_files(dir.to_str().unwrap());
        // proxy_up = false ⇒ registered set empty + caveat printed.
        let report = scan_report(dir.to_str().unwrap(), &files, &HashSet::new(), false);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(report.contains("APIKEY"), "candidate listed:\n{report}");
        assert!(report.contains("best-effort"), "proxy-down caveat present:\n{report}");
    }

    #[test]
    fn scan_skips_example_and_sample_sidecars() {
        let dir = scratch_dir("scan-d");
        std::fs::write(dir.join(".env.example"), "APIKEY=sk-abcDEF123456ghiJKL\n").unwrap();
        std::fs::write(dir.join(".env.sample"), "APIKEY=sk-abcDEF123456ghiJKL\n").unwrap();
        std::fs::write(dir.join(".env.prod.example"), "APIKEY=sk-abcDEF123456ghiJKL\n").unwrap();
        let files = enumerate_env_files(dir.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(files.is_empty(), "example/sample sidecars must be skipped: {files:?}");
    }

    #[test]
    fn is_intake_env_file_matrix() {
        assert!(is_intake_env_file(".env"));
        assert!(is_intake_env_file(".env.local"));
        assert!(is_intake_env_file(".env.production"));
        assert!(!is_intake_env_file(".env.example"));
        assert!(!is_intake_env_file(".env.sample"));
        assert!(!is_intake_env_file(".env.prod.example"));
        assert!(!is_intake_env_file("env")); // no leading dot
        assert!(!is_intake_env_file("config.toml"));
    }

    #[test]
    fn resolve_import_files_respects_intake_boundary() {
        // Layout: <parent>/project/.env         (real intake file)
        //         <parent>/project/.env.example (placeholder sidecar)
        //         <parent>/.env                 (OUTSIDE the project, reachable via `..`)
        let parent = scratch_dir("resolve-boundary");
        let project = parent.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join(".env"), "API=sk-abcDEF123456ghiJKL\n").unwrap();
        std::fs::write(project.join(".env.example"), "API=placeholder\n").unwrap();
        std::fs::write(parent.join(".env"), "OUTSIDE=sk-abcDEF123456ghiJKL\n").unwrap();
        let root = project.to_str().unwrap();

        // Some(.env): a real intake file inside root ⇒ Ok, single NON-canonical resolved path.
        let ok = resolve_import_files(root, Some(PathBuf::from(".env")));
        assert!(ok.is_ok(), "real .env inside root must resolve: {ok:?}");
        assert_eq!(ok.unwrap(), vec![project.join(".env")]);

        // Some(.env.example): placeholder sidecar excluded by is_intake_env_file ⇒ Err.
        assert!(
            resolve_import_files(root, Some(PathBuf::from(".env.example"))).is_err(),
            "placeholder .env.example sidecar must be rejected"
        );

        // Some(../.env): intake-named but OUTSIDE the project (containment) ⇒ Err.
        assert!(
            resolve_import_files(root, Some(PathBuf::from("../.env"))).is_err(),
            "an intake-named file outside the project root must be rejected"
        );

        // None: discovery set INCLUDES .env and EXCLUDES the .env.example sidecar.
        let all = resolve_import_files(root, None).unwrap();
        assert!(all.contains(&project.join(".env")), "discovery includes .env: {all:?}");
        assert!(
            !all
                .iter()
                .any(|p| p.file_name().and_then(|n| n.to_str()) == Some(".env.example")),
            "discovery excludes .env.example: {all:?}"
        );

        let _ = std::fs::remove_dir_all(&parent);
    }

    // -----------------------------------------------------------------------
    // import_merge falsifiers (text -> text)
    // -----------------------------------------------------------------------

    fn accepted(name: &str, from_ref: &str, op: Option<&str>) -> AcceptedSecret {
        AcceptedSecret {
            name: name.into(),
            from_ref: from_ref.into(),
            operator: op.map(str::to_string),
        }
    }

    #[test]
    fn import_merge_empty_doc_one_ref_no_value_key() {
        let out = import_merge("", &[accepted("DB_URL", "dotenv:.env#DB_URL", None)]);
        let text = match out {
            ImportOutcome::Changed(t) => t,
            other => panic!("expected Changed, got {other:?}"),
        };
        assert!(text.contains("[[secrets]]"));
        assert!(text.contains("name = \"DB_URL\""));
        assert!(text.contains("from_ref = \"dotenv:.env#DB_URL\""));
        // NEVER a value/operator (operator was None).
        for forbidden in ["value", "literal", "secret =", "plaintext", "from_env", "operator"] {
            assert!(!text.contains(forbidden), "{forbidden:?} must not appear:\n{text}");
        }
        // The proxy config parser re-accepts it.
        let doc: toml_edit::DocumentMut = text.parse().unwrap();
        assert!(doc.get("secrets").and_then(|s| s.as_array_of_tables()).is_some());
    }

    #[test]
    fn import_merge_preserves_engine_and_comments() {
        let current = "# top comment\n[engine]\nprofile = \"balanced\"  # inline note\n";
        let out = import_merge(current, &[accepted("API", "dotenv:.env#API", Some("hash"))]);
        let text = match out {
            ImportOutcome::Changed(t) => t,
            other => panic!("expected Changed, got {other:?}"),
        };
        assert!(text.contains("# top comment"), "top comment preserved:\n{text}");
        assert!(text.contains("[engine]"), "[engine] preserved");
        assert!(text.contains("profile = \"balanced\"  # inline note"), "inline comment preserved:\n{text}");
        assert!(text.contains("[[secrets]]"), "stanza appended");
        assert!(text.contains("operator = \"hash\""));
    }

    #[test]
    fn import_merge_idempotent_existing_name_is_noop() {
        let current = "[[secrets]]\nname = \"DB_URL\"\nfrom_ref = \"dotenv:.env#DB_URL\"\n";
        let out = import_merge(current, &[accepted("DB_URL", "dotenv:.env#DB_URL", None)]);
        assert_eq!(out, ImportOutcome::NoOp, "existing name ⇒ NoOp (no rewrite)");
    }

    #[test]
    fn import_merge_unparseable_refuses_no_write() {
        let out = import_merge("this = = broken\n[[[", &[accepted("X", "dotenv:.env#X", None)]);
        assert!(matches!(out, ImportOutcome::Refused(_)), "unparseable ⇒ Refused");
    }

    #[test]
    fn import_merge_secrets_scalar_refuses() {
        let out = import_merge("secrets = \"x\"\n", &[accepted("X", "dotenv:.env#X", None)]);
        assert!(matches!(out, ImportOutcome::Refused(_)), "scalar `secrets` ⇒ Refused");
        // A `[secrets]` table (not array-of-tables) is likewise refused.
        let out2 = import_merge("[secrets]\nfoo = 1\n", &[accepted("X", "dotenv:.env#X", None)]);
        assert!(matches!(out2, ImportOutcome::Refused(_)), "[secrets] table ⇒ Refused");
    }

    #[test]
    fn import_merge_exact_byte_trace() {
        let out = import_merge(
            "",
            &[accepted("DB_URL", "dotenv:.env#DB_URL", Some("redact"))],
        );
        let text = match out {
            ImportOutcome::Changed(t) => t,
            other => panic!("expected Changed, got {other:?}"),
        };
        assert_eq!(
            text,
            "[[secrets]]\nname = \"DB_URL\"\nfrom_ref = \"dotenv:.env#DB_URL\"\noperator = \"redact\"\n",
            "byte-trace mismatch:\n{text:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Offline resolve + end-to-end MASK proof (no proxy process, no network)
    // -----------------------------------------------------------------------

    /// A written import ref resolves back to the fixture value via the dotenv provider.
    #[tokio::test]
    async fn import_ref_resolves_offline() {
        let dir = scratch_dir("resolve");
        std::fs::write(dir.join(".env"), "DB_URL=postgres://u:p@h:5432/db\n").unwrap();
        // Simulate what import writes: dotenv:<rel>#KEY.
        let sref = sordino_secrets::SecretRef::parse("dotenv:.env#DB_URL").unwrap();
        assert_eq!(sref.scheme, "dotenv");
        assert_eq!(sref.field.as_deref(), Some("DB_URL"));
        let provider = sordino_secrets::providers::dotenv::DotenvProvider::new(Some(dir.clone()));
        let val = provider.resolve(&sref).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(val.expose(), "postgres://u:p@h:5432/db");
    }

    /// Serialize the config::load tests (they mutate the process-global user-config env).
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// REAL end-to-end: import-written sordino.toml -> config::load -> default_registry ->
    /// resolve_and_install on a fresh MaskEngine -> the fixture value is masked. The
    /// SKIP-negative (no install) leaves the value present.
    #[tokio::test]
    async fn end_to_end_written_config_masks_value() {
        let _g = env_guard();
        let dir = scratch_dir("e2e");
        // Isolate the user config layer so a real ~/.config file can't pollute load().
        unsafe { std::env::set_var("SORDINO_USER_CONFIG", dir.join("no-such-user.toml")) };

        // A LOW-entropy, non-structured token (no URL/DSN shape, below the generic
        // entropy-gated API_KEY recognizer's floor) so the ONLY thing that can mask it is
        // the installed secret rule — otherwise a generic recognizer would mask it even
        // without install, defeating the SKIP-negative.
        let fixture_value = "hunter2hunter2hunter2hunter2";
        std::fs::write(dir.join(".env"), format!("API_TOKEN={fixture_value}\n")).unwrap();

        // What `secrets import` writes for an accepted API_TOKEN.
        let toml = import_merge("", &[accepted("API_TOKEN", "dotenv:.env#API_TOKEN", Some("redact"))]);
        let toml_text = match toml {
            ImportOutcome::Changed(t) => t,
            other => panic!("expected Changed, got {other:?}"),
        };
        let toml_path = dir.join("sordino.toml");
        std::fs::write(&toml_path, &toml_text).unwrap();

        // config::load re-parses the written refs (scope invariant passes — refs only).
        let loaded = sordino_proxy::config::load(Some(&toml_path)).expect("config::load");
        assert_eq!(loaded.secrets.len(), 1);
        assert_eq!(loaded.secrets[0].name, "API_TOKEN");
        assert_eq!(loaded.secrets[0].from_ref.as_deref(), Some("dotenv:.env#API_TOKEN"));

        let registry = sordino_secrets::default_registry(Some(dir.clone()));
        let admin_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // POSITIVE: install ⇒ the value is masked out of the transcript surface.
        let engine = sordino_engine::MaskEngine::new(sordino_engine::EngineConfig::default()).unwrap();
        let (status, ok) =
            sordino_proxy::secrets::resolve_and_install(&loaded.secrets, &engine, &registry, admin_key).await;
        assert!(ok, "the dotenv-referenced secret resolves offline");
        assert_eq!(status.resolved(), 1);
        let masked = engine
            .mask(&format!("connect via {fixture_value} now"), sordino_engine::Surface::UserMessage)
            .unwrap();
        assert!(
            !masked.masked_text.contains(fixture_value),
            "installed secret must be masked:\n{}",
            masked.masked_text
        );

        // NEGATIVE (skip install): a fresh engine with no rules leaves the value present.
        let engine2 = sordino_engine::MaskEngine::new(sordino_engine::EngineConfig::default()).unwrap();
        let unmasked = engine2
            .mask(&format!("connect via {fixture_value} now"), sordino_engine::Surface::UserMessage)
            .unwrap();
        assert!(
            unmasked.masked_text.contains(fixture_value),
            "without install the value is NOT masked (proves the install did the masking)"
        );

        unsafe { std::env::remove_var("SORDINO_USER_CONFIG") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
