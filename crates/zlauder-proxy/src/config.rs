//! Proxy configuration loading — layered across user / project / local scopes.
//!
//! Precedence (later wins): user (`~/.config/zlauder/config.toml`) <
//! project (`./zlauder.toml`, the `--config` path) < local
//! (`<project-dir>/zlauder.local.toml`, gitignored). The `/privacy` CLI persists
//! to one of these files per `--scope`, and the proxy re-reads + re-merges them on
//! `POST /zlauder/reload`. A per-key override replaces wholesale (a project's
//! `enabled_categories` fully replaces the user's), which is the intuitive
//! meaning of a scoped override.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use zlauder_engine::{AllowList, EngineConfig, Profile};

use crate::admin::Scope;

/// The resolved file paths for each config scope, kept so `reload` can recompute.
#[derive(Clone, Debug)]
pub struct ConfigLayers {
    pub user: PathBuf,
    pub project: Option<PathBuf>,
    pub local: Option<PathBuf>,
}

pub struct LoadedConfig {
    pub port: u16,
    pub bind: String,
    pub upstream_base_url: String,
    pub engine: EngineConfig,
    /// Registered-secret REFERENCES (`[[secrets]]`), resolved at startup. Refs only —
    /// a value can never appear here (the scope invariant rejects it pre-parse).
    pub secrets: Vec<SecretSpec>,
    /// Broker policy allow-rules (`[[broker.allow]]`), installed at startup.
    pub broker_allows: Vec<BrokerAllowSpec>,
    pub layers: ConfigLayers,
}

/// A secret REFERENCE from `[[secrets]]`. The scope invariant
/// ([`validate_no_inline_secret_values`]) forbids an inline value. Exactly one of
/// `from_ref` / `from_env` selects the backend.
#[derive(Deserialize, Clone, Debug)]
pub struct SecretSpec {
    pub name: String,
    /// `hash` | `redact` | `mask` | `broker`; omitted ⇒ classifier default (Hash for
    /// high-entropy, Redact for low). `broker` must be explicit.
    #[serde(default)]
    pub operator: Option<String>,
    /// A provider ref `scheme:path[#field]` (pass/age/sops/dotenv/env).
    #[serde(default)]
    pub from_ref: Option<String>,
    /// Sugar for `env:VAR`.
    #[serde(default)]
    pub from_env: Option<String>,
    /// A required secret that fails to resolve holds LLM intake at 503 (fail-closed).
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_case_sensitive")]
    pub case_sensitive: bool,
}

fn default_case_sensitive() -> bool {
    true
}

/// `[broker]` — the default-deny broker policy. Each `[[broker.allow]]` rule names
/// the secret + tool + param pointer (+ optional dest host allow-list) that may
/// receive a brokered value at the local tool boundary.
#[derive(Deserialize, Clone, Debug, Default)]
pub struct BrokerSection {
    #[serde(default)]
    pub allow: Vec<BrokerAllowSpec>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct BrokerAllowSpec {
    /// Glob over the registered secret name (`None` ⇒ any secret). Per-secret least
    /// privilege: a DB password resolves only into the rule(s) that name it.
    #[serde(default)]
    pub secret: Option<String>,
    /// Glob over the tool name (`psql`, `curl`, `mcp__*` — though egress tools are
    /// denied regardless).
    pub tool: String,
    /// Glob over the RFC-6901 param pointer (`/connection_uri`, `/args/*`). Default
    /// `*` = any param of the tool.
    #[serde(default = "default_param_glob")]
    pub param: String,
    /// Destination constraint: `host_allowlist:db.internal,db2.internal` | `any` |
    /// omitted (no host constraint).
    #[serde(default)]
    pub dest: Option<String>,
    /// Optional TTL (seconds) hint for the minted broker token.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

fn default_param_glob() -> String {
    "*".to_string()
}

#[derive(Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    proxy: ProxySection,
    #[serde(default)]
    engine: EngineConfig,
    #[serde(default)]
    secrets: Vec<SecretSpec>,
    #[serde(default)]
    broker: BrokerSection,
}

#[derive(Deserialize)]
struct ProxySection {
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default = "default_bind")]
    bind: String,
    #[serde(default = "default_upstream")]
    upstream_base_url: String,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            port: default_port(),
            bind: default_bind(),
            upstream_base_url: default_upstream(),
        }
    }
}

fn default_port() -> u16 {
    8787
}
fn default_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_upstream() -> String {
    "https://api.anthropic.com".to_string()
}

/// Resolve the per-scope file paths given the project config path (the `--config`
/// argument, usually `./zlauder.toml`).
pub fn resolve_layers(project: Option<&Path>) -> ConfigLayers {
    let local = project.map(|p| {
        p.parent()
            .unwrap_or(Path::new("."))
            .join("zlauder.local.toml")
    });
    ConfigLayers {
        user: zlauder_state::user_config_path(),
        project: project.map(Path::to_path_buf),
        local,
    }
}

/// Load and merge config across all scopes. `project` is the `--config` path.
pub fn load(project: Option<&Path>) -> anyhow::Result<LoadedConfig> {
    let layers = resolve_layers(project);
    let merged = merged_value(&layers)?;

    // Scope invariant: a secret VALUE must never live in a config file.
    validate_no_inline_secret_values(&merged)?;

    let file: FileConfig = merged.clone().try_into()?;
    let mut engine = file.engine;
    engine.allow_list = build_allow_list(Some(&merged))?;
    warn_unknown_entity_types(&engine);
    warn_narrowing_profile(&merged, &engine);

    Ok(LoadedConfig {
        port: file.proxy.port,
        bind: file.proxy.bind,
        upstream_base_url: file.proxy.upstream_base_url,
        engine,
        secrets: file.secrets,
        broker_allows: file.broker.allow,
        layers,
    })
}

/// Recompute only the engine config from the current files (for `reload`). The
/// proxy section (port/bind/upstream) is intentionally NOT re-applied — those
/// can't change under a live socket.
pub fn reload_engine(layers: &ConfigLayers) -> anyhow::Result<EngineConfig> {
    let merged = merged_value(layers)?;
    // Re-enforce the scope invariant on reload — a value added to `[[secrets]]` after
    // startup must be rejected here too, not just at load (defense consistency).
    validate_no_inline_secret_values(&merged)?;
    let file: FileConfig = merged.clone().try_into()?;
    let mut engine = file.engine;
    engine.allow_list = build_allow_list(Some(&merged))?;
    warn_unknown_entity_types(&engine);
    Ok(engine)
}

/// Re-read the `[[broker.allow]]` rules from the current files (for `reload`), so a
/// removed/restricted broker rule takes effect live. Re-runs the scope invariant.
pub fn reload_broker_allows(layers: &ConfigLayers) -> anyhow::Result<Vec<BrokerAllowSpec>> {
    let merged = merged_value(layers)?;
    validate_no_inline_secret_values(&merged)?;
    let file: FileConfig = merged.try_into()?;
    Ok(file.broker.allow)
}

/// Scope invariant: a secret VALUE must NEVER live in a config file. Reject any
/// `[[secrets]]` entry carrying an inline `value`/`literal`/`secret`/`plaintext` key
/// (the channel is refs-only — `from_ref`/`from_env`). Rejected pre-parse so a value
/// can never even be deserialized into a `SecretSpec`.
fn validate_no_inline_secret_values(merged: &toml::Value) -> anyhow::Result<()> {
    let Some(arr) = merged.get("secrets").and_then(toml::Value::as_array) else {
        return Ok(());
    };
    for (i, item) in arr.iter().enumerate() {
        if let Some(tbl) = item.as_table() {
            for forbidden in ["value", "literal", "secret", "plaintext"] {
                if tbl.contains_key(forbidden) {
                    anyhow::bail!(
                        "zlauder config: secrets[{i}] has a `{forbidden}` key — secret VALUES \
                         must never live in a config file. Use `from_ref`/`from_env` to reference \
                         a backend (pass/age/sops/dotenv/env)."
                    );
                }
            }
        }
    }
    Ok(())
}

/// Warn (don't reject) on `entity_operators` keys that aren't canonical `EntityType`
/// Display names (nor a declared `custom_replacement.entity_type`) — a file-scope
/// reload must not hard-fail a running proxy, but such a key is a SILENT NO-OP (it
/// never matches a real detection, so it masks nothing) and deserves a loud line.
/// The interactive `PUT /zlauder/config` REJECTS the same condition (admin.rs); this
/// is the persistent-file counterpart.
fn warn_unknown_entity_types(engine: &EngineConfig) {
    let unknown = engine.unknown_entity_types();
    if !unknown.is_empty() {
        eprintln!(
            "ZlauDeR: WARNING — config has entity_operators key(s) {unknown:?} that are not \
             canonical EntityType Display names (alias or typo), so they mask NOTHING. Fix the \
             entity_operators key, or declare a matching custom_replacement."
        );
    }
}

/// One-time migration surfacing for the load-bearing-`profile=` change (item 2b).
///
/// BEFORE the change, a config that set ONLY a narrowing `profile = "minimal"` /
/// `"secrets_only"` (without explicit `enabled_categories`) ran with BALANCED
/// fallback behavior: threshold 0.5 and categories {Secrets, Financial, Identity,
/// Contact}. AFTER the change, that bare profile now seeds its own (narrower) fields:
/// Minimal → {Secrets, Financial} @ 0.6, SecretsOnly → {Secrets} @ 0.6. On upgrade
/// this SILENTLY drops Identity (SSN/passport) and Contact (email/phone) masking for
/// any operator who relied on the old Balanced fallback. The behavior is approved and
/// intended; this loud line is so the narrowing is not silent on first load. Strict
/// only ADDS a category (Personal), so it is not warned.
fn warn_narrowing_profile(merged: &toml::Value, engine: &EngineConfig) {
    use zlauder_engine::Profile;
    // Only the narrowing profiles, and only when the operator did NOT pin categories
    // explicitly (an explicit `enabled_categories` already overrides the seed, so
    // there is nothing to migrate).
    let narrowing = matches!(engine.profile, Profile::Minimal | Profile::SecretsOnly);
    if !narrowing {
        return;
    }
    let engine_tbl = merged.get("engine").and_then(toml::Value::as_table);
    let has_explicit_cats = engine_tbl
        .map(|t| t.contains_key("enabled_categories"))
        .unwrap_or(false);
    if has_explicit_cats {
        return;
    }
    let profile_name = serde_json::to_value(engine.profile)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "minimal".to_string());
    eprintln!(
        "ZlauDeR: NOTE — config sets `profile = \"{profile_name}\"` without an explicit \
         `enabled_categories`. As of the load-bearing-profile change, this now applies that \
         profile's NARROWER categories/threshold directly (it no longer falls back to Balanced). \
         Identity and Contact masking are NOT active under this profile. If you relied on the old \
         Balanced fallback, add explicit `enabled_categories`/`score_threshold` to retain it."
    );
}

/// Resolve the file path a `scope` write targets. `Session` has no file (handled by
/// the caller); `Project`/`Local` fall back to `<project_root>/zlauder.{,local.}toml`
/// when the layers don't already carry an explicit path.
fn scope_file_path(layers: &ConfigLayers, project_root: &str, scope: Scope) -> Option<PathBuf> {
    match scope {
        Scope::Session => None,
        Scope::User => Some(layers.user.clone()),
        Scope::Project => layers.project.clone().or_else(|| {
            (!project_root.is_empty()).then(|| Path::new(project_root).join("zlauder.toml"))
        }),
        Scope::Local => layers.local.clone().or_else(|| {
            (!project_root.is_empty()).then(|| Path::new(project_root).join("zlauder.local.toml"))
        }),
    }
}

/// Persist a detection profile (profile + threshold + categories + default operator,
/// all from [`EngineConfig::for_profile`]) to the `scope`'s TOML file, preserving
/// existing content/formatting via `toml_edit`. This is the SAME field shape the
/// hooks CLI's `apply_profile` writes, so the proxy `POST /zlauder/profile/{name}`
/// endpoint and the CLI converge on one persisted representation. Returns the path.
pub fn persist_profile(
    layers: &ConfigLayers,
    project_root: &str,
    scope: Scope,
    profile: Profile,
) -> anyhow::Result<PathBuf> {
    let path = scope_file_path(layers, project_root, scope)
        .ok_or_else(|| anyhow::anyhow!("scope {scope:?} has no persistable file path"))?;

    let defaults = EngineConfig::for_profile(profile);
    let profile_str = serde_json::to_value(profile)?
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "balanced".to_string());
    let mut cats: Vec<String> = defaults
        .enabled_categories
        .iter()
        .filter_map(|c| serde_json::to_value(c).ok()?.as_str().map(str::to_string))
        .collect();
    cats.sort();
    let operator = serde_json::to_value(defaults.default_operator)?;

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    if !doc.contains_key("engine") {
        doc["engine"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["engine"]["profile"] = toml_edit::value(profile_str.as_str());
    doc["engine"]["score_threshold"] = toml_edit::value(f32_to_toml(defaults.score_threshold));
    let mut arr = toml_edit::Array::new();
    for c in &cats {
        arr.push(c.as_str());
    }
    doc["engine"]["enabled_categories"] = toml_edit::value(arr);
    if let Some(kind) = operator.get("kind").and_then(|v| v.as_str()) {
        let mut t = toml_edit::InlineTable::new();
        t.insert("kind", kind.into());
        doc["engine"]["default_operator"] = toml_edit::value(t);
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, doc.to_string())
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    Ok(path)
}

/// Widen an `f32` to `f64` via its shortest decimal form so e.g. `0.4` persists as
/// `0.4`, not `0.4000000059604645`. Mirrors the hooks CLI helper of the same name.
fn f32_to_toml(v: f32) -> f64 {
    format!("{v}").parse().unwrap_or(v as f64)
}

/// Read every existing layer file and deep-merge them (user < project < local).
fn merged_value(layers: &ConfigLayers) -> anyhow::Result<toml::Value> {
    let mut merged = toml::Value::Table(toml::map::Map::new());
    for path in [
        Some(layers.user.as_path()),
        layers.project.as_deref(),
        layers.local.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(v) = read_layer(path)? {
            merge(&mut merged, v);
        }
    }
    Ok(merged)
}

fn read_layer(path: &Path) -> anyhow::Result<Option<toml::Value>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let v =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    Ok(Some(v))
}

/// Deep-merge `over` into `base`: tables recurse, every other value (incl. arrays)
/// replaces wholesale.
fn merge(base: &mut toml::Value, over: toml::Value) {
    match (base, over) {
        (toml::Value::Table(b), toml::Value::Table(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(bv) => merge(bv, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

fn build_allow_list(raw: Option<&toml::Value>) -> anyhow::Result<AllowList> {
    let Some(al) = raw
        .and_then(|r| r.get("engine"))
        .and_then(|e| e.get("allow_list"))
    else {
        return Ok(AllowList::with_common_words());
    };
    let strings = |key: &str| -> Vec<String> {
        al.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    AllowList::from_specs(strings("exact"), strings("exact_ci"), strings("patterns"))
        .map_err(|e| anyhow::anyhow!("invalid allow_list pattern: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zlauder_engine::{Category, Operator};

    #[test]
    fn loads_repo_zlauder_toml() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../zlauder.toml");
        let cfg = load(Some(&path)).expect("zlauder.toml should parse");

        assert_eq!(cfg.port, 8787);
        assert_eq!(cfg.upstream_base_url, "https://api.anthropic.com");
        assert!(cfg.engine.enabled, "enabled defaults true");

        // Tagged `Operator` enum parsed from `{ kind = "mask", char = "*", from_end = 4 }`.
        assert!(matches!(
            cfg.engine.entity_operators.get("CREDIT_CARD"),
            Some(Operator::Mask { from_end: 4, .. })
        ));
        // Categories parsed (snake_case).
        assert!(cfg.engine.enabled_categories.contains(&Category::Secrets));
        // Reveal marker seeded on with the ANSI escape (basic-string \u001b).
        assert!(cfg.engine.reveal_marker.enabled);
        assert!(cfg.engine.reveal_marker.prefix.starts_with('\u{1b}'));
        // Allow-list compiled: common-word default + the `^\d{4}$` pattern.
        assert!(cfg.engine.allow_list.is_allowed("Anthropic"));
        assert!(cfg.engine.allow_list.is_allowed("1234"));
    }

    #[test]
    fn loads_repo_zlauder_toml_example() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../zlauder.toml.example");
        let cfg = load(Some(&path)).expect("zlauder.toml.example should parse");

        assert_eq!(cfg.port, 8787);
        assert!(cfg.engine.enabled);
        assert_eq!(cfg.engine.detection_cache_cap, 50_000);
        assert!(cfg.engine.reveal_marker.enabled);
        assert!(cfg.engine.allow_list.is_allowed("1234"));
    }

    #[test]
    fn loads_plugin_seed_zlauder_toml() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../zlauder-plugin/zlauder.toml");
        let cfg = load(Some(&path)).expect("plugin zlauder.toml should parse");

        assert_eq!(
            cfg.port, 8787,
            "plugin seed omits port and uses loader default"
        );
        assert!(cfg.engine.enabled);
        assert!(cfg.engine.reveal_marker.enabled);
        assert!(matches!(
            cfg.engine.entity_operators.get("CREDIT_CARD"),
            Some(Operator::Mask { from_end: 4, .. })
        ));
    }

    #[test]
    fn loads_plugin_zlauder_toml_example() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../zlauder-plugin/zlauder.toml.example");
        let cfg = load(Some(&path)).expect("plugin zlauder.toml.example should parse");

        assert_eq!(cfg.port, 8787);
        assert!(cfg.engine.enabled);
        assert_eq!(cfg.engine.detection_cache_cap, 50_000);
        assert!(cfg.engine.reveal_marker.enabled);
    }

    #[test]
    fn missing_config_uses_defaults() {
        // Point user-scope at a path that doesn't exist so a real ~/.config file
        // can't perturb the test.
        // SAFETY: single-threaded unit test.
        unsafe { std::env::set_var("ZLAUDER_USER_CONFIG", "/nonexistent/zlauder/config.toml") };
        let cfg = load(None).expect("defaults");
        assert_eq!(cfg.port, 8787);
        assert!(cfg.engine.enabled);
        assert!(cfg.engine.allow_list.is_allowed("localhost"));
        unsafe { std::env::remove_var("ZLAUDER_USER_CONFIG") };
    }

    #[test]
    fn parses_engine_ml_section() {
        let dir = std::env::temp_dir().join(format!("zlauder-ml-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let project = dir.join("zlauder.toml");
        std::fs::write(
            &project,
            "[engine.ml]\nenabled = true\nmodel = \"acme/privacy\"\nmin_score = 0.7\n",
        )
        .unwrap();
        // SAFETY: single-threaded unit test.
        unsafe { std::env::set_var("ZLAUDER_USER_CONFIG", "/nonexistent/zlauder/config.toml") };

        let cfg = load(Some(&project)).expect("ml section load");
        assert!(cfg.engine.ml.enabled);
        assert_eq!(cfg.engine.ml.model, "acme/privacy");
        assert_eq!(cfg.engine.ml.min_score, Some(0.7));
        // A config without `[engine.ml]` still defaults cleanly (off).
        assert!(!EngineConfig::default().ml.enabled);

        unsafe { std::env::remove_var("ZLAUDER_USER_CONFIG") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_engine_reveal_marker_section() {
        let dir = std::env::temp_dir().join(format!("zlauder-marker-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let project = dir.join("zlauder.toml");
        // TOML basic strings carry the ANSI ESC byte via a \u001b escape.
        std::fs::write(
            &project,
            "[engine.reveal_marker]\nenabled = true\nprefix = \"\\u001b[97;44m\"\nsuffix = \"\\u001b[0m\"\n",
        )
        .unwrap();
        // SAFETY: single-threaded unit test.
        unsafe { std::env::set_var("ZLAUDER_USER_CONFIG", "/nonexistent/zlauder/config.toml") };

        let cfg = load(Some(&project)).expect("reveal_marker section load");
        assert!(cfg.engine.reveal_marker.enabled);
        assert_eq!(cfg.engine.reveal_marker.prefix, "\u{1b}[97;44m");
        assert_eq!(cfg.engine.reveal_marker.suffix, "\u{1b}[0m");
        // A config without the section defaults cleanly (off).
        assert!(
            !zlauder_engine::EngineConfig::default()
                .reveal_marker
                .enabled
        );

        unsafe { std::env::remove_var("ZLAUDER_USER_CONFIG") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_layer_overrides_project() {
        let dir = std::env::temp_dir().join(format!("zlauder-layer-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let project = dir.join("zlauder.toml");
        let local = dir.join("zlauder.local.toml");
        std::fs::write(
            &project,
            "[engine]\nenabled = true\nscore_threshold = 0.5\n",
        )
        .unwrap();
        std::fs::write(&local, "[engine]\nenabled = false\n").unwrap();
        // SAFETY: single-threaded unit test.
        unsafe { std::env::set_var("ZLAUDER_USER_CONFIG", "/nonexistent/zlauder/config.toml") };

        let cfg = load(Some(&project)).expect("layered load");
        assert!(!cfg.engine.enabled, "local layer should win for `enabled`");
        // project value untouched by local survives the merge.
        assert!((cfg.engine.score_threshold - 0.5).abs() < f32::EPSILON);

        unsafe { std::env::remove_var("ZLAUDER_USER_CONFIG") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
