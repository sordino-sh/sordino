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
use zlauder_engine::{AllowList, EngineConfig};

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
    pub layers: ConfigLayers,
}

#[derive(Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    proxy: ProxySection,
    #[serde(default)]
    engine: EngineConfig,
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

    let file: FileConfig = merged.clone().try_into()?;
    let mut engine = file.engine;
    engine.allow_list = build_allow_list(Some(&merged))?;

    Ok(LoadedConfig {
        port: file.proxy.port,
        bind: file.proxy.bind,
        upstream_base_url: file.proxy.upstream_base_url,
        engine,
        layers,
    })
}

/// Recompute only the engine config from the current files (for `reload`). The
/// proxy section (port/bind/upstream) is intentionally NOT re-applied — those
/// can't change under a live socket.
pub fn reload_engine(layers: &ConfigLayers) -> anyhow::Result<EngineConfig> {
    let merged = merged_value(layers)?;
    let file: FileConfig = merged.clone().try_into()?;
    let mut engine = file.engine;
    engine.allow_list = build_allow_list(Some(&merged))?;
    Ok(engine)
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
        assert!(!zlauder_engine::EngineConfig::default().reveal_marker.enabled);

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
