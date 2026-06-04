//! Proxy configuration loading (`zlauder.toml`).

use serde::Deserialize;
use std::path::Path;
use zlauder_engine::{AllowList, EngineConfig};

pub struct LoadedConfig {
    pub port: u16,
    pub bind: String,
    pub upstream_base_url: String,
    pub engine: EngineConfig,
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

/// Load config from `path` if it exists; otherwise use defaults. The
/// `[engine.allow_list]` sub-table is parsed separately because `regex::Regex`
/// is not `Deserialize`.
pub fn load(path: Option<&Path>) -> anyhow::Result<LoadedConfig> {
    let (file, raw): (FileConfig, Option<toml::Value>) = match path {
        Some(p) if p.exists() => {
            let text = std::fs::read_to_string(p)?;
            (toml::from_str(&text)?, Some(toml::from_str(&text)?))
        }
        _ => (FileConfig::default(), None),
    };

    let mut engine = file.engine;
    engine.allow_list = build_allow_list(raw.as_ref())?;

    Ok(LoadedConfig {
        port: file.proxy.port,
        bind: file.proxy.bind,
        upstream_base_url: file.proxy.upstream_base_url,
        engine,
    })
}

fn build_allow_list(raw: Option<&toml::Value>) -> anyhow::Result<AllowList> {
    let Some(al) = raw.and_then(|r| r.get("engine")).and_then(|e| e.get("allow_list")) else {
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

        // Tagged `Operator` enum parsed from `{ kind = "mask", char = "*", from_end = 4 }`.
        assert!(matches!(
            cfg.engine.entity_operators.get("CREDIT_CARD"),
            Some(Operator::Mask { from_end: 4, .. })
        ));
        // Categories parsed (snake_case).
        assert!(cfg.engine.enabled_categories.contains(&Category::Secrets));
        // Allow-list compiled: common-word default + the `^\d{4}$` pattern.
        assert!(cfg.engine.allow_list.is_allowed("Anthropic"));
        assert!(cfg.engine.allow_list.is_allowed("1234"));
    }

    #[test]
    fn missing_config_uses_defaults() {
        let cfg = load(None).expect("defaults");
        assert_eq!(cfg.port, 8787);
        assert!(cfg.engine.allow_list.is_allowed("localhost"));
    }
}
