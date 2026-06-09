//! Declarative CLI-backed provider. A per-backend [`CliManifest`] says how to build
//! argv and parse stdout; [`CliProvider`] runs it through the [`SecretBroker`]
//! choke-point. Adding a CLI backend is a manifest, not new resolver/engine code.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use zlauder_engine::SecretValue;

use crate::broker_spawn::SecretBroker;
use crate::error::ProviderError;
use crate::provider::SecretProvider;
use crate::types::{Caps, Health, SecretRef};

#[allow(clippy::type_complexity)] // declarative fn-pointer manifest is the point
pub struct CliManifest {
    pub scheme: &'static str,
    pub binary: &'static str,
    pub caps: Caps,
    /// Build the resolve argv (argv\[0\] = binary). The secret MUST come back on
    /// stdout — never put it (or any field) where argv can leak it.
    pub resolve_argv: fn(&SecretRef) -> Vec<String>,
    /// Parse resolve stdout into the secret value (extract `#field`, trim, etc.).
    pub parse_output: fn(&SecretRef, &[u8]) -> Result<String, ProviderError>,
    pub list_argv: Option<fn(Option<&str>) -> Vec<String>>,
    pub parse_list: Option<fn(&[u8]) -> Vec<SecretRef>>,
    /// A cheap argv whose exit status reports backend health.
    pub health_argv: fn() -> Vec<String>,
    /// Run with cwd = project root (sops needs `.sops.yaml` in scope).
    pub use_project_root_cwd: bool,
}

pub struct CliProvider {
    manifest: CliManifest,
    project_root: Option<PathBuf>,
}

impl CliProvider {
    pub fn new(manifest: CliManifest, project_root: Option<PathBuf>) -> Self {
        Self {
            manifest,
            project_root,
        }
    }

    fn cwd(&self) -> Option<&Path> {
        if self.manifest.use_project_root_cwd {
            self.project_root.as_deref()
        } else {
            None
        }
    }
}

#[async_trait]
impl SecretProvider for CliProvider {
    fn scheme(&self) -> &str {
        self.manifest.scheme
    }

    fn capabilities(&self) -> Caps {
        self.manifest.caps
    }

    async fn health(&self) -> Health {
        let argv = (self.manifest.health_argv)();
        match SecretBroker::probe(&argv, self.cwd()).await {
            Err(ProviderError::BinaryMissing(b)) => Health::BinaryMissing { binary: b },
            Err(e) => Health::Misconfigured(e.to_string()),
            Ok(o) if o.status_success => Health::Ok,
            // Best-effort: a non-zero health probe usually means a locked agent / no key.
            Ok(_) => Health::AgentLocked,
        }
    }

    async fn resolve(&self, r: &SecretRef) -> Result<SecretValue, ProviderError> {
        if r.field.is_some() && !self.manifest.caps.fields {
            return Err(ProviderError::Unsupported(format!(
                "{} does not support #field addressing",
                self.manifest.scheme
            )));
        }
        let argv = (self.manifest.resolve_argv)(r);
        let stdout = SecretBroker::run(&argv, self.cwd()).await?;
        let value = (self.manifest.parse_output)(r, &stdout)?;
        // A successful-but-empty resolve (e.g. `pass show` of an empty entry) is not a
        // usable secret — fail closed rather than register an empty `SecretValue`.
        if value.is_empty() {
            return Err(ProviderError::NotFound);
        }
        Ok(SecretValue::new(value))
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<SecretRef>, ProviderError> {
        let Some(list_argv) = self.manifest.list_argv else {
            return Err(ProviderError::Unsupported(format!(
                "{} does not support list",
                self.manifest.scheme
            )));
        };
        let argv = list_argv(prefix);
        let stdout = SecretBroker::run(&argv, self.cwd()).await?;
        match self.manifest.parse_list {
            Some(parse) => Ok(parse(&stdout)),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // L1 (ship-gate): a successful-but-empty resolve fails closed as NotFound rather
    // than registering an empty `SecretValue`.
    #[tokio::test]
    async fn empty_resolve_is_not_found() {
        fn argv(_r: &SecretRef) -> Vec<String> {
            // `printf ""` exits 0 with empty stdout.
            vec!["printf".into(), "".into()]
        }
        fn parse(_r: &SecretRef, out: &[u8]) -> Result<String, ProviderError> {
            Ok(String::from_utf8_lossy(out).into_owned())
        }
        fn health() -> Vec<String> {
            vec!["true".into()]
        }
        let m = CliManifest {
            scheme: "t",
            binary: "printf",
            caps: Caps::default(),
            resolve_argv: argv,
            parse_output: parse,
            list_argv: None,
            parse_list: None,
            health_argv: health,
            use_project_root_cwd: false,
        };
        let p = CliProvider::new(m, None);
        assert!(matches!(
            p.resolve(&SecretRef::new("t", "x")).await,
            Err(ProviderError::NotFound)
        ));
    }
}
