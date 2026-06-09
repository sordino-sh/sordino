//! Native `dotenv:` provider — reads a `.env`-style file and returns the value
//! of a required `#field` (the KEY). No process spawn; file reads need no agent.

use std::path::PathBuf;

use async_trait::async_trait;
use zlauder_engine::SecretValue;

use crate::{Caps, Health, ProviderError, SecretProvider, SecretRef};

/// Resolves `dotenv:<file>#KEY` by parsing the dotenv file at `<file>` (joined onto
/// `project_root` when relative) and returning the value for `KEY`.
pub struct DotenvProvider {
    project_root: Option<PathBuf>,
}

impl DotenvProvider {
    pub fn new(project_root: Option<PathBuf>) -> Self {
        Self { project_root }
    }

    /// Resolve `r.path` to the file to read: relative paths are joined onto
    /// `project_root` when one is configured; absolute paths are used as-is.
    fn file_path(&self, path: &str) -> PathBuf {
        let p = PathBuf::from(path);
        match &self.project_root {
            Some(root) if p.is_relative() => root.join(p),
            _ => p,
        }
    }
}

#[async_trait]
impl SecretProvider for DotenvProvider {
    fn scheme(&self) -> &str {
        "dotenv"
    }

    fn capabilities(&self) -> Caps {
        Caps {
            fields: true,
            list: true,
            session_unlock: false,
        }
    }

    async fn health(&self) -> Health {
        // File reads need no agent / unlock.
        Health::Ok
    }

    async fn resolve(&self, r: &SecretRef) -> Result<SecretValue, ProviderError> {
        let field = r
            .field
            .as_deref()
            .ok_or_else(|| ProviderError::BadRef("dotenv ref needs a #KEY field".into()))?;

        let path = self.file_path(&r.path);
        // A file that can't be opened is treated as "secret absent" → NotFound.
        let iter = dotenvy::from_path_iter(&path).map_err(|_| ProviderError::NotFound)?;

        for item in iter {
            let (key, value) = item.map_err(|e| ProviderError::Parse(e.to_string()))?;
            if key == field {
                return Ok(SecretValue::new(value));
            }
        }
        Err(ProviderError::NotFound)
    }

    async fn list(&self, _prefix: Option<&str>) -> Result<Vec<SecretRef>, ProviderError> {
        // A provider-level list has no file to enumerate; listing needs an explicit file.
        Err(ProviderError::Unsupported(
            "dotenv list needs an explicit file".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_key_from_temp_env_file() {
        let path = std::env::temp_dir().join(format!("zlauder-dotenv-{}.env", std::process::id()));
        std::fs::write(&path, "FOO=bar\nAPI_KEY=sk-secret-123\n").unwrap();

        let provider = DotenvProvider::new(None);
        let r = SecretRef {
            scheme: "dotenv".into(),
            path: path.to_string_lossy().into_owned(),
            field: Some("API_KEY".into()),
            version: None,
        };

        let resolved = provider.resolve(&r).await;
        let _ = std::fs::remove_file(&path);

        let value = resolved.expect("resolve should succeed");
        assert_eq!(value.expose(), "sk-secret-123");
    }

    #[tokio::test]
    async fn missing_field_is_bad_ref() {
        let provider = DotenvProvider::new(None);
        let r = SecretRef {
            scheme: "dotenv".into(),
            path: "anything.env".into(),
            field: None,
            version: None,
        };
        assert!(matches!(
            provider.resolve(&r).await,
            Err(ProviderError::BadRef(_))
        ));
    }

    #[tokio::test]
    async fn absent_key_is_not_found() {
        let path = std::env::temp_dir().join(format!(
            "zlauder-dotenv-absent-{}.env",
            std::process::id()
        ));
        std::fs::write(&path, "FOO=bar\n").unwrap();

        let provider = DotenvProvider::new(None);
        let r = SecretRef {
            scheme: "dotenv".into(),
            path: path.to_string_lossy().into_owned(),
            field: Some("NOPE".into()),
            version: None,
        };

        let resolved = provider.resolve(&r).await;
        let _ = std::fs::remove_file(&path);

        assert!(matches!(resolved, Err(ProviderError::NotFound)));
    }
}
