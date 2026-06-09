//! `sops:` provider — decrypts a SOPS-encrypted file to JSON and extracts an
//! optional dotted `#field`. Runs with cwd = project root so `sops` can find the
//! repo's `.sops.yaml` creation rules. The decrypted value rides stdout only.

use std::path::PathBuf;

use crate::error::ProviderError;
use crate::{CliManifest, CliProvider};
use crate::{Caps, SecretRef};

/// Build the `sops` CLI provider.
pub fn provider(project_root: Option<PathBuf>) -> CliProvider {
    CliProvider::new(
        CliManifest {
            scheme: "sops",
            binary: "sops",
            caps: Caps {
                fields: true,
                list: false,
                session_unlock: false,
            },
            resolve_argv,
            parse_output,
            list_argv: None,
            parse_list: None,
            health_argv,
            // sops resolves `.sops.yaml` relative to the working directory.
            use_project_root_cwd: true,
        },
        project_root,
    )
}

fn resolve_argv(r: &SecretRef) -> Vec<String> {
    vec![
        "sops".into(),
        "--decrypt".into(),
        "--output-type".into(),
        "json".into(),
        r.path.clone(),
    ]
}

fn health_argv() -> Vec<String> {
    vec!["sops".into(), "--version".into()]
}

fn parse_output(r: &SecretRef, out: &[u8]) -> Result<String, ProviderError> {
    let root: serde_json::Value = serde_json::from_slice(out)
        .map_err(|e| ProviderError::Parse(format!("sops output is not valid JSON: {e}")))?;

    match &r.field {
        // No field: hand back the whole decrypted JSON document.
        None => Ok(String::from_utf8_lossy(out).into_owned()),
        // Field: treat as a dotted path and descend object keys to a scalar leaf.
        Some(field) => extract_dotted(&root, field),
    }
}

/// Descend `value` along the dot-separated `field` path; the leaf must be a JSON
/// scalar (string returned as-is, number/bool stringified). Missing key ->
/// `NotFound`; a non-scalar (object/array/null) leaf -> `Parse`.
fn extract_dotted(value: &serde_json::Value, field: &str) -> Result<String, ProviderError> {
    let mut cur = value;
    for key in field.split('.') {
        cur = cur.get(key).ok_or(ProviderError::NotFound)?;
    }
    match cur {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(ProviderError::Parse(format!(
            "sops field {field:?} is not a scalar value"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_dotted_scalar_fields() {
        let json = serde_json::json!({
            "db": {
                "password": "s3cr3t",
                "port": 5432,
                "tls": true
            }
        });

        assert_eq!(extract_dotted(&json, "db.password").unwrap(), "s3cr3t");
        assert_eq!(extract_dotted(&json, "db.port").unwrap(), "5432");
        assert_eq!(extract_dotted(&json, "db.tls").unwrap(), "true");

        assert!(matches!(
            extract_dotted(&json, "db.missing"),
            Err(ProviderError::NotFound)
        ));
        // `db` is an object, not a scalar.
        assert!(matches!(
            extract_dotted(&json, "db"),
            Err(ProviderError::Parse(_))
        ));
    }
}
