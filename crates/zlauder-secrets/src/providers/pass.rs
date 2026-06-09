use std::path::PathBuf;

use crate::{Caps, CliManifest, CliProvider, ProviderError, SecretRef};

fn resolve_argv(r: &SecretRef) -> Vec<String> {
    vec!["pass".into(), "show".into(), r.path.clone()]
}

fn parse_output(r: &SecretRef, out: &[u8]) -> Result<String, ProviderError> {
    let text = String::from_utf8_lossy(out);
    match &r.field {
        None => {
            // First line is the secret (no trailing newline).
            Ok(text.lines().next().unwrap_or("").to_string())
        }
        Some(field) => {
            // pass multiline convention: lines of the form "key: value".
            for line in text.lines() {
                if let Some((key, value)) = line.split_once(':')
                    && key.trim().eq_ignore_ascii_case(field.trim())
                {
                    return Ok(value.trim().to_string());
                }
            }
            Err(ProviderError::NotFound)
        }
    }
}

fn health_argv() -> Vec<String> {
    vec!["pass".into(), "ls".into()]
}

pub fn provider(project_root: Option<PathBuf>) -> CliProvider {
    let manifest = CliManifest {
        scheme: "pass",
        binary: "pass",
        caps: Caps {
            fields: true,
            list: true,
            session_unlock: false,
        },
        resolve_argv,
        parse_output,
        list_argv: None,
        parse_list: None,
        health_argv,
        use_project_root_cwd: false,
    };
    CliProvider::new(manifest, project_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sref(field: Option<&str>) -> SecretRef {
        SecretRef {
            scheme: "pass".into(),
            path: "some/entry".into(),
            field: field.map(|f| f.to_string()),
            version: None,
        }
    }

    #[test]
    fn first_line_is_secret() {
        let out = b"hunter2\nuser: alice\nurl: https://example.com\n";
        let r = sref(None);
        assert_eq!(parse_output(&r, out).unwrap(), "hunter2");
    }

    #[test]
    fn first_line_no_trailing_newline() {
        let out = b"hunter2";
        let r = sref(None);
        assert_eq!(parse_output(&r, out).unwrap(), "hunter2");
    }

    #[test]
    fn field_extraction_case_insensitive() {
        let out = b"hunter2\nUser: alice\nURL: https://example.com\n";
        let r = sref(Some("user"));
        assert_eq!(parse_output(&r, out).unwrap(), "alice");
    }

    #[test]
    fn field_value_is_trimmed() {
        let out = b"hunter2\nuser:    spaced-value   \n";
        let r = sref(Some("user"));
        assert_eq!(parse_output(&r, out).unwrap(), "spaced-value");
    }

    #[test]
    fn field_not_found_is_error() {
        let out = b"hunter2\nuser: alice\n";
        let r = sref(Some("missing"));
        assert!(matches!(parse_output(&r, out), Err(ProviderError::NotFound)));
    }
}
