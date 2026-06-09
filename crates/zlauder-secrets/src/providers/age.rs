use std::path::PathBuf;

use crate::{Caps, CliManifest, CliProvider, ProviderError, SecretRef};

/// Resolve the age identity file path at call time, in precedence order:
/// `ZLAUDER_AGE_IDENTITY`, then `AGE_KEY_FILE`, then `$HOME/.config/age/keys.txt`.
fn identity_path() -> String {
    if let Ok(p) = std::env::var("ZLAUDER_AGE_IDENTITY") {
        return p;
    }
    if let Ok(p) = std::env::var("AGE_KEY_FILE") {
        return p;
    }
    format!(
        "{}/.config/age/keys.txt",
        std::env::var("HOME").unwrap_or_default()
    )
}

fn resolve_argv(r: &SecretRef) -> Vec<String> {
    vec![
        "age".into(),
        "--decrypt".into(),
        "--identity".into(),
        identity_path(),
        r.path.clone(),
    ]
}

fn parse_output(_r: &SecretRef, out: &[u8]) -> Result<String, ProviderError> {
    let mut s = String::from_utf8(out.to_vec())
        .map_err(|_| ProviderError::Parse("age output not utf-8".into()))?;
    // Strip a SINGLE trailing newline if present (not all trailing whitespace).
    if s.ends_with('\n') {
        s.pop();
    }
    Ok(s)
}

fn health_argv() -> Vec<String> {
    vec!["age".into(), "--version".into()]
}

pub fn provider(project_root: Option<PathBuf>) -> CliProvider {
    let manifest = CliManifest {
        scheme: "age",
        binary: "age",
        caps: Caps {
            fields: false,
            list: false,
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

    fn dummy_ref() -> SecretRef {
        SecretRef {
            scheme: "age".into(),
            path: "secret.age".into(),
            field: None,
            version: None,
        }
    }

    #[test]
    fn parse_output_strips_exactly_one_trailing_newline() {
        let r = dummy_ref();

        // Single trailing newline is stripped.
        assert_eq!(parse_output(&r, b"hunter2\n").unwrap(), "hunter2");

        // Only one newline is stripped; a second remains.
        assert_eq!(parse_output(&r, b"hunter2\n\n").unwrap(), "hunter2\n");

        // No trailing newline: value is unchanged.
        assert_eq!(parse_output(&r, b"hunter2").unwrap(), "hunter2");

        // Empty input stays empty.
        assert_eq!(parse_output(&r, b"").unwrap(), "");

        // A lone newline becomes empty.
        assert_eq!(parse_output(&r, b"\n").unwrap(), "");

        // Interior newlines are preserved; one trailing newline stripped.
        assert_eq!(parse_output(&r, b"line1\nline2\n").unwrap(), "line1\nline2");
    }

    #[test]
    fn parse_output_rejects_non_utf8() {
        let r = dummy_ref();
        let err = parse_output(&r, &[0xff, 0xfe]).unwrap_err();
        assert!(matches!(err, ProviderError::Parse(_)));
    }
}
