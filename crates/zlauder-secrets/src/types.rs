use crate::error::ProviderError;

/// What a provider can do beyond a bare whole-value `resolve`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// Supports `#field` sub-addressing (multi-field secrets).
    pub fields: bool,
    /// Supports `list(prefix)`.
    pub list: bool,
    /// Supports an in-memory session unlock (e.g. a passphrase-protected identity).
    pub session_unlock: bool,
}

/// Health of a provider's backend, for the readiness gate + status UX.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Health {
    Ok,
    BinaryMissing { binary: String },
    AgentLocked,
    NeedsUnlock,
    Misconfigured(String),
}

/// A provider-addressed secret reference, parsed from `scheme:path[#field]`.
/// `scheme` selects the provider; `path` + `field` are provider-owned addressing.
/// (`version` is reserved for providers that support it; not parsed in v1.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    pub scheme: String,
    pub path: String,
    pub field: Option<String>,
    pub version: Option<String>,
}

impl SecretRef {
    pub fn new(scheme: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into(),
            path: path.into(),
            field: None,
            version: None,
        }
    }

    /// Parse `scheme:path[#field]`. `scheme` (before the first `:`) and `path` are
    /// required and non-empty; an optional `#field` is split on the first `#`.
    pub fn parse(s: &str) -> Result<Self, ProviderError> {
        let (scheme, rest) = s
            .split_once(':')
            .ok_or_else(|| ProviderError::BadRef(format!("missing scheme in {s:?} (want scheme:path)")))?;
        if scheme.is_empty() {
            return Err(ProviderError::BadRef(format!("empty scheme in {s:?}")));
        }
        let (path, field) = match rest.split_once('#') {
            // An explicit trailing `#` with no field is a MALFORMED ref — not the
            // whole-value request (which is the no-`#` form). Reject it so e.g.
            // `sops:secrets.yaml#` can't silently resolve to the WHOLE document.
            Some((_, f)) if f.is_empty() => {
                return Err(ProviderError::BadRef(format!("empty #field in {s:?}")));
            }
            Some((p, f)) => (p, Some(f.to_string())),
            None => (rest, None),
        };
        if path.is_empty() {
            return Err(ProviderError::BadRef(format!("empty path in {s:?}")));
        }
        Ok(Self {
            scheme: scheme.to_string(),
            path: path.to_string(),
            field,
            version: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scheme_path_field() {
        let r = SecretRef::parse("pass:openai/key#password").unwrap();
        assert_eq!(r.scheme, "pass");
        assert_eq!(r.path, "openai/key");
        assert_eq!(r.field.as_deref(), Some("password"));

        let r2 = SecretRef::parse("env:PGPASSWORD").unwrap();
        assert_eq!(r2.scheme, "env");
        assert_eq!(r2.path, "PGPASSWORD");
        assert_eq!(r2.field, None);
    }

    #[test]
    fn rejects_malformed() {
        assert!(SecretRef::parse("noscheme").is_err());
        assert!(SecretRef::parse(":path").is_err());
        assert!(SecretRef::parse("scheme:").is_err());
        // Explicit trailing `#` with no field is malformed, NOT a whole-value request.
        assert!(SecretRef::parse("sops:secrets.yaml#").is_err());
    }
}
