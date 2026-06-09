//! Registered-secret channel: exact-literal Pass-0 detection over known secret
//! values.
//!
//! Secrets are held OFF [`crate::config::EngineConfig`] (never serialized) so a
//! value can't leak into `WireConfig` / `GET /zlauder/config` / the monitor. Values
//! live only here (zeroized) and, once minted, encrypted in the session store. A
//! registered secret selects an [`Operator`] — `Hash` / `Redact` / `Mask` / `Broker`
//! (`Token`/`Keep` are rejected: a secret must never be display-revealable or passed
//! through). There is no separate "mode" type; the operator IS the choice.

use std::collections::HashSet;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::cache::{CachedDetection, Source};
use crate::config::Operator;
use crate::error::EngineError;
use crate::surface::Surface;
use crate::token::slugify;

/// A secret value, zeroized on drop. No `Clone`/`Serialize`/`Display`; `Debug`
/// redacts.
pub struct SecretValue(zeroize::Zeroizing<String>);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(zeroize::Zeroizing::new(value.into()))
    }
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue(***)")
    }
}

/// A registered secret, as handed to [`crate::MaskEngine::set_secret_rules`]. Built
/// by the host-side provider crate; never serialized.
pub struct SecretRule {
    /// Stable, human-meaningful name — also the broker-policy key and the token slug
    /// seed. For a secret detection this becomes the detection `entity_type`, so the
    /// `Hash` render is `[NAME:hex]` and the broker entity is `BROKER__<slug(NAME)>`.
    pub name: String,
    pub value: SecretValue,
    /// One of `Hash` / `Redact` / `Mask` / `Broker` (validated; `Token`/`Keep`
    /// rejected by [`compile_secrets`]).
    pub operator: Operator,
    pub case_sensitive: bool,
    /// Restrict to specific surfaces (`None` ⇒ all surfaces).
    pub apply_to_surfaces: Option<HashSet<Surface>>,
}

/// A compiled secret: an Aho-Corasick matcher over the exact value plus the value
/// itself (for minting). NOT `Clone` (holds the matcher + the non-`Clone` value);
/// the whole [`SecretSet`] is swapped behind an `Arc`, never cloned per-rule.
pub struct CompiledSecret {
    pub name: String,
    pub operator: Operator,
    /// blake3 of the value (NOT the value) — feeds the fingerprint and any future
    /// bind-and-remember `value-hash → ref` recognition.
    pub value_hash: [u8; 32],
    matcher: AhoCorasick,
    value: SecretValue,
    surfaces: Option<HashSet<Surface>>,
}

impl CompiledSecret {
    /// The plaintext value (for the host-side resolve/bind paths). Never serialized.
    pub fn value(&self) -> &str {
        self.value.expose()
    }
}

/// The installed secret set + its fingerprint (folded into the cache key).
pub struct SecretSet {
    pub compiled: Vec<CompiledSecret>,
    pub secrets_fp: u64,
}

impl SecretSet {
    pub fn empty() -> Self {
        Self {
            compiled: Vec::new(),
            secrets_fp: secrets_fingerprint(&[]),
        }
    }
}

/// Compile registered secrets into matchers. Rejects `Token`/`Keep` operators (a
/// secret must not be display-revealable or passed through), empty values, and
/// duplicate broker slugs — so two distinct broker secrets never share a token
/// entity even at an identical value (round-3 F1: the slug is cosmetic, but a
/// collision would still be a confusing config error).
pub fn compile_secrets(rules: Vec<SecretRule>) -> Result<Vec<CompiledSecret>, EngineError> {
    let mut out = Vec::with_capacity(rules.len());
    let mut seen_slug: HashSet<String> = HashSet::new();
    for r in rules {
        match r.operator {
            Operator::Token | Operator::Keep => {
                return Err(EngineError::InvalidSecret(format!(
                    "secret {:?}: operator {:?} is not valid for a secret \
                     (use hash/redact/mask/broker)",
                    r.name, r.operator
                )));
            }
            _ => {}
        }
        if r.value.expose().is_empty() {
            return Err(EngineError::InvalidSecret(format!(
                "secret {:?}: empty value",
                r.name
            )));
        }
        if r.operator == Operator::Broker {
            let slug = slugify(&r.name);
            if !seen_slug.insert(slug) {
                return Err(EngineError::InvalidSecret(format!(
                    "secret {:?}: broker token slug collides with another secret; rename it",
                    r.name
                )));
            }
        }
        let value_hash = *blake3::hash(r.value.expose().as_bytes()).as_bytes();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(!r.case_sensitive)
            .build([r.value.expose()])
            .map_err(|e| EngineError::InvalidSecret(format!("secret {:?}: {e}", r.name)))?;
        out.push(CompiledSecret {
            name: r.name,
            operator: r.operator,
            value_hash,
            matcher,
            value: r.value,
            surfaces: r.apply_to_surfaces,
        });
    }
    Ok(out)
}

/// Fingerprint of the compiled secret set: name + operator + value_hash + surfaces.
/// The VALUE never enters the fingerprint (its `value_hash` does), and the
/// fingerprint never enters any serialized surface.
pub fn secrets_fingerprint(compiled: &[CompiledSecret]) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"zlauder-secrets-fp-v1");
    for c in compiled {
        h.update(c.name.as_bytes());
        h.update(&[0]);
        h.update(&[operator_tag(c.operator)]);
        h.update(&c.value_hash);
        match &c.surfaces {
            None => h.update(&[0]),
            Some(set) => {
                h.update(&[1]);
                let mut tags: Vec<u8> = set.iter().map(|s| surface_tag(*s)).collect();
                tags.sort_unstable();
                h.update(&tags)
            }
        };
        h.update(&[0xff]);
    }
    u64::from_le_bytes(
        h.finalize().as_bytes()[..8]
            .try_into()
            .expect("32-byte digest"),
    )
}

/// Pass-0: exact-literal detection of registered secret values, surface-filtered.
/// Each match is `Source::Secret`, `score 1.0`, carries the secret's operator in
/// `secret_op`, and uses the EXACT registered name as `entity_type` (the broker mint
/// / hash render / policy authority). These win every overlap (tier 0) and are
/// EXEMPT from allow-list suppression (see `detect::run_detection`).
pub fn detect_secrets(
    compiled: &[CompiledSecret],
    text: &str,
    surface: Surface,
) -> Vec<CachedDetection> {
    let mut dets = Vec::new();
    for c in compiled {
        if let Some(surfs) = &c.surfaces
            && !surfs.contains(&surface)
        {
            continue;
        }
        for m in c.matcher.find_iter(text) {
            dets.push(CachedDetection {
                start: m.start(),
                end: m.end(),
                entity_type: c.name.clone(),
                score: 1.0,
                source: Source::Secret,
                literal: false,
                fixed_token: None,
                secret_op: Some(c.operator),
            });
        }
    }
    dets
}

fn operator_tag(op: Operator) -> u8 {
    match op {
        Operator::Token => 0,
        Operator::Redact => 1,
        Operator::Mask { .. } => 2,
        Operator::Hash => 3,
        Operator::Broker => 4,
        Operator::Keep => 5,
    }
}

fn surface_tag(s: Surface) -> u8 {
    match s {
        Surface::UserMessage => 0,
        Surface::SystemPrompt => 1,
        Surface::ToolResult => 2,
        Surface::AssistantText => 3,
        Surface::ToolUseInput => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, value: &str, op: Operator) -> SecretRule {
        SecretRule {
            name: name.into(),
            value: SecretValue::new(value),
            operator: op,
            case_sensitive: true,
            apply_to_surfaces: None,
        }
    }

    #[test]
    fn rejects_token_and_keep_operators() {
        assert!(compile_secrets(vec![rule("a", "v", Operator::Token)]).is_err());
        assert!(compile_secrets(vec![rule("a", "v", Operator::Keep)]).is_err());
        assert!(compile_secrets(vec![rule("a", "v", Operator::Hash)]).is_ok());
        assert!(compile_secrets(vec![rule("a", "v", Operator::Broker)]).is_ok());
    }

    #[test]
    fn rejects_empty_value_and_broker_slug_collision() {
        assert!(compile_secrets(vec![rule("a", "", Operator::Hash)]).is_err());
        // Two broker secrets whose names slugify identically collide.
        let dup = compile_secrets(vec![
            rule("db-pass", "v1", Operator::Broker),
            rule("db.pass", "v2", Operator::Broker), // both slug to DB_PASS
        ]);
        assert!(dup.is_err(), "broker slug collision must be rejected");
    }

    #[test]
    fn detects_exact_value_with_name_as_entity() {
        let compiled = compile_secrets(vec![rule("api_key", "SECRET123", Operator::Hash)]).unwrap();
        assert_eq!(compiled[0].value(), "SECRET123");
        let dets = detect_secrets(&compiled, "use SECRET123 here", Surface::UserMessage);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "api_key");
        assert_eq!(dets[0].source, Source::Secret);
        assert_eq!(dets[0].secret_op, Some(Operator::Hash));
    }

    #[test]
    fn surface_filter_scopes_detection() {
        let compiled = compile_secrets(vec![SecretRule {
            name: "k".into(),
            value: SecretValue::new("ZZZ"),
            operator: Operator::Hash,
            case_sensitive: true,
            apply_to_surfaces: Some(HashSet::from([Surface::ToolResult])),
        }])
        .unwrap();
        assert!(detect_secrets(&compiled, "ZZZ", Surface::UserMessage).is_empty());
        assert_eq!(detect_secrets(&compiled, "ZZZ", Surface::ToolResult).len(), 1);
    }

    #[test]
    fn fingerprint_moves_with_value_but_not_with_identical_set() {
        let a = compile_secrets(vec![rule("k", "v1", Operator::Hash)]).unwrap();
        let b = compile_secrets(vec![rule("k", "v1", Operator::Hash)]).unwrap();
        let c = compile_secrets(vec![rule("k", "v2", Operator::Hash)]).unwrap();
        assert_eq!(secrets_fingerprint(&a), secrets_fingerprint(&b));
        assert_ne!(secrets_fingerprint(&a), secrets_fingerprint(&c));
    }
}
