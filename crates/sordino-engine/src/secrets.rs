//! Registered-secret channel: exact-literal Pass-0 detection over known secret
//! values.
//!
//! Secrets are held OFF [`crate::config::EngineConfig`] (never serialized) so a
//! value can't leak into `WireConfig` / `GET /sordino/config` / the monitor. Values
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
    /// Tier-2 base64-needle matcher (case-significant), or `None` when every needle
    /// fell below [`MIN_NEEDLE_CHARS`]. Only consulted by the encoded-ON byte scan.
    encoded: Option<AhoCorasick>,
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
        // Tier-2: build a case-SIGNIFICANT matcher over the secret's base64 needles
        // (base64 is case-significant, so `ascii_case_insensitive(false)` UNCONDITIONALLY;
        // the secret's `case_sensitive` governs the Tier-1 plaintext matcher only). None
        // when every needle fell below the min-length floor (short-secret FP guard).
        let needles = base64_needles(r.value.expose().as_bytes());
        let encoded = if needles.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .ascii_case_insensitive(false)
                    .build(&needles)
                    .map_err(|e| EngineError::InvalidSecret(format!("secret {:?}: {e}", r.name)))?,
            )
        };
        out.push(CompiledSecret {
            name: r.name,
            operator: r.operator,
            value_hash,
            matcher,
            encoded,
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
    h.update(b"sordino-secrets-fp-v1");
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

/// Like [`detect_secrets`] but IGNORES each secret's `apply_to_surfaces` scoping.
/// Used where the scanned text sits on no well-defined surface (the schema/contract
/// carve-out subtrees the proxy never rewrites, and the `>>…<<` user-bypass span):
/// an operator's surface-scoping must not silently reopen those exfil channels. Every
/// registered secret is matched regardless of its surfaces; matches are otherwise
/// identical to [`detect_secrets`] (`Source::Secret`, `score 1.0`, `secret_op` set,
/// registered name as `entity_type`, tier-0 exact-literal).
pub fn detect_secrets_unscoped(compiled: &[CompiledSecret], text: &str) -> Vec<CachedDetection> {
    let mut dets = Vec::new();
    for c in compiled {
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

/// Refuse-only boolean byte-scan over the installed secret set. `true` on the first
/// registered secret whose exact plaintext (Tier-1) appears in `bytes`; when
/// `include_encoded` is set, ALSO on the first secret whose base64 needle (Tier-2)
/// appears. IGNORES each secret's `apply_to_surfaces` (a non-walked egress surface has
/// no [`Surface`]) and applies NO Tier-1 length floor — a short registered secret that
/// matches a large body MUST refuse, since a floor there would be a fail-OPEN leak.
/// Empty set ⇒ `false`. Pure predicate: mints no `EngineError`, the 409 is the proxy's.
pub fn secret_hit_bytes(set: &SecretSet, bytes: &[u8], include_encoded: bool) -> bool {
    for c in &set.compiled {
        if c.matcher.is_match(bytes) {
            return true;
        }
        if include_encoded && c.encoded.as_ref().is_some_and(|e| e.is_match(bytes)) {
            return true;
        }
    }
    false
}

/// Minimum trimmed base64-needle length: below this a base64 needle is dropped, so a
/// short secret can't spray false positives across arbitrary base64 blobs.
pub(crate) const MIN_NEEDLE_CHARS: usize = 16;

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Hand-rolled no-padding base64 encoder over a 64-char alphabet table (no base64
/// crate dep). ASCII output.
fn b64_encode_nopad(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32;
        out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3f) as usize] as char);
        out.push(alphabet[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
            out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = (rem[0] as u32) << 16 | (rem[1] as u32) << 8;
            out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
            out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
            out.push(alphabet[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

/// Tier-2 needle set for `value`: the interior base64 chars that appear verbatim when
/// `value` is embedded inside a larger base64 blob, across both alphabets
/// ({STANDARD, URL_SAFE}, no padding) and all three byte alignments (0/1/2 bytes of
/// preceding data). For each (alphabet, prefix_len): encode `[0u8; prefix_len] ++ value`,
/// then drop the `lead` boundary-straddling chars from the front and `trail` from the
/// back so the needle is alignment-independent; keep only if `>= MIN_NEEDLE_CHARS`.
/// Deduped, deterministic order. Base64 output is ASCII, so byte-index slicing is safe.
pub(crate) fn base64_needles(value: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for alphabet in [B64_STD, B64_URL] {
        for prefix_len in 0usize..=2 {
            let mut buf = vec![0u8; prefix_len];
            buf.extend_from_slice(value);
            let encoded = b64_encode_nopad(&buf, alphabet);
            let lead = (8 * prefix_len + 5) / 6;
            let trail = if (8 * (prefix_len + value.len())) % 6 == 0 {
                0
            } else {
                1
            };
            if encoded.len() < lead + trail {
                continue;
            }
            let trimmed = &encoded[lead..encoded.len() - trail];
            if trimmed.len() >= MIN_NEEDLE_CHARS && !out.iter().any(|n| n == trimmed) {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

fn operator_tag(op: Operator) -> u8 {
    match op {
        Operator::Token => 0,
        Operator::Redact => 1,
        Operator::Mask { .. } => 2,
        Operator::Hash => 3,
        Operator::Broker => 4,
        Operator::Keep => 5,
        Operator::Local => 6,
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

    fn set_of(rules: Vec<SecretRule>) -> SecretSet {
        let compiled = compile_secrets(rules).unwrap();
        let secrets_fp = secrets_fingerprint(&compiled);
        SecretSet {
            compiled,
            secrets_fp,
        }
    }

    // Embed `value` inside a real base64 blob at `prefix_len` bytes of (non-zero)
    // preceding data plus trailing data, over the given alphabet.
    fn embed_b64(value: &[u8], prefix_len: usize, alphabet: &[u8; 64]) -> String {
        let mut blob = vec![0x11u8, 0x22, 0x33][..prefix_len].to_vec();
        blob.extend_from_slice(value);
        blob.extend_from_slice(&[0x44, 0x55, 0x66]);
        b64_encode_nopad(&blob, alphabet)
    }

    #[test]
    fn a0_1_tier1_plaintext_hit() {
        let set = set_of(vec![rule("k", "sk-live-9f8e7d6c5b4a", Operator::Hash)]);
        assert!(secret_hit_bytes(
            &set,
            b"authorization: bearer sk-live-9f8e7d6c5b4a trailing",
            true
        ));
    }

    #[test]
    fn a0_2_clean_bytes_no_hit() {
        let set = set_of(vec![rule("k", "sk-live-9f8e7d6c5b4a", Operator::Hash)]);
        assert!(!secret_hit_bytes(&set, b"nothing sensitive in this body", true));
    }

    #[test]
    fn a0_3_base64_embedded_all_alignments_hit() {
        let secret = b"sk-live-9f8e7d6c5b4a";
        let set = set_of(vec![rule("k", "sk-live-9f8e7d6c5b4a", Operator::Hash)]);
        for prefix_len in 0..=2 {
            for alphabet in [B64_STD, B64_URL] {
                let blob = embed_b64(secret, prefix_len, alphabet);
                assert!(
                    secret_hit_bytes(&set, blob.as_bytes(), true),
                    "alignment {prefix_len} must hit with include_encoded=true"
                );
            }
        }
    }

    #[test]
    fn a0_4_base64_needles_contains_pinned() {
        let n = base64_needles(b"sk-live-9f8e7d6c5b4a");
        assert!(
            n.iter().any(|s| s == "c2stbGl2ZS05ZjhlN2Q2YzViNG"),
            "needles: {n:?}"
        );
    }

    #[test]
    fn a0_5_base64_embedded_header_exact_only_no_hit() {
        let secret = b"sk-live-9f8e7d6c5b4a";
        let set = set_of(vec![rule("k", "sk-live-9f8e7d6c5b4a", Operator::Hash)]);
        let blob = embed_b64(secret, 0, B64_STD);
        // include_encoded=false is the header exact-only tier: Tier-2 must not fire.
        assert!(!secret_hit_bytes(&set, blob.as_bytes(), false));
    }

    #[test]
    fn a0_6_short_secret_base64_embedded_no_hit() {
        assert!(
            base64_needles(b"abcd").is_empty(),
            "4-byte secret must yield no needle above the min floor"
        );
        let set = set_of(vec![rule("k4", "abcd", Operator::Hash)]);
        let blob = embed_b64(b"abcd", 1, B64_STD);
        assert!(
            !secret_hit_bytes(&set, blob.as_bytes(), true),
            "short-secret base64 FP guard must hold"
        );
    }

    #[test]
    fn a0_7_empty_set_large_buffer_no_panic() {
        let set = SecretSet::empty();
        let big = vec![0x41u8; 4 * 1024 * 1024];
        assert!(!secret_hit_bytes(&set, &big, true));
    }

    #[test]
    fn a0_8_dual_alphabet_distinct_needles() {
        let n = base64_needles(b"secret????>>>>@@@@1234");
        assert!(
            n.iter().any(|s| s == "c2VjcmV0Pz8/Pz4+Pj5AQEBAMTIzN"),
            "std needle missing: {n:?}"
        );
        assert!(
            n.iter().any(|s| s == "c2VjcmV0Pz8_Pz4-Pj5AQEBAMTIzN"),
            "url-safe needle missing: {n:?}"
        );
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
