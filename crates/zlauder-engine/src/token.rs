//! Deterministic session-salted token minting (ported from orchestr8-privacy `make_token`).

use regex::Regex;
use std::sync::OnceLock;

/// Number of hex chars of the blake3 digest kept in a token (48 bits).
pub const TOKEN_HASH_HEX_LEN: usize = 12;

/// `[ENTITY_TYPE_xxxxxxxxxxxx]` where the suffix is
/// `blake3(salt || entity_type || ":" || plaintext)[..12 hex]`.
///
/// Idempotent within a session: the same `(salt, entity_type, plaintext)` always
/// yields the same token, which is what keeps Anthropic prompt-cache prefixes
/// byte-stable across turns.
pub fn make_token(entity_type: &str, plaintext: &str, salt: &[u8; 16]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(salt);
    h.update(entity_type.as_bytes());
    h.update(b":");
    h.update(plaintext.as_bytes());
    let hex = h.finalize().to_hex();
    let suffix: String = hex.as_str().chars().take(TOKEN_HASH_HEX_LEN).collect();
    format!("[{}_{suffix}]", entity_type.to_uppercase())
}

/// Irreversible `Hash` operator rendering: `[ENTITY_TYPE:xxxxxxxxxxxx]`.
pub fn hash_value(entity_type: &str, plaintext: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(plaintext.as_bytes());
    let hex = h.finalize().to_hex();
    let suffix: String = hex.as_str().chars().take(TOKEN_HASH_HEX_LEN).collect();
    format!("[{}:{suffix}]", entity_type.to_uppercase())
}

/// SALTED irreversible `Hash` rendering for a *registered secret*:
/// `[ENTITY:xxxxxxxxxxxx]` where the suffix is `blake3(salt ‖ entity ‖ ":" ‖
/// plaintext)[..12 hex]`. Colon form ⇒ outside [`token_regex`] ⇒ never scanned by
/// unmask (structurally unrevealable). Distinct from [`hash_value`] (bare, unsalted)
/// which stays for auto-PII `Hash`: the salt makes the 48-bit fingerprint
/// deterministic *within a project* (prompt-cache stable) but not a cross-project
/// confirmation oracle for a low-entropy secret.
pub fn make_hash_token(entity_type: &str, plaintext: &str, salt: &[u8; 16]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(salt);
    h.update(entity_type.as_bytes());
    h.update(b":");
    h.update(plaintext.as_bytes());
    let hex = h.finalize().to_hex();
    let suffix: String = hex.as_str().chars().take(TOKEN_HASH_HEX_LEN).collect();
    format!("[{}:{suffix}]", entity_type.to_uppercase())
}

/// Self-identifying prefix on a broker token's entity (`[BROKER__SLUG_<hex>]`).
pub const BROKER_PREFIX: &str = "BROKER__";

/// True iff `token` is a broker token (`[BROKER__…_<hex>]`). A cheap, lock-free
/// classifier used by the on-wire skip and the display-refusal gate. Checks the
/// rendered form (`[` + uppercased prefix), so it matches what [`make_token`] emits.
pub fn is_broker_token(token: &str) -> bool {
    token.starts_with("[BROKER__")
}

/// Normalize a registered secret name into a token-grammar-safe slug: ASCII
/// alphanumerics uppercased, everything else `_`, truncated to a bounded length so
/// the full `[BROKER__<slug>_<hex>]` token stays within [`MAX_TOKEN_LEN`]. This is
/// COSMETIC only — the `StoreEntry` carries the exact registered name as the policy
/// authority (the slug is never parsed back). Uniqueness across registered secrets
/// is enforced at registration (`secrets::compile_secrets`), so a slug collision is
/// a config error, never a silent policy mismatch.
pub fn slugify(name: &str) -> String {
    /// Keep `BROKER__` (8) + slug + `_` + 12 hex + brackets under `MAX_TOKEN_LEN`
    /// (entity budget is 48; `BROKER__` eats 8, so cap the slug at 32 with margin).
    const MAX_SLUG: usize = 32;
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if s.len() > MAX_SLUG {
        s.truncate(MAX_SLUG);
    }
    if s.is_empty() {
        s.push('_');
    }
    s
}

/// Recognizes standard zlauder tokens: `[A-Z0-9_]+_[0-9a-f]{12}` inside brackets.
/// Used by the proxy SSE buffer to find token boundaries that may straddle deltas.
pub fn token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[A-Z0-9_]+_[0-9a-f]{12}\]").expect("valid token regex"))
}

/// Longest plausible standard token in bytes: `[` + entity (<=48) + `_` + 12 hex + `]`.
/// The SSE carry buffer releases any held `[`-prefixed run longer than this as
/// non-token prose, preventing an unbounded stall on a stray `[`.
pub const MAX_TOKEN_LEN: usize = 1 + 48 + 1 + TOKEN_HASH_HEX_LEN + 1;
