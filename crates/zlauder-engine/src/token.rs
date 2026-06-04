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
