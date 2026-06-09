//! Registration-time classifier — the anti-over-masking gate. Decides whether a
//! candidate (name, value) is eligible to register as a secret, and defaults its
//! operator by entropy. `shannon_entropy` is duplicated here (no shared crate, per
//! the brief). Refuses booleans / integers / too-short / low-entropy values so the
//! engine never floods the transcript with masks for `DEBUG=true` / `PORT=8080`.

use std::sync::OnceLock;

use regex::Regex;
use zlauder_engine::Operator;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EligibleReason {
    NameMatch,
    Entropy,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    Empty,
    TooShort,
    LowEntropy,
    BooleanLike,
    IntegerLike,
    EnumLike,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Eligibility {
    /// Eligible to register; `operator` is the entropy-defaulted choice (overridable
    /// by an explicit config `operator =`). High-entropy ⇒ `Hash` (fingerprint
    /// harmless, referenceable); low-entropy ⇒ `Redact` (no confirmation oracle).
    Eligible {
        reason: EligibleReason,
        operator: Operator,
    },
    Skip(SkipReason),
}

fn name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|KEY|CREDENTIAL|DSN|PRIVATE|AUTH|BEARER)")
            .expect("valid name regex")
    })
}

/// Minimum length + entropy for the entropy path (a name match bypasses both).
const MIN_LEN: usize = 8;
const ENTROPY_FLOOR: f64 = 3.5;
/// Operator default boundary: at/above this, `Hash`; below, `Redact`.
const HASH_ENTROPY: f64 = 4.0;

pub fn classify(name: &str, value: &str) -> Eligibility {
    if value.is_empty() {
        return Eligibility::Skip(SkipReason::Empty);
    }
    if is_boolean_like(value) {
        return Eligibility::Skip(SkipReason::BooleanLike);
    }
    if is_integer_like(value) {
        return Eligibility::Skip(SkipReason::IntegerLike);
    }
    // Reject short all-alphabetic enum/mode values (e.g. AUTH_MODE=oauth) BEFORE the
    // name gate — a real secret of this length almost always carries digits/symbols/
    // mixed case, so a short all-alpha token is a config value, not a secret, even
    // when the NAME matches.
    if is_enum_like(value) {
        return Eligibility::Skip(SkipReason::EnumLike);
    }
    let name_match = name_re().is_match(name);
    let ent = shannon_entropy(value);
    let entropy_match = value.len() >= MIN_LEN && ent >= ENTROPY_FLOOR;

    if name_match || entropy_match {
        let reason = match (name_match, entropy_match) {
            (true, true) => EligibleReason::Both,
            (true, false) => EligibleReason::NameMatch,
            (false, _) => EligibleReason::Entropy,
        };
        let operator = if ent >= HASH_ENTROPY {
            Operator::Hash
        } else {
            Operator::Redact
        };
        return Eligibility::Eligible { reason, operator };
    }

    if value.len() < MIN_LEN {
        Eligibility::Skip(SkipReason::TooShort)
    } else {
        Eligibility::Skip(SkipReason::LowEntropy)
    }
}

fn is_boolean_like(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "1" | "0" | "enabled" | "disabled"
    )
}

fn is_integer_like(v: &str) -> bool {
    let t = v.trim();
    !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())
}

/// A short, all-alphabetic token (e.g. "oauth", "us", "abcdefg") — an enum / mode
/// value, not a secret. Rejected even when the NAME matches.
fn is_enum_like(v: &str) -> bool {
    v.len() < MIN_LEN && !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Byte-level Shannon entropy (bits/byte).
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_db_password_rejects_port_and_bool() {
        assert!(matches!(
            classify("DB_PASSWORD", "hunter2!xQ"),
            Eligibility::Eligible { .. }
        ));
        assert!(matches!(
            classify("PORT", "8080"),
            Eligibility::Skip(SkipReason::IntegerLike)
        ));
        assert!(matches!(
            classify("DEBUG", "true"),
            Eligibility::Skip(SkipReason::BooleanLike)
        ));
        assert!(matches!(
            classify("REGION", "us"),
            Eligibility::Skip(SkipReason::EnumLike)
        ));
        assert!(matches!(
            classify("AUTH_MODE", "oauth"),
            Eligibility::Skip(SkipReason::EnumLike)
        ));
        // A long, low-variety value that is not enum-like still skips on entropy.
        assert!(matches!(
            classify("NOTE", "aaaaaaaa1"),
            Eligibility::Skip(SkipReason::LowEntropy)
        ));
    }

    #[test]
    fn name_match_bypasses_entropy() {
        // Not enum-like (has digits) and below the entropy floor, but the name says
        // SECRET ⇒ eligible by NameMatch.
        assert!(matches!(
            classify("API_SECRET", "ab12cd34"),
            Eligibility::Eligible {
                reason: EligibleReason::NameMatch,
                ..
            }
        ));
        // ...but a short all-alphabetic value is enum-like and rejected even with a
        // matching name (the F4 fix).
        assert!(matches!(
            classify("API_SECRET", "abcdefg"),
            Eligibility::Skip(SkipReason::EnumLike)
        ));
    }

    #[test]
    fn operator_defaults_by_entropy() {
        // High-entropy random ⇒ Hash.
        match classify("OPAQUE", "k7Lm2Nq9Rp4StUvWxYz0aBcD1eF") {
            Eligibility::Eligible { operator, .. } => assert_eq!(operator, Operator::Hash),
            other => panic!("expected Eligible, got {other:?}"),
        }
        // Low-entropy but name-matched ⇒ Redact (kills the confirmation oracle).
        match classify("PASSWORD", "aaaaaaaa") {
            Eligibility::Eligible { operator, .. } => assert_eq!(operator, Operator::Redact),
            other => panic!("expected Eligible, got {other:?}"),
        }
    }
}
