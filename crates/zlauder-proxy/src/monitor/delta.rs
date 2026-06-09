//! Per-turn context delta.
//!
//! Claude Code resends the entire growing conversation every turn. To spare the
//! reviewer from re-reading the whole transcript, we compute which request
//! surfaces are NEW this turn vs the previous turn of the same conversation,
//! keyed by surface `block_hash`.

use std::collections::HashSet;

use super::model::{Surface, TurnDelta};

/// Compute the delta for `current` surfaces against the `previous` turn's
/// surfaces. `prev_turn` is the 1-based turn index of that previous turn.
///
/// When `previous` is `None`, this is the first turn: `is_first = true` and no
/// added hashes are reported (the whole turn is implicitly new).
pub(crate) fn compute_delta(current: &[Surface], previous: Option<(u32, &[Surface])>) -> TurnDelta {
    let Some((prev_turn, prev_surfaces)) = previous else {
        return TurnDelta::first();
    };

    let prev_hashes: HashSet<&str> = prev_surfaces
        .iter()
        .map(|s| s.block_hash.as_str())
        .collect();

    let mut seen = HashSet::new();
    let mut added = Vec::new();
    for s in current {
        if prev_hashes.contains(s.block_hash.as_str()) {
            continue;
        }
        // De-duplicate identical new surfaces within the same turn.
        if seen.insert(s.block_hash.as_str()) {
            added.push(s.block_hash.clone());
        }
    }

    TurnDelta {
        prev_turn: Some(prev_turn),
        is_first: false,
        prev_unavailable: false,
        added_surface_hashes: added,
    }
}

/// Compute the delta when only the previous turn's surface `block_hash`es are
/// available (its full record was evicted from the ring, but the hashes were
/// cached). Equivalent to [`compute_delta`] but keyed off hashes alone.
pub(crate) fn compute_delta_from_hashes(
    current: &[Surface],
    prev_turn: u32,
    prev_hashes: &[String],
) -> TurnDelta {
    let prev: HashSet<&str> = prev_hashes.iter().map(String::as_str).collect();

    let mut seen = HashSet::new();
    let mut added = Vec::new();
    for s in current {
        if prev.contains(s.block_hash.as_str()) {
            continue;
        }
        if seen.insert(s.block_hash.as_str()) {
            added.push(s.block_hash.clone());
        }
    }

    TurnDelta {
        prev_turn: Some(prev_turn),
        is_first: false,
        prev_unavailable: false,
        added_surface_hashes: added,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::model::Run;

    fn surface(hash: &str) -> Surface {
        Surface {
            label: hash.to_string(),
            role: None,
            kind: "message".to_string(),
            provenance: "user_input".to_string(),
            runs: vec![Run {
                text: hash.to_string(),
                token: None,
            }],
            block_hash: hash.to_string(),
        }
    }

    #[test]
    fn first_turn_is_marked_first() {
        let cur = vec![surface("a"), surface("b")];
        let d = compute_delta(&cur, None);
        assert!(d.is_first);
        assert_eq!(d.prev_turn, None);
        assert!(d.added_surface_hashes.is_empty());
    }

    #[test]
    fn delta_detects_added_surface() {
        // Previous turn had a, b. New turn resends a, b and adds c.
        let prev = vec![surface("a"), surface("b")];
        let cur = vec![surface("a"), surface("b"), surface("c")];
        let d = compute_delta(&cur, Some((1, &prev)));
        assert!(!d.is_first);
        assert_eq!(d.prev_turn, Some(1));
        assert_eq!(d.added_surface_hashes, vec!["c".to_string()]);
    }

    #[test]
    fn delta_from_hashes_matches_full_compare() {
        let prev = [surface("a"), surface("b")];
        let cur = vec![surface("a"), surface("b"), surface("c")];
        let prev_hashes: Vec<String> = prev.iter().map(|s| s.block_hash.clone()).collect();
        let d = compute_delta_from_hashes(&cur, 1, &prev_hashes);
        assert!(!d.is_first);
        assert!(!d.prev_unavailable);
        assert_eq!(d.prev_turn, Some(1));
        assert_eq!(d.added_surface_hashes, vec!["c".to_string()]);
    }

    #[test]
    fn delta_dedups_repeated_new_surface() {
        let prev = vec![surface("a")];
        let cur = vec![surface("a"), surface("c"), surface("c")];
        let d = compute_delta(&cur, Some((2, &prev)));
        assert_eq!(d.added_surface_hashes, vec!["c".to_string()]);
    }
}
