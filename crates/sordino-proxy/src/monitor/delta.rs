//! Per-turn context delta.
//!
//! Claude Code resends the entire growing conversation every turn. To spare the
//! reviewer from re-reading the whole transcript, we compute which request
//! surfaces are NEW this turn vs the previous turn of the same conversation,
//! keyed by surface `block_hash`.
//!
//! The delta answers exactly one question: "what NEW content does the reviewer
//! have to vet for masking this turn?" The previous turn's baseline therefore
//! includes not only that turn's REQUEST surfaces but also the model REPLY we
//! captured for it (`response_surfaces`): the reply we produced under the masker's
//! nose is re-hydrated tokens the reviewer already vetted, so when Claude Code
//! echoes it back in the next request it is NOT new and must not re-surface as
//! delta (nor re-pollute the NEW-PII signal). The reply is matched in its EGRESS
//! form (see [`egress_hash`]) because the request carries it re-masked.
//!
//! Crucially the fold is scoped to replies WE captured. Assistant content the
//! masker never saw — a resumed/imported/injected transcript whose prior reply was
//! produced elsewhere — has no captured response to fold, so it stays in the delta
//! and is reviewed: such content can carry un-masked PII that retroactively ought
//! to be masked, and hiding it is the one thing a masking-review tool must never do.

use std::collections::HashSet;

use super::model::{Surface, TurnDelta};
use super::surfaces::egress_hash;

/// Compute the delta for `current` request surfaces against the previous turn.
/// `previous` is `(prev_turn, prev_request_surfaces, prev_response_surfaces)`:
/// the baseline is the union of the prior request's `block_hash`es and the prior
/// CAPTURED reply's [`egress_hash`]es (its re-masked form, which is how the reply
/// reappears in this turn's request).
///
/// When `previous` is `None`, this is the first turn: `is_first = true` and no
/// added hashes are reported (the whole turn is implicitly new).
pub(crate) fn compute_delta(
    current: &[Surface],
    previous: Option<(u32, &[Surface], &[Surface])>,
) -> TurnDelta {
    let Some((prev_turn, prev_request, prev_response)) = previous else {
        return TurnDelta::first();
    };

    // Baseline: prior request surfaces (already in egress/masked form, so their
    // block_hash IS the egress hash) plus the captured reply folded in its egress
    // form so the echoed reply matches and drops out.
    let mut prev_hashes: HashSet<String> =
        prev_request.iter().map(|s| s.block_hash.clone()).collect();
    prev_hashes.extend(prev_response.iter().map(egress_hash));

    let mut seen = HashSet::new();
    let mut added = Vec::new();
    for s in current {
        if prev_hashes.contains(&s.block_hash) {
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

    fn assistant_surface(hash: &str) -> Surface {
        Surface {
            label: hash.to_string(),
            role: Some("assistant".to_string()),
            kind: "message".to_string(),
            provenance: "assistant".to_string(),
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
        // Previous turn had a, b. New turn resends a, b and adds c. No captured reply.
        let prev = vec![surface("a"), surface("b")];
        let cur = vec![surface("a"), surface("b"), surface("c")];
        let d = compute_delta(&cur, Some((1, &prev, &[])));
        assert!(!d.is_first);
        assert_eq!(d.prev_turn, Some(1));
        assert_eq!(d.added_surface_hashes, vec!["c".to_string()]);
    }

    #[test]
    fn captured_reply_folds_out_of_next_delta() {
        // Turn N: request [a], and WE CAPTURED reply [r]. Turn N+1 resends
        // [a, r (the echoed reply), b]. Only the genuinely-new inbound `b` is delta —
        // the reply `r` is folded out because it is in the captured response baseline.
        let prev_req = vec![surface("a")];
        let prev_resp = vec![surface("r")]; // a no-token reply: egress_hash == block_hash
        let cur = vec![surface("a"), surface("r"), surface("b")];
        let d = compute_delta(&cur, Some((1, &prev_req, &prev_resp)));
        assert_eq!(d.added_surface_hashes, vec!["b".to_string()]);
        assert!(
            !d.added_surface_hashes.contains(&"r".to_string()),
            "a reply we captured must fold out of the following turn's delta"
        );
    }

    #[test]
    fn uncaptured_assistant_content_still_shows() {
        // Resumed/imported/injected transcript: turn N+1 carries assistant content `x`
        // we NEVER captured (no matching response in the baseline). It MUST stay in the
        // delta — it can hold un-masked PII that retroactively ought to be masked, and a
        // masking-review tool must never hide it.
        let prev_req = vec![surface("a")];
        let prev_resp: Vec<Surface> = vec![]; // nothing captured this turn
        let cur = vec![surface("a"), assistant_surface("x")];
        let d = compute_delta(&cur, Some((1, &prev_req, &prev_resp)));
        assert_eq!(
            d.added_surface_hashes,
            vec!["x".to_string()],
            "assistant content the masker never saw must remain reviewable"
        );
    }

    #[test]
    fn delta_dedups_repeated_new_surface() {
        let prev = vec![surface("a")];
        let cur = vec![surface("a"), surface("c"), surface("c")];
        let d = compute_delta(&cur, Some((2, &prev, &[])));
        assert_eq!(d.added_surface_hashes, vec!["c".to_string()]);
    }
}
