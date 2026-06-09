//! Per-call unmask manifest (ported from orchestr8-privacy, ephemeral / never serialized).

use smallvec::SmallVec;
use std::ops::Range;
use uuid::Uuid;

use crate::surface::Surface;

#[derive(Clone, Debug)]
pub struct ManifestEntry {
    /// The original plaintext.
    pub canonical_form: String,
    /// The `[ENTITY_xxx]` token substituted in its place.
    pub token_handle: String,
    pub entity_kind: String,
    /// Which mask arrow produced this token.
    pub arrow_origin: Surface,
    /// Byte span of the token in the masked text (audit only).
    pub exposed_at: Option<Range<usize>>,
    /// True iff this is a BROKER token (`Operator::Broker`): the value is resolvable
    /// only at the tool-input boundary, never on display. The monitor reads this to
    /// suppress the value from any `TokenPreview`, and the display unmask refuses it.
    pub broker: bool,
}

#[derive(Clone, Debug)]
pub struct UnmaskManifest {
    pub call_id: Uuid,
    pub entries: SmallVec<[ManifestEntry; 8]>,
}

impl Default for UnmaskManifest {
    fn default() -> Self {
        Self::new()
    }
}

impl UnmaskManifest {
    pub fn new() -> Self {
        Self {
            call_id: Uuid::new_v4(),
            entries: SmallVec::new(),
        }
    }

    /// Accumulate entries from another manifest (one request masks many fields).
    pub fn merge(&mut self, other: UnmaskManifest) {
        self.entries.extend(other.entries);
    }

    pub fn push(&mut self, entry: ManifestEntry) {
        self.entries.push(entry);
    }

    /// First plaintext registered for `token`, if any.
    pub fn lookup(&self, token: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.token_handle == token)
            .map(|e| e.canonical_form.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Per-`mask()`-call detection-cache instrumentation (Component 2). Exactly one
/// leaf per `mask()` call, so each field is 0/1 there; `MaskWalker` sums them
/// across a request's leaves and logs once (the falsifiable `fresh_misses`
/// observable for the caching win). Definitions (audit #12):
/// - `leaves`: leaves that reached `mask()` (incl. disabled passthroughs).
/// - `hit`: served from cache (incl. a single-flight gate re-check hit).
/// - `fresh_miss`: ran `run_detection` successfully (its result is now cached).
/// - `ml_ran`: the ML recognizer was consulted on this leaf (⊆ misses).
/// - `fail_open`: deprecated; detection errors now refuse the request.
/// - `disabled`: master-switch-off / surface-disabled passthrough (no detection).
#[derive(Clone, Copy, Debug, Default)]
pub struct MaskStats {
    pub leaves: u32,
    pub hit: u32,
    pub fresh_miss: u32,
    pub ml_ran: u32,
    pub fail_open: u32,
    pub disabled: u32,
}

impl MaskStats {
    /// Stats for an un-detected passthrough leaf (master off / surface disabled).
    pub fn disabled() -> Self {
        Self {
            leaves: 1,
            disabled: 1,
            ..Default::default()
        }
    }

    /// Accumulate another leaf's stats (one request masks many leaves).
    pub fn merge(&mut self, o: &MaskStats) {
        self.leaves += o.leaves;
        self.hit += o.hit;
        self.fresh_miss += o.fresh_miss;
        self.ml_ran += o.ml_ran;
        self.fail_open += o.fail_open;
        self.disabled += o.disabled;
    }
}

#[derive(Clone, Debug)]
pub struct MaskOutcome {
    pub masked_text: String,
    /// Tokens minted in this `mask()` call.
    pub manifest: UnmaskManifest,
    /// Detection-cache instrumentation for this call.
    pub stats: MaskStats,
}

impl MaskOutcome {
    /// A transparent passthrough outcome (text unchanged, empty manifest) carrying
    /// the given stats.
    pub fn passthrough(text: &str, stats: MaskStats) -> Self {
        Self {
            masked_text: text.to_string(),
            manifest: UnmaskManifest::new(),
            stats,
        }
    }
}
