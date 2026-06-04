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

#[derive(Clone, Debug)]
pub struct MaskOutcome {
    pub masked_text: String,
    /// Tokens minted in this `mask()` call.
    pub manifest: UnmaskManifest,
}
