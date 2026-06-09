//! Legacy byte-offset span computation for the raw "Full Masked Request" and
//! response previews, plus shared preview/token helpers.
//!
//! New UI rendering uses pre-segmented [`super::model::Surface`]/`Run` (see
//! [`super::surfaces`]); this module is retained only for the raw preview views
//! and the existing span integration tests.

use std::time::{SystemTime, UNIX_EPOCH};

use zlauder_engine::UnmaskManifest;

use super::model::{PreviewSpan, TokenClass, TokenPreview};

pub(crate) const PREVIEW_LIMIT: usize = 128 * 1024;

/// Build [`TokenPreview`]s from a manifest, carrying the canonical plaintext,
/// entity kind and arrow origin used to fill [`super::model::TokenRef`].
pub(crate) fn token_previews(manifest: &UnmaskManifest) -> Vec<TokenPreview> {
    manifest
        .entries
        .iter()
        .map(|e| {
            // Mirror the ledger's structural redaction: withhold plaintext for a
            // non-peekable (secret-class) token so it never rides a record/SSE frame.
            // CVV is the live non-peekable case here ([`TokenClass::Sad`], mirroring the
            // ledger guard): its plaintext is withheld from this per-record/SSE preview
            // surface too. Ordinary detector/keyword PII stays AutoPii ⇒ peekable.
            let class = TokenClass::for_manifest_entry(e);
            let peekable = class.is_peekable();
            TokenPreview {
                token: e.token_handle.clone(),
                value: if peekable {
                    e.canonical_form.clone()
                } else {
                    String::new()
                },
                entity_kind: e.entity_kind.clone(),
                surface: format!("{:?}", e.arrow_origin),
                request_start: e.exposed_at.as_ref().map(|r| r.start),
                request_end: e.exposed_at.as_ref().map(|r| r.end),
                class,
                peekable,
            }
        })
        .collect()
}

/// Spans derived from the engine-reported byte offsets of each token handle.
pub(crate) fn spans_from_manifest(manifest: &UnmaskManifest, preview: &str) -> Vec<PreviewSpan> {
    let mut spans: Vec<PreviewSpan> = manifest
        .entries
        .iter()
        .filter_map(|e| {
            let r = e.exposed_at.as_ref()?;
            if r.start >= r.end || r.end > preview.len() {
                return None;
            }
            Some(PreviewSpan {
                start: r.start,
                end: r.end,
                token: e.token_handle.clone(),
                entity_kind: e.entity_kind.clone(),
                surface: format!("{:?}", e.arrow_origin),
            })
        })
        .collect();
    spans.sort_by_key(|s| (s.start, s.end));
    spans
}

/// Spans located by searching for each token's plaintext value in `preview`.
/// Used for the response preview, where engine offsets are not available.
pub(crate) fn spans_from_values(tokens: &[TokenPreview], preview: &str) -> Vec<PreviewSpan> {
    let mut spans = Vec::new();
    for t in tokens {
        if t.value.is_empty() {
            continue;
        }
        let mut search_from = 0;
        while search_from < preview.len() {
            let Some(rel) = preview[search_from..].find(&t.value) else {
                break;
            };
            let start = search_from + rel;
            let end = start + t.value.len();
            spans.push(PreviewSpan {
                start,
                end,
                token: t.token.clone(),
                entity_kind: t.entity_kind.clone(),
                surface: t.surface.clone(),
            });
            search_from = end;
        }
    }
    spans.sort_by_key(|s| (s.start, s.end));
    dedupe_overlapping_spans(spans)
}

/// Drop any span that overlaps an earlier-kept span (first-wins).
pub(crate) fn dedupe_overlapping_spans(spans: Vec<PreviewSpan>) -> Vec<PreviewSpan> {
    let mut out: Vec<PreviewSpan> = Vec::new();
    for span in spans {
        if out.iter().any(|s| span.start < s.end && s.start < span.end) {
            continue;
        }
        out.push(span);
    }
    out
}

/// Lossy UTF-8 preview of a body, clipped to [`PREVIEW_LIMIT`] bytes.
pub(crate) fn preview(body: &[u8]) -> String {
    let clipped = if body.len() > PREVIEW_LIMIT {
        &body[..PREVIEW_LIMIT]
    } else {
        body
    };
    let mut s = String::from_utf8_lossy(clipped).to_string();
    if body.len() > PREVIEW_LIMIT {
        s.push_str("\n...[truncated]");
    }
    s
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
