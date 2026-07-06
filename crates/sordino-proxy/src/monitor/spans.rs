//! Legacy byte-offset span computation for the raw "Full Masked Request" and
//! response previews, plus shared preview/token helpers.
//!
//! New UI rendering uses pre-segmented [`super::model::Surface`]/`Run` (see
//! [`super::surfaces`]); this module is retained only for the raw preview views
//! and the existing span integration tests.

use std::time::{SystemTime, UNIX_EPOCH};

use sordino_engine::UnmaskManifest;

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

/// The `(plaintext → handle)` re-mask pairs for every NON-peekable (secret-class) token
/// in `manifest` — CVV ([`TokenClass::Sad`]) and brokered secrets. A captured RESPONSE is
/// the reply forwarded to the client UNMASKED (the client owns the data), so its monitor
/// mirror would otherwise persist a secret plaintext the request side never exposes (the
/// request stores the masked handle; `token_previews` only withholds the *peek* value, it
/// cannot scrub already-unmasked text). Sorted longest-value-first so a value that is a
/// substring of another is replaced first. Brokered values never reach the display unmask
/// (it refuses them), so they cannot appear in a reply — included only as defense in depth.
pub(crate) fn redaction_pairs(manifest: &UnmaskManifest) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = manifest
        .entries
        .iter()
        .filter(|e| !TokenClass::for_manifest_entry(e).is_peekable())
        .filter(|e| !e.canonical_form.is_empty())
        .map(|e| (e.canonical_form.clone(), e.token_handle.clone()))
        .collect();
    pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    pairs
}

/// Replace every non-peekable plaintext value in `text` with its `[ENTITY_xxxx]` handle
/// (see [`redaction_pairs`]). A no-op (and allocation-cheap) when there are no secret-class
/// tokens — the common path. A value the engine resolved is whole within a single forwarded
/// fragment (display unmask never emits a partial value), so this can run per-fragment on a
/// stream without splitting a value. Over-redacts a coincidental verbatim collision with a
/// secret value — the SAFE direction for a monitor copy (the wire already carried the real
/// value to the client); peekable PII is left intact for re-hydration.
pub(crate) fn redact_secret_values(text: &str, pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return text.to_string();
    }
    let mut out = text.to_string();
    for (value, handle) in pairs {
        if out.contains(value.as_str()) {
            out = out.replace(value.as_str(), handle);
        }
    }
    out
}

/// [`redaction_pairs`] expanded with the JSON-string-escaped form of each value, for
/// scrubbing a SERIALIZED JSON body (the non-streaming `record_response` path): a value
/// containing a quote / backslash / control char appears in the body in its escaped form,
/// not raw, so the raw needle would miss it. The streaming path scrubs unmasked PLAINTEXT
/// fragments and so needs only [`redaction_pairs`]. Today's non-peekable classes are
/// escape-free (CVV is digits; brokered secrets never egress on the display path), so this
/// is defense-in-depth for any future escapable secret class. Longest-needle-first.
pub(crate) fn json_body_redaction_pairs(manifest: &UnmaskManifest) -> Vec<(String, String)> {
    json_body_expand(redaction_pairs(manifest))
}

/// Expand raw `(value, handle)` pairs into the json-body needle set: each value PLUS its
/// JSON-escaped form (so a value embedded in a serialized body is matched in the escaped
/// form the raw needle misses), longest-first. Shared by [`json_body_redaction_pairs`] and
/// the capture scrub's session-`Local` pairs.
pub(crate) fn json_body_expand(pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (value, handle) in pairs {
        if let Ok(json) = serde_json::to_string(&value) {
            // Strip the surrounding quotes serde adds, leaving the inner escaped form.
            let escaped = json[1..json.len().saturating_sub(1)].to_string();
            if escaped != value {
                out.push((escaped, handle.clone()));
            }
        }
        out.push((value, handle));
    }
    out.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use sordino_engine::{ENTITY_CVV, ManifestEntry, Surface};

    fn entry(value: &str, handle: &str, entity_kind: &str, broker: bool) -> ManifestEntry {
        ManifestEntry {
            canonical_form: value.into(),
            token_handle: handle.into(),
            entity_kind: entity_kind.into(),
            arrow_origin: Surface::UserMessage,
            exposed_at: None,
            broker,
            local: false,
        }
    }

    #[test]
    fn redaction_pairs_covers_secret_classes_only() {
        let mut m = UnmaskManifest::new();
        m.push(entry("joe@x.com", "[EMAIL_ADDRESS_aa]", "EMAIL_ADDRESS", false)); // peekable
        m.push(entry("987", "[CVV_bb]", ENTITY_CVV, false)); // non-peekable (Sad)
        m.push(entry("sk-secret", "[API_KEY_cc]", "API_KEY", true)); // non-peekable (Broker)
        let values: Vec<String> = redaction_pairs(&m).into_iter().map(|(v, _)| v).collect();
        assert!(values.contains(&"987".to_string()));
        assert!(values.contains(&"sk-secret".to_string()));
        assert!(
            !values.contains(&"joe@x.com".to_string()),
            "peekable PII must never be scrubbed (it is intentionally re-hydrated)"
        );
    }

    // A `Local` (owner-reveal) token is REVEALED on the display wire, but the monitor must
    // treat it non-peekable: its value is re-masked to the handle in the captured reply
    // (so the capture matches the re-masked re-send → the fold converges) and withheld
    // from the ledger preview.
    #[test]
    fn local_class_is_non_peekable_and_scrubbed() {
        let mut m = UnmaskManifest::new();
        let mut e = entry("0ee276deadbeef", "[SORDINO_ADMIN_KEY_aabbccddeeff]", "SORDINO_ADMIN_KEY", false);
        e.local = true;
        m.push(e);
        assert_eq!(
            TokenClass::for_manifest_entry(&m.entries[0]),
            TokenClass::Local
        );
        assert!(!TokenClass::Local.is_peekable(), "Local must be non-peekable");
        // In the capture redaction pairs (so a revealed reply is re-masked to the handle).
        let pairs = redaction_pairs(&m);
        assert!(
            pairs
                .iter()
                .any(|(v, h)| v == "0ee276deadbeef" && h == "[SORDINO_ADMIN_KEY_aabbccddeeff]"),
            "a Local value must be scrubbed back to its handle on the monitor copy"
        );
        // Ledger preview withholds the value.
        let prev = token_previews(&m);
        assert!(
            prev[0].value.is_empty(),
            "Local value must be withheld from the ledger preview"
        );
    }

    #[test]
    fn redact_scrubs_secret_value_keeps_peekable() {
        let mut m = UnmaskManifest::new();
        m.push(entry("joe@x.com", "[EMAIL_ADDRESS_aa]", "EMAIL_ADDRESS", false));
        m.push(entry("987", "[CVV_bb]", ENTITY_CVV, false));
        let pairs = redaction_pairs(&m);
        let scrubbed = redact_secret_values("mail joe@x.com cvv 987 done", &pairs);
        assert_eq!(scrubbed, "mail joe@x.com cvv [CVV_bb] done");
    }

    #[test]
    fn json_body_pairs_cover_escaped_form() {
        // Defense-in-depth: a (hypothetical future) non-peekable value with a quote appears
        // in a SERIALIZED body in its escaped form, so the json-body needle set must carry it.
        let mut m = UnmaskManifest::new();
        m.push(entry("a\"b", "[CVV_zz]", ENTITY_CVV, false));
        let pairs = json_body_redaction_pairs(&m);
        let needles: Vec<&str> = pairs.iter().map(|(v, _)| v.as_str()).collect();
        assert!(needles.contains(&"a\"b"), "raw form present");
        assert!(needles.contains(&"a\\\"b"), "json-escaped form present");
        // Scrubbing a serialized body redacts the ESCAPED occurrence the raw needle misses.
        let body = serde_json::to_string(&serde_json::json!({ "x": "a\"b" })).unwrap();
        let scrubbed = redact_secret_values(&body, &pairs);
        assert!(!scrubbed.contains("a\\\"b"), "escaped secret must be scrubbed: {scrubbed}");
        assert!(scrubbed.contains("[CVV_zz]"));
    }

    #[test]
    fn redact_is_noop_without_secret_classes() {
        let mut m = UnmaskManifest::new();
        m.push(entry("joe@x.com", "[EMAIL_ADDRESS_aa]", "EMAIL_ADDRESS", false));
        let pairs = redaction_pairs(&m);
        assert!(pairs.is_empty(), "ordinary PII mints no redaction pair");
        assert_eq!(redact_secret_values("anything 987", &pairs), "anything 987");
    }
}
