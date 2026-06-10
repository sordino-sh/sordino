//! Streamed-response capture.
//!
//! The three SSE relay paths (Anthropic `/v1/messages`, OpenAI chat, OpenAI responses)
//! unmask the upstream reply frame-by-frame and forward it downstream, but historically
//! dropped it on the floor afterwards — a streamed turn's monitor record kept empty
//! `response_*` fields, so the operator only ever saw the model's reply once the NEXT
//! request resent it as transcript. [`ResponseCapture`] accumulates the unmasked text AS
//! WE EMIT IT, keyed per logical content block, so the same record can carry the reply:
//! surfaced live as it streams (lightweight progress frames) and finalized when the stream
//! drains. It is owned by the [`CompletionGuard`](super::store::CompletionGuard) so the
//! abort / upstream-error paths can still persist whatever streamed before the failure.

use std::collections::HashMap;

use super::model::{Surface, TokenPreview};
use super::spans::PREVIEW_LIMIT;
use super::surfaces::response_text_surface;

/// What a captured block represents — drives the rendered surface's `kind`/`role`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CapKind {
    /// Assistant prose (`text_delta` / `content` / `output_text.delta`).
    Text,
    /// A tool call's argument blob (`input_json_delta` / `tool_calls` / `function_call`).
    ToolUse,
}

/// One logical content block being accumulated, in first-seen order.
struct CapBlock {
    kind: CapKind,
    label: String,
    text: String,
    /// Tool NAME for a `ToolUse` block (from the content-block start), so the captured
    /// surface renders as `name(args)` — matching how the request extractor surfaces a
    /// re-sent tool call — and therefore folds out of the next turn's delta. `None` for
    /// prose, or a tool call whose name never arrived (then it falls back to args-only).
    name: Option<String>,
}

/// Canonicalize a tool-args JSON blob (parse → re-serialize) so the captured form
/// matches the request extractor's canonical form, regardless of the whitespace/key-order
/// the model streamed. Falls back to the raw text on any parse failure (partial/non-JSON
/// args) — a non-match there just means the tool call re-surfaces in the delta (safe
/// over-show), never a wrong fold. Shared with the request-side surface extractor
/// (`surfaces.rs`) so both sides of the fold canonicalize identically, which is what makes
/// the OpenAI `arguments`-string fold deterministic (the harness re-sends the model's
/// arguments string verbatim, so request and capture only match once both are canonical).
pub(crate) fn canonical_args(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| serde_json::to_string(&v).ok())
        .unwrap_or_else(|| raw.to_string())
}

/// Accumulator for one streamed response. Append-only; renders to a preview string and
/// pre-segmented surfaces on demand. Total captured text is bounded by [`PREVIEW_LIMIT`]
/// (the same cap the request preview uses) so a runaway response can't grow unbounded.
#[derive(Default)]
pub(crate) struct ResponseCapture {
    blocks: Vec<CapBlock>,
    /// block key (path-specific, e.g. content-block index) → slot in `blocks`.
    slot: HashMap<String, usize>,
    /// Running byte total across all blocks (the throttle + cap key).
    total: usize,
    /// Set once the cap is hit; renders a trailing truncation marker.
    truncated: bool,
}

impl ResponseCapture {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an already-unmasked downstream fragment to the block identified by `key`,
    /// creating it (with `kind`/`label`) on first sight. Empty fragments and anything past
    /// the [`PREVIEW_LIMIT`] cap are dropped (the latter flips `truncated`).
    pub fn push(&mut self, key: &str, kind: CapKind, label: &str, text: &str) {
        if text.is_empty() {
            return;
        }
        let room = PREVIEW_LIMIT.saturating_sub(self.total);
        if room == 0 {
            self.truncated = true;
            return;
        }
        // Clamp THIS fragment to the remaining room — checking the cap only before the
        // append (the prior shape) let a single oversized delta (e.g. a big tool-args blob)
        // blow past PREVIEW_LIMIT in one push. Truncate on a UTF-8 char boundary so the
        // slice never splits a multi-byte char.
        let text = if text.len() <= room {
            text
        } else {
            self.truncated = true;
            let mut end = room;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            &text[..end]
        };
        if text.is_empty() {
            return; // remaining room smaller than the next whole char
        }
        let idx = match self.slot.get(key) {
            Some(&i) => i,
            None => {
                let i = self.blocks.len();
                self.blocks.push(CapBlock {
                    kind,
                    label: label.to_string(),
                    text: String::new(),
                    name: None,
                });
                self.slot.insert(key.to_string(), i);
                i
            }
        };
        self.blocks[idx].text.push_str(text);
        self.total += text.len();
    }

    /// Record the tool NAME for a tool-call block at `key`, creating the (empty) block in
    /// first-seen order if its args have not streamed yet. Called when the content-block
    /// start carries the name (which the per-fragment [`Self::push`] never sees). Idempotent
    /// — a later push appends args to the same slot, and [`Self::render`] emits `name(args)`.
    pub fn start_tool(&mut self, key: &str, name: &str) {
        let idx = match self.slot.get(key) {
            Some(&i) => i,
            None => {
                let i = self.blocks.len();
                self.blocks.push(CapBlock {
                    kind: CapKind::ToolUse,
                    label: key.to_string(),
                    text: String::new(),
                    name: None,
                });
                self.slot.insert(key.to_string(), i);
                i
            }
        };
        if !name.is_empty() {
            self.blocks[idx].name = Some(name.to_string());
        }
    }

    /// Total bytes captured so far (the progress-flush throttle key).
    pub fn total_len(&self) -> usize {
        self.total
    }

    /// True when [`Self::render`] would emit nothing. Mirrors render's per-block skip
    /// condition exactly (`text empty AND name none`) rather than testing `total == 0`, so
    /// a name-only tool call (a tool that streamed a name but zero arg bytes → `total == 0`)
    /// still counts as content: it is persisted and folds as `name()` instead of being
    /// dropped at finalize (the completion path gates the response surfaces on this).
    pub fn is_empty(&self) -> bool {
        !self.blocks.iter().any(|b| !b.text.is_empty() || b.name.is_some())
    }

    /// Render `(preview, surfaces)` from the accumulated blocks. `preview` is the raw
    /// concatenation (blocks joined by a blank line) for the legacy span view; `surfaces`
    /// are pre-segmented per block (token VALUES wrapped) for the structured view.
    pub fn render(&self, tokens: &[TokenPreview]) -> (String, Vec<Surface>) {
        let mut surfaces = Vec::with_capacity(self.blocks.len());
        let mut preview = String::new();
        for b in &self.blocks {
            // Skip a truly empty block, but keep a named tool call with no args (`name()`).
            if b.text.is_empty() && b.name.is_none() {
                continue;
            }
            let (kind, role) = match b.kind {
                CapKind::Text => ("message", Some("assistant".to_string())),
                CapKind::ToolUse => ("tool_use", Some("assistant".to_string())),
            };
            // A named tool call surfaces `name(canonical_args)` — the SAME form the request
            // extractor produces for a re-sent tool call — so it folds out of the next
            // turn's delta. Prose and unnamed tool calls surface their captured text as-is.
            let surface_text = match (b.kind, &b.name) {
                (CapKind::ToolUse, Some(name)) => {
                    let args = canonical_args(&b.text);
                    if args.is_empty() {
                        format!("{name}()")
                    } else {
                        format!("{name}({args})")
                    }
                }
                _ => b.text.clone(),
            };
            surfaces.push(response_text_surface(
                b.label.clone(),
                role,
                kind,
                &surface_text,
                tokens,
            ));
            if !preview.is_empty() {
                preview.push_str("\n\n");
            }
            preview.push_str(&surface_text);
        }
        if self.truncated {
            preview.push_str("\n...[truncated]");
        }
        (preview, surfaces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::model::TokenClass;

    fn tok(handle: &str, value: &str) -> TokenPreview {
        TokenPreview {
            token: handle.to_string(),
            value: value.to_string(),
            entity_kind: "EMAIL_ADDRESS".to_string(),
            surface: "UserMessage".to_string(),
            request_start: None,
            request_end: None,
            class: TokenClass::AutoPii,
            peekable: true,
        }
    }

    #[test]
    fn accumulates_across_fragments_and_renders_one_surface_per_block() {
        let mut c = ResponseCapture::new();
        c.push("t0", CapKind::Text, "assistant", "your email is ");
        c.push("t0", CapKind::Text, "assistant", "a@b.com now");
        let (preview, surfaces) = c.render(&[tok("[EMAIL_ab]", "a@b.com")]);
        assert_eq!(preview, "your email is a@b.com now");
        assert_eq!(surfaces.len(), 1);
        // The echoed plaintext is wrapped as a token run (segmented by VALUE).
        let token_runs: Vec<_> = surfaces[0].runs.iter().filter(|r| r.token.is_some()).collect();
        assert_eq!(token_runs.len(), 1);
        assert_eq!(token_runs[0].text, "a@b.com");
        assert_eq!(surfaces[0].role.as_deref(), Some("assistant"));
        assert_eq!(surfaces[0].provenance, "assistant");
    }

    #[test]
    fn named_tool_call_renders_name_and_canonical_args() {
        // The name (from the block start) + canonicalized args (whitespace/order-normalized)
        // reproduce the request extractor's `name(args)` form, so the call folds next turn.
        let mut c = ResponseCapture::new();
        c.start_tool("j0", "Bash");
        c.push("j0", CapKind::ToolUse, "tool_use[0]", "{ \"command\" :  \"ls\" }");
        let (preview, surfaces) = c.render(&[]);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].kind, "tool_use");
        assert!(
            preview.starts_with("Bash({\"command\":\"ls\"})"),
            "expected name(canonical_args), got: {preview}"
        );
    }

    #[test]
    fn unnamed_tool_call_falls_back_to_args_only() {
        // No start_tool (name never arrived) -> args-only, the prior behavior (safe over-show).
        let mut c = ResponseCapture::new();
        c.push("j0", CapKind::ToolUse, "tool_use[0]", "{\"x\":1}");
        let (preview, _surfaces) = c.render(&[]);
        assert_eq!(preview, "{\"x\":1}");
    }

    #[test]
    fn name_only_tool_call_is_non_empty_and_renders_name_parens() {
        // A tool call that streamed a name but zero arg bytes must NOT be treated as empty
        // (else the completion path drops it instead of persisting/folding it as `name()`).
        let mut c = ResponseCapture::new();
        c.start_tool("j0", "Bash");
        assert!(!c.is_empty(), "name-only capture must count as content");
        let (preview, surfaces) = c.render(&[]);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].kind, "tool_use");
        assert_eq!(preview, "Bash()");
    }

    #[test]
    fn empty_name_start_tool_stays_empty() {
        // start_tool with an empty name creates a phantom block with no name and no text;
        // render skips it, so is_empty() must agree (no over-persist of a blank surface).
        let mut c = ResponseCapture::new();
        c.start_tool("j0", "");
        assert!(c.is_empty());
        let (preview, surfaces) = c.render(&[]);
        assert!(preview.is_empty());
        assert!(surfaces.is_empty());
    }

    #[test]
    fn separate_blocks_become_separate_surfaces_in_order() {
        let mut c = ResponseCapture::new();
        c.push("t0", CapKind::Text, "assistant", "prose");
        c.push("j0", CapKind::ToolUse, "tool_use[0]", "{\"x\":1}");
        let (_preview, surfaces) = c.render(&[]);
        assert_eq!(surfaces.len(), 2);
        assert_eq!(surfaces[0].kind, "message");
        assert_eq!(surfaces[1].kind, "tool_use");
    }

    #[test]
    fn empty_is_empty() {
        let mut c = ResponseCapture::new();
        assert!(c.is_empty());
        c.push("t0", CapKind::Text, "assistant", "");
        assert!(c.is_empty());
    }

    #[test]
    fn caps_at_preview_limit_and_marks_truncated() {
        let mut c = ResponseCapture::new();
        let big = "x".repeat(PREVIEW_LIMIT + 10);
        c.push("t0", CapKind::Text, "assistant", &big);
        // The oversized fragment is clamped to the cap in ONE push (hard bound).
        assert!(c.total_len() <= PREVIEW_LIMIT, "hard cap honored per-append");
        // A further push past the cap is dropped and the marker stays set.
        c.push("t0", CapKind::Text, "assistant", "more");
        let (preview, _surfaces) = c.render(&[]);
        assert!(preview.ends_with("...[truncated]"));
        assert!(c.total_len() <= PREVIEW_LIMIT);
    }

    #[test]
    fn cap_truncates_on_char_boundary() {
        // A multi-byte char straddling the cap must not panic or split mid-char.
        let mut c = ResponseCapture::new();
        // Fill to one byte under the cap, then push a 2-byte char that would straddle it.
        c.push("t0", CapKind::Text, "assistant", &"a".repeat(PREVIEW_LIMIT - 1));
        c.push("t0", CapKind::Text, "assistant", "é"); // 2 bytes — doesn't fit in 1 byte room
        let (preview, _surfaces) = c.render(&[]);
        assert!(c.total_len() <= PREVIEW_LIMIT);
        assert!(preview.ends_with("...[truncated]"));
        assert!(!preview.contains('\u{fffd}'), "no broken char");
    }
}
