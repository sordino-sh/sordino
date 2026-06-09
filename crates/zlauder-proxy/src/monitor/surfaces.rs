//! Server-side message parsing + run segmentation.
//!
//! Ports the old client-side `messageBlocks` / `textValues` / `renderTokenMatches`
//! into byte-correct Rust: we parse a masked request/response JSON body, collect
//! reviewable text [`Surface`]s, and split each surface text into [`Run`]s by
//! locating masked-token handles within THAT surface string. The client then
//! renders runs with zero offset arithmetic, eliminating the UTF-16/byte
//! disagreement that drifted highlights off their text.

use serde_json::Value;

use super::model::{Run, Surface, TokenPreview, TokenRef};

/// Short blake3 hex digest of a surface's masked text (delta / dedupe key).
pub(crate) fn block_hash(text: &str) -> String {
    let hex = blake3::hash(text.as_bytes()).to_hex();
    hex.as_str().chars().take(16).collect()
}

/// Which substring of a [`TokenPreview`] to locate when segmenting a surface.
///
/// Requests carry the masked `[ENTITY_xxxx]` handle ([`NeedleMode::Handle`]);
/// responses have already been unmasked, so they carry the canonical plaintext
/// [`NeedleMode::Value`]. Searching the wrong one yields zero highlights.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NeedleMode {
    /// Locate `token.token` — the masked handle (request bodies).
    Handle,
    /// Locate `token.value` — the canonical plaintext (unmasked response bodies).
    Value,
}

/// Parse a masked REQUEST body and return its reviewable surfaces, each
/// segmented into runs by locating masked-token handles. Bodies that are not
/// valid JSON yield an empty vec (the raw preview view still shows them).
pub(crate) fn surfaces_from_body(body: &[u8], tokens: &[TokenPreview]) -> Vec<Surface> {
    surfaces_from_body_with(body, tokens, NeedleMode::Handle)
}

/// Parse an UNMASKED RESPONSE body and return its reviewable surfaces, each
/// segmented by locating the canonical plaintext VALUE of each token (the
/// response no longer contains handles). Mirrors [`surfaces_from_body`].
pub(crate) fn surfaces_from_response_body(body: &[u8], tokens: &[TokenPreview]) -> Vec<Surface> {
    surfaces_from_body_with(body, tokens, NeedleMode::Value)
}

fn surfaces_from_body_with(body: &[u8], tokens: &[TokenPreview], mode: NeedleMode) -> Vec<Surface> {
    let Ok(root) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let raw = collect_surfaces(&root);
    raw.into_iter().map(|s| segment(s, tokens, mode)).collect()
}

/// A surface before segmentation: label/role/kind plus the raw masked text.
struct RawSurface {
    label: String,
    role: Option<String>,
    kind: String,
    text: String,
}

/// Walk the request/response envelope and collect text surfaces from
/// `system` / `instructions` / `messages[]` / `input[]`.
fn collect_surfaces(root: &Value) -> Vec<RawSurface> {
    let mut out = Vec::new();
    let Some(obj) = root.as_object() else {
        return out;
    };

    if let Some(v) = obj.get("system") {
        push_texts(&mut out, "system", "system", None, v);
    }
    if let Some(v) = obj.get("instructions") {
        push_texts(&mut out, "instructions", "instructions", None, v);
    }
    if let Some(Value::Array(items)) = obj.get("messages") {
        collect_message_list(&mut out, "messages", items);
    }
    if let Some(v) = obj.get("input") {
        match v {
            Value::Array(items) => collect_message_list(&mut out, "input", items),
            other => push_texts(&mut out, "input", "message", None, other),
        }
    }
    out
}

/// Collect surfaces from a `messages`/`input` array, one labeled group per item.
fn collect_message_list(out: &mut Vec<RawSurface>, base: &str, items: &[Value]) {
    for (i, m) in items.iter().enumerate() {
        let role = m
            .as_object()
            .and_then(|o| o.get("role"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let label = match &role {
            Some(r) => format!("{base}[{i}] - {r}"),
            None => format!("{base}[{i}]"),
        };
        // Prefer the `content` field when present (matches the old JS `hasOwn`).
        let content = m.as_object().and_then(|o| o.get("content")).unwrap_or(m);
        push_texts(out, &label, "message", role.clone(), content);
        // OpenAI Chat: an assistant message's tool calls live in a `tool_calls`
        // sibling of `content` (not inside it), so they never reach
        // `text_values_from_block`. Harvest them here as `tool_use` surfaces.
        if let Some(Value::Array(calls)) = m.as_object().and_then(|o| o.get("tool_calls")) {
            for (j, call) in calls.iter().enumerate() {
                let func = call
                    .as_object()
                    .and_then(|c| c.get("function"))
                    .and_then(Value::as_object);
                let name = func
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("tool");
                let args = func
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let text = if args.is_empty() {
                    format!("{name}()")
                } else {
                    format!("{name}({args})")
                };
                out.push(RawSurface {
                    label: format!("{label} · tool_call[{j}]"),
                    role: role.clone(),
                    kind: "tool_use".to_string(),
                    text,
                });
            }
        }
    }
}

/// Append one surface per non-empty text value extracted from `v`.
fn push_texts(out: &mut Vec<RawSurface>, label: &str, kind: &str, role: Option<String>, v: &Value) {
    for (text, resolved_kind) in text_values(v, kind) {
        if text.trim().is_empty() {
            continue;
        }
        out.push(RawSurface {
            label: label.to_string(),
            role: role.clone(),
            kind: resolved_kind,
            text,
        });
    }
}

/// Extract `(text, kind)` pairs from an arbitrary content value, recursing into
/// array content blocks (`text`, `input_text`, `output_text`, `tool_result`,
/// nested `content`). Mirrors the old `textValues` but also classifies kind.
fn text_values(v: &Value, default_kind: &str) -> Vec<(String, String)> {
    match v {
        Value::String(s) => vec![(s.clone(), default_kind.to_string())],
        Value::Array(items) => {
            let mut out = Vec::new();
            for x in items {
                match x {
                    Value::String(s) => out.push((s.clone(), default_kind.to_string())),
                    Value::Object(o) => out.extend(text_values_from_block(o, default_kind)),
                    _ => {}
                }
            }
            out
        }
        Value::Object(o) => text_values_from_block(o, default_kind),
        _ => Vec::new(),
    }
}

/// Extract texts from a single content-block object, classifying tool results.
fn text_values_from_block(
    o: &serde_json::Map<String, Value>,
    default_kind: &str,
) -> Vec<(String, String)> {
    let block_type = o.get("type").and_then(Value::as_str);
    // Tool call (Anthropic `tool_use` / OpenAI Responses `function_call`): surface
    // the tool NAME plus its masked args so the operator can review what arguments
    // — which may carry masked PII — are about to leave the machine. The volatile
    // tool id (`id`/`call_id`) is deliberately NOT included in the surface text: it
    // varies per call and would re-hash the surface every turn, breaking both the
    // delta and the conversation-anchor prefix. The name IS in the text (not just a
    // label) so two different tools with identical args don't collapse to one hash.
    if matches!(block_type, Some("tool_use") | Some("function_call")) {
        let name = o.get("name").and_then(Value::as_str).unwrap_or("tool");
        let args = match o.get("input") {
            // Anthropic: `input` is a JSON object (already masked in place).
            Some(v) if !v.is_null() => serde_json::to_string(v).unwrap_or_default(),
            // OpenAI Responses: `arguments` is a JSON string.
            _ => o
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        };
        let text = if args.is_empty() {
            format!("{name}()")
        } else {
            format!("{name}({args})")
        };
        return vec![(text, "tool_use".to_string())];
    }
    // Classify as a tool result only on a positive signal: an explicit block type
    // or Anthropic's `tool_use_id` back-reference. A bare `output` key is NOT a
    // signal — assistant/control blocks can carry unrelated `output` fields, and
    // harvesting those as surface text mislabels and over-shows content.
    let is_tool_result = matches!(
        block_type,
        Some("tool_result") | Some("function_call_output")
    ) || o.contains_key("tool_use_id");
    let kind = if is_tool_result {
        "tool_result"
    } else {
        default_kind
    };

    if let Some(Value::String(s)) = o.get("text") {
        return vec![(s.clone(), kind.to_string())];
    }
    if let Some(Value::String(s)) = o.get("input_text") {
        return vec![(s.clone(), kind.to_string())];
    }
    if let Some(Value::String(s)) = o.get("output_text") {
        return vec![(s.clone(), kind.to_string())];
    }
    // `output` is a tool-result-only field (OpenAI `function_call_output`); only
    // harvest it when the block is actually a tool result.
    if is_tool_result && let Some(Value::String(s)) = o.get("output") {
        return vec![(s.clone(), kind.to_string())];
    }
    if let Some(c) = o.get("content") {
        return text_values(c, kind);
    }
    Vec::new()
}

/// Segment a raw surface's text into runs by locating every token handle.
///
/// Byte-correct: all slicing is done on the UTF-8 byte indices returned by
/// [`str::find`], so a multi-byte char before a token cannot shift a highlight.
fn segment(raw: RawSurface, tokens: &[TokenPreview], mode: NeedleMode) -> Surface {
    let hash = block_hash(&raw.text);
    let runs = segment_runs_with(&raw.text, tokens, mode);
    Surface {
        label: raw.label,
        role: raw.role,
        kind: raw.kind,
        runs,
        block_hash: hash,
    }
}

/// Locate all non-overlapping masked-token-handle occurrences in `text`
/// (request mode) and split it into alternating plain / token runs.
#[cfg(test)]
pub(crate) fn segment_runs(text: &str, tokens: &[TokenPreview]) -> Vec<Run> {
    segment_runs_with(text, tokens, NeedleMode::Handle)
}

/// Locate all non-overlapping token occurrences in `text` and split it into
/// alternating plain / token runs. The needle is the masked handle
/// ([`NeedleMode::Handle`]) or the canonical plaintext ([`NeedleMode::Value`]).
/// The concatenation of all run texts reproduces `text` exactly.
fn segment_runs_with(text: &str, tokens: &[TokenPreview], mode: NeedleMode) -> Vec<Run> {
    // Collect candidate (start, end, token_ref) matches by byte offset.
    let mut matches: Vec<(usize, usize, TokenRef)> = Vec::new();
    for t in tokens {
        let needle = match mode {
            NeedleMode::Handle => &t.token,
            NeedleMode::Value => &t.value,
        };
        if needle.is_empty() {
            continue;
        }
        let mut from = 0;
        while from <= text.len() {
            let Some(rel) = text[from..].find(needle) else {
                break;
            };
            let start = from + rel;
            let end = start + needle.len();
            matches.push((
                start,
                end,
                TokenRef {
                    token: t.token.clone(),
                    value: t.value.clone(),
                    entity_kind: t.entity_kind.clone(),
                    surface: t.surface.clone(),
                },
            ));
            from = end;
        }
    }
    // Earliest first; on tie prefer the longer match.
    matches.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

    let mut runs = Vec::new();
    let mut cursor = 0usize;
    for (start, end, tref) in matches {
        if start < cursor {
            continue; // overlaps an already-emitted run
        }
        if start > cursor {
            runs.push(Run {
                text: text[cursor..start].to_string(),
                token: None,
            });
        }
        runs.push(Run {
            text: text[start..end].to_string(),
            token: Some(tref),
        });
        cursor = end;
    }
    if cursor < text.len() {
        runs.push(Run {
            text: text[cursor..].to_string(),
            token: None,
        });
    }
    if runs.is_empty() {
        // Surface had no token and (defensively) no length-0 edge: emit one
        // plain run so concatenation still reproduces the text.
        runs.push(Run {
            text: text.to_string(),
            token: None,
        });
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(handle: &str, value: &str) -> TokenPreview {
        TokenPreview {
            token: handle.to_string(),
            value: value.to_string(),
            entity_kind: "EMAIL_ADDRESS".to_string(),
            surface: "UserMessage".to_string(),
            request_start: None,
            request_end: None,
            class: crate::monitor::model::TokenClass::AutoPii,
            peekable: true,
        }
    }

    fn reassemble(runs: &[Run]) -> String {
        runs.iter().map(|r| r.text.as_str()).collect()
    }

    #[test]
    fn segment_runs_is_byte_correct_with_multibyte_char() {
        // "café " is 6 bytes ('é' = 2 bytes); a naive UTF-16/char index would
        // place the highlight one position off.
        let text = "café [EMAIL_ADDRESS_ab12] tail";
        let runs = segment_runs(text, &[tok("[EMAIL_ADDRESS_ab12]", "a@b.com")]);

        // Round-trips exactly.
        assert_eq!(reassemble(&runs), text);

        // Exactly one token run, and it wraps the handle precisely.
        let token_runs: Vec<&Run> = runs.iter().filter(|r| r.token.is_some()).collect();
        assert_eq!(token_runs.len(), 1);
        assert_eq!(token_runs[0].text, "[EMAIL_ADDRESS_ab12]");
        assert_eq!(token_runs[0].token.as_ref().unwrap().value, "a@b.com");

        // The plain run before the token preserved the multi-byte char intact.
        assert_eq!(runs[0].text, "café ");
    }

    #[test]
    fn segment_runs_handles_repeated_token() {
        let text = "[T] x [T]";
        let runs = segment_runs(text, &[tok("[T]", "v")]);
        assert_eq!(reassemble(&runs), text);
        assert_eq!(runs.iter().filter(|r| r.token.is_some()).count(), 2);
    }

    #[test]
    fn response_surfaces_segment_by_plaintext_value() {
        // Responses are UNMASKED: the handle is gone and the plaintext value
        // is present. Segmenting by value must produce a token run wrapping it.
        let body = serde_json::json!({
            "messages": [
                {"role": "assistant", "content": "your email is a@b.com now"}
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let toks = [tok("[EMAIL_ADDRESS_ab12]", "a@b.com")];

        // Handle-mode (request) finds nothing because the handle is absent.
        let req = surfaces_from_body(&bytes, &toks);
        assert_eq!(req.len(), 1);
        assert!(req[0].runs.iter().all(|r| r.token.is_none()));

        // Value-mode (response) wraps the plaintext occurrence as a token run.
        let resp = surfaces_from_response_body(&bytes, &toks);
        assert_eq!(resp.len(), 1);
        let token_runs: Vec<&Run> = resp[0].runs.iter().filter(|r| r.token.is_some()).collect();
        assert_eq!(token_runs.len(), 1);
        assert_eq!(token_runs[0].text, "a@b.com");
        // Round-trips exactly.
        let reassembled: String = resp[0].runs.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(reassembled, "your email is a@b.com now");
    }

    #[test]
    fn anthropic_tool_use_block_becomes_tool_use_surface() {
        let body = serde_json::json!({
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "toolu_1", "name": "Bash",
                     "input": {"command": "mail [EMAIL_ADDRESS_ab12]"}}
                ]}
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let surfaces = surfaces_from_body(&bytes, &[tok("[EMAIL_ADDRESS_ab12]", "a@b.com")]);
        let tu: Vec<&Surface> = surfaces.iter().filter(|s| s.kind == "tool_use").collect();
        assert_eq!(tu.len(), 1);
        let text: String = tu[0].runs.iter().map(|r| r.text.as_str()).collect();
        // Name is in the (hashed) surface text; the masked arg handle is located.
        assert!(text.starts_with("Bash("), "got: {text}");
        assert!(tu[0].runs.iter().any(|r| r.token.is_some()));
        // The volatile tool id must NOT leak into the surface text (stable hash).
        assert!(!text.contains("toolu_1"));
    }

    #[test]
    fn openai_chat_tool_calls_sibling_becomes_tool_use_surface() {
        let body = serde_json::json!({
            "messages": [
                {"role": "assistant", "content": Value::Null, "tool_calls": [
                    {"id": "call_1", "type": "function",
                     "function": {"name": "send", "arguments": "{\"to\":\"[EMAIL_ADDRESS_ab12]\"}"}}
                ]}
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let surfaces = surfaces_from_body(&bytes, &[tok("[EMAIL_ADDRESS_ab12]", "a@b.com")]);
        let tu: Vec<&Surface> = surfaces.iter().filter(|s| s.kind == "tool_use").collect();
        assert_eq!(tu.len(), 1);
        let text: String = tu[0].runs.iter().map(|r| r.text.as_str()).collect();
        assert!(text.starts_with("send("), "got: {text}");
        assert!(tu[0].runs.iter().any(|r| r.token.is_some()));
    }

    #[test]
    fn surfaces_from_body_extracts_messages_and_system() {
        let body = serde_json::json!({
            "system": "You are [EMAIL_ADDRESS_ab12]",
            "messages": [
                {"role": "user", "content": "hi [EMAIL_ADDRESS_ab12]"},
                {"role": "assistant", "content": [
                    {"type": "text", "text": "plain reply"}
                ]}
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let surfaces = surfaces_from_body(&bytes, &[tok("[EMAIL_ADDRESS_ab12]", "a@b.com")]);
        assert_eq!(surfaces.len(), 3);
        assert_eq!(surfaces[0].kind, "system");
        assert_eq!(surfaces[1].role.as_deref(), Some("user"));
        // user surface has a token run.
        assert!(surfaces[1].runs.iter().any(|r| r.token.is_some()));
        // distinct surfaces get distinct hashes when text differs.
        assert_ne!(surfaces[0].block_hash, surfaces[1].block_hash);
    }
}
