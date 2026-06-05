//! Walk Anthropic request/response bodies and mask (request) or unmask
//! (response) every text-bearing field.
//!
//! Invariant for unmask-on-the-wire: the request path masks every outbound
//! text field (user, system, tool_result, and assistant-authored history,
//! which the local transcript stores as plaintext); the response path unmasks
//! every inbound model-authored field. `Thinking` / `RedactedThinking` /
//! signatures are opaque both ways (never unmasked → stay tokenized → their
//! signatures stay valid, zero leak). Unknown fields ride through the typed
//! `extra` flatten sinks untouched.

use anthropic_wire::{
    ApiContentBlock, ApiDocumentSource, ApiImageSource, ApiRequest, ApiResponse, SystemContent,
    ToolResultBlock, ToolResultContent,
};
use serde_json::{Map, Value};
use zlauder_engine::{EngineError, MaskEngine, MaskStats, Surface, UnmaskManifest};

// ---------------------------------------------------------------------------
// Request — mask
// ---------------------------------------------------------------------------

/// Deserialize, mask every text field, re-serialize. Returns masked JSON bytes
/// and the merged per-call manifest.
///
/// If the body doesn't fit the typed `ApiRequest` schema, we do NOT forward it
/// unmasked — we fall back to a structure-agnostic Value-walk that masks every
/// string leaf (presidio only tokenizes detected PII, so structural strings like
/// the model id are untouched). This keeps the proxy fail-safe against any
/// request shape the wire types can't represent.
pub fn mask_request(
    engine: &MaskEngine,
    body: &[u8],
) -> Result<(Vec<u8>, UnmaskManifest), MaskError> {
    let mut manifest = UnmaskManifest::new();
    match serde_json::from_slice::<ApiRequest>(body) {
        Ok(mut req) => {
            let stats = {
                let mut w = MaskWalker {
                    engine,
                    manifest: &mut manifest,
                    stats: MaskStats::default(),
                };
                w.request(&mut req).map_err(MaskError::Engine)?;
                w.stats
            };
            log_mask_stats(&stats);
            let bytes = serde_json::to_vec(&req).map_err(MaskError::Json)?;
            Ok((bytes, manifest))
        }
        Err(typed_err) => {
            tracing::warn!("typed request parse failed ({typed_err}); using fail-safe value-walk");
            let mut value: Value = serde_json::from_slice(body).map_err(MaskError::Json)?;
            let stats = {
                let mut w = MaskWalker {
                    engine,
                    manifest: &mut manifest,
                    stats: MaskStats::default(),
                };
                w.value_safe(&mut value, Surface::UserMessage)
                    .map_err(MaskError::Engine)?;
                w.stats
            };
            log_mask_stats(&stats);
            let bytes = serde_json::to_vec(&value).map_err(MaskError::Json)?;
            Ok((bytes, manifest))
        }
    }
}

/// Emit the per-request detection-cache instrumentation once (Component 2). On a
/// steady turn deep in a session `fresh_misses` must collapse to single digits
/// while `hits` tracks the (growing) leaf count — the falsifiable caching-win
/// observable. `ml_misses` are the inferences actually run this turn.
fn log_mask_stats(s: &MaskStats) {
    let ml_misses = s.ml_ran;
    let regex_misses = s.fresh_miss.saturating_sub(s.ml_ran);
    tracing::debug!(
        leaves = s.leaves,
        hits = s.hit,
        fresh_misses = s.fresh_miss,
        ml_misses,
        regex_misses,
        fail_open = s.fail_open,
        disabled = s.disabled,
        "mask walk detection-cache stats"
    );
}

#[derive(thiserror::Error, Debug)]
pub enum MaskError {
    #[error("request JSON error: {0}")]
    Json(#[source] serde_json::Error),
    #[error("masking refused (fail_closed): {0}")]
    Engine(#[source] EngineError),
}

struct MaskWalker<'a> {
    engine: &'a MaskEngine,
    manifest: &'a mut UnmaskManifest,
    /// Accumulated detection-cache stats across every leaf this walk masks.
    stats: MaskStats,
}

impl MaskWalker<'_> {
    fn request(&mut self, req: &mut ApiRequest) -> Result<(), EngineError> {
        if let Some(sys) = req.system.as_mut() {
            match sys {
                SystemContent::Text(t) => self.str(t, Surface::SystemPrompt)?,
                SystemContent::Blocks(blocks) => {
                    for b in blocks.iter_mut() {
                        self.str(&mut b.text, Surface::SystemPrompt)?;
                        self.map(&mut b.extra, Surface::SystemPrompt)?;
                    }
                }
                _ => {}
            }
        }
        for msg in req.messages.iter_mut() {
            let role = msg.role.to_string();
            for block in msg.content.iter_mut() {
                self.block(block, &role)?;
            }
            self.map(&mut msg.extra, surface_for_role(&role))?;
        }
        if let Some(tools) = req.tools.as_mut() {
            for tool in tools.iter_mut() {
                self.str(&mut tool.description, Surface::SystemPrompt)?;
                // input_schema is left verbatim: masking schema constraints could
                // break the model's tool-call validation.
            }
        }
        if let Some(meta) = req.metadata.as_mut() {
            self.value(meta, Surface::UserMessage)?;
        }
        if let Some(ctx) = req.context_management.as_mut() {
            self.value(ctx, Surface::UserMessage)?;
        }
        self.map(&mut req.extra, Surface::UserMessage)?;
        Ok(())
    }

    fn block(&mut self, block: &mut ApiContentBlock, role: &str) -> Result<(), EngineError> {
        match block {
            ApiContentBlock::Text { text, .. } => self.str(text, surface_for_role(role))?,
            ApiContentBlock::ToolUse { input, .. } => self.value(input, Surface::ToolUseInput)?,
            ApiContentBlock::ToolResult { content, .. } => self.tool_result(content)?,
            ApiContentBlock::Image { source } => self.image(source, Surface::UserMessage)?,
            ApiContentBlock::Document { source, .. } => {
                self.document(source, Surface::UserMessage)?
            }
            ApiContentBlock::Compaction { content, .. } => {
                self.str(content, Surface::AssistantText)?
            }
            // Opaque: thinking text + signature stay tokenized end-to-end.
            ApiContentBlock::Thinking { .. } | ApiContentBlock::RedactedThinking { .. } => {}
            _ => {}
        }
        Ok(())
    }

    fn tool_result(&mut self, content: &mut ToolResultContent) -> Result<(), EngineError> {
        match content {
            ToolResultContent::Text(t) => self.str(t, Surface::ToolResult)?,
            ToolResultContent::Blocks(blocks) => {
                for b in blocks.iter_mut() {
                    match b {
                        ToolResultBlock::Text { text } => self.str(text, Surface::ToolResult)?,
                        ToolResultBlock::Image { source } => {
                            self.image(source, Surface::ToolResult)?
                        }
                        ToolResultBlock::Document { source, .. } => {
                            self.document(source, Surface::ToolResult)?
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn image(&mut self, source: &mut ApiImageSource, surface: Surface) -> Result<(), EngineError> {
        if let ApiImageSource::Url { url } = source {
            self.str(url, surface)?;
        }
        // Base64 data is binary; masking it would corrupt the image.
        Ok(())
    }

    fn document(
        &mut self,
        source: &mut ApiDocumentSource,
        surface: Surface,
    ) -> Result<(), EngineError> {
        if let ApiDocumentSource::Url { url } = source {
            self.str(url, surface)?;
        }
        Ok(())
    }

    fn str(&mut self, text: &mut String, surface: Surface) -> Result<(), EngineError> {
        let outcome = self.engine.mask(text, surface)?;
        *text = outcome.masked_text;
        self.manifest.merge(outcome.manifest);
        self.stats.merge(&outcome.stats);
        Ok(())
    }

    fn value(&mut self, v: &mut Value, surface: Surface) -> Result<(), EngineError> {
        match v {
            Value::String(s) => {
                let outcome = self.engine.mask(s, surface)?;
                *s = outcome.masked_text;
                self.manifest.merge(outcome.manifest);
                self.stats.merge(&outcome.stats);
            }
            Value::Array(a) => {
                for item in a.iter_mut() {
                    self.value(item, surface)?;
                }
            }
            Value::Object(o) => {
                for (_k, val) in o.iter_mut() {
                    self.value(val, surface)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn map(&mut self, m: &mut Map<String, Value>, surface: Surface) -> Result<(), EngineError> {
        for (_k, val) in m.iter_mut() {
            self.value(val, surface)?;
        }
        Ok(())
    }

    /// Like [`Self::value`] but skips the `data` field of base64 sources (any
    /// object with `"type": "base64"`), so it's safe to run over a whole
    /// unknown-shaped request without corrupting embedded images/documents.
    fn value_safe(&mut self, v: &mut Value, surface: Surface) -> Result<(), EngineError> {
        match v {
            Value::String(s) => {
                let outcome = self.engine.mask(s, surface)?;
                *s = outcome.masked_text;
                self.manifest.merge(outcome.manifest);
                self.stats.merge(&outcome.stats);
            }
            Value::Array(a) => {
                for item in a.iter_mut() {
                    self.value_safe(item, surface)?;
                }
            }
            Value::Object(o) => {
                let is_base64 = o.get("type").and_then(Value::as_str) == Some("base64");
                for (k, val) in o.iter_mut() {
                    if is_base64 && k == "data" {
                        continue;
                    }
                    self.value_safe(val, surface)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn surface_for_role(role: &str) -> Surface {
    if role == "assistant" {
        Surface::AssistantText
    } else {
        Surface::UserMessage
    }
}

// ---------------------------------------------------------------------------
// Response — unmask (non-streaming)
// ---------------------------------------------------------------------------

/// Deserialize a non-streaming response, unmask every model-authored text
/// field, re-serialize.
pub fn unmask_response(
    engine: &MaskEngine,
    manifest: &UnmaskManifest,
    body: &[u8],
) -> Result<Vec<u8>, serde_json::Error> {
    let mut resp: ApiResponse = serde_json::from_slice(body)?;
    for block in resp.content.iter_mut() {
        unmask_block(engine, manifest, block);
    }
    unmask_map(engine, manifest, &mut resp.extra);
    serde_json::to_vec(&resp)
}

fn unmask_block(engine: &MaskEngine, manifest: &UnmaskManifest, block: &mut ApiContentBlock) {
    match block {
        // Assistant prose → display: the ONLY place the reveal marker decorates, so
        // the operator can see which spans were un-masked.
        ApiContentBlock::Text { text, .. } => unmask_str_assistant(engine, manifest, text),
        // Tool input is consumed verbatim by a tool (could be written to a file): no
        // decoration, ever. Same for compaction (machine context that is re-sent).
        ApiContentBlock::ToolUse { input, .. } => unmask_value(engine, manifest, input),
        ApiContentBlock::Compaction { content, .. } => unmask_str(engine, manifest, content),
        // Opaque: leave thinking/redacted tokenized so signatures stay valid.
        _ => {}
    }
}

/// Unmask a single string in place (used by the response walkers). No decoration —
/// for fields whose bytes must stay exact (compaction).
pub fn unmask_str(engine: &MaskEngine, manifest: &UnmaskManifest, text: &mut String) {
    if let Ok(out) = engine.unmask(text, manifest) {
        *text = out;
    }
}

/// Unmask assistant prose in place, applying the reveal marker (when configured).
fn unmask_str_assistant(engine: &MaskEngine, manifest: &UnmaskManifest, text: &mut String) {
    if let Ok(out) = engine.unmask_assistant(text, manifest) {
        *text = out;
    }
}

pub fn unmask_value(engine: &MaskEngine, manifest: &UnmaskManifest, v: &mut Value) {
    match v {
        Value::String(s) => {
            if let Ok(out) = engine.unmask(s, manifest) {
                *s = out;
            }
        }
        Value::Array(a) => {
            for item in a.iter_mut() {
                unmask_value(engine, manifest, item);
            }
        }
        Value::Object(o) => {
            for (_k, val) in o.iter_mut() {
                unmask_value(engine, manifest, val);
            }
        }
        _ => {}
    }
}

fn unmask_map(engine: &MaskEngine, manifest: &UnmaskManifest, m: &mut Map<String, Value>) {
    for (_k, val) in m.iter_mut() {
        unmask_value(engine, manifest, val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zlauder_engine::{EngineConfig, RevealMarker};

    fn engine() -> MaskEngine {
        MaskEngine::new(EngineConfig::default()).unwrap()
    }

    fn engine_marked() -> MaskEngine {
        let mut cfg = EngineConfig::default();
        cfg.reveal_marker = RevealMarker {
            enabled: true,
            prefix: "«".into(),
            suffix: "»".into(),
        };
        MaskEngine::new(cfg).unwrap()
    }

    // The reveal marker decorates the assistant `text` block but MUST leave a
    // `tool_use` input untouched (it may be written verbatim into a file/tool).
    #[test]
    fn reveal_marker_decorates_text_block_not_tool_input() {
        let e = engine_marked();
        // Mint a token for an email via a request mask.
        let (_m, manifest) = mask_request(
            &e,
            serde_json::json!({
                "model": "m", "max_tokens": 10,
                "messages": [{"role":"user","content":[{"type":"text","text":"to bob@example.com"}]}]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let token = manifest.entries[0].token_handle.clone();

        let resp = serde_json::json!({
            "content": [
                {"type":"text","text": format!("I'll write to {token} now")},
                {"type":"tool_use","id":"t1","name":"write_file",
                 "input": {"path":"/etc/cfg","contents": format!("addr={token}")}}
            ],
            "model": "m"
        });
        let out = unmask_response(&e, &manifest, resp.to_string().as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();

        // Assistant prose: decorated.
        assert_eq!(
            v["content"][0]["text"].as_str().unwrap(),
            "I'll write to «bob@example.com» now"
        );
        // Tool input: un-masked but NOT decorated — the file would otherwise get the
        // marker bytes baked in.
        assert_eq!(
            v["content"][1]["input"]["contents"].as_str().unwrap(),
            "addr=bob@example.com"
        );
    }

    #[test]
    fn request_round_trip_preserves_unknown_fields() {
        let e = engine();
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 100,
            "x_future_flag": true,
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "email me at alice@example.com"}
                ], "x_msg_extra": {"note": "ping carol@example.com"}},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1",
                     "content": "the admin is reachable at bob@example.com"}
                ]}
            ]
        });
        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();
        let s = String::from_utf8(masked.clone()).unwrap();

        // R2 — unknown top-level key survives, and the unknown nested `extra`
        // map is still walked (its PII is masked).
        assert_eq!(v["x_future_flag"], serde_json::json!(true));
        assert!(
            !s.contains("carol@example.com"),
            "unknown-field PII leaked: {s}"
        );

        // Arrow 1 — user text masked.
        assert!(!s.contains("alice@example.com"), "user email leaked");
        // Arrow 4 — tool_result content masked.
        assert!(!s.contains("bob@example.com"), "tool_result email leaked");
        assert!(s.contains("[EMAIL_ADDRESS_"));
        assert_eq!(manifest.len(), 3, "three distinct emails minted");

        // The masked tool_result round-trips back to plaintext.
        let masked_tr = v["messages"][1]["content"][0]["content"].as_str().unwrap();
        let restored = e.unmask(masked_tr, &manifest).unwrap();
        assert_eq!(restored, "the admin is reachable at bob@example.com");
    }

    // Regression: Claude Code sends some messages with bare-string `content`
    // (and role "system" inside messages). This historically broke typed parse
    // and leaked plaintext upstream. Must be masked now.
    #[test]
    fn string_content_message_is_masked_not_leaked() {
        let e = engine();
        let body = serde_json::json!({
            "model": "claude-opus-4-8", "max_tokens": 100,
            "system": [{"type": "text", "text": "system prompt"}],
            "messages": [
                {"role": "system", "content": "note: ops contact is sue@example.com"},
                {"role": "user", "content": [{"type": "text", "text": "and mine is rob@example.com"}]}
            ]
        });
        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(masked).unwrap();
        assert!(
            !s.contains("sue@example.com"),
            "string-content PII leaked: {s}"
        );
        assert!(
            !s.contains("rob@example.com"),
            "array-content PII leaked: {s}"
        );
        assert!(s.contains("[EMAIL_ADDRESS_"));
        assert_eq!(manifest.len(), 2);
    }

    #[test]
    fn response_unmask_restores_plaintext() {
        let e = engine();
        // Mint a token via a request mask.
        let (_m, manifest) = mask_request(
            &e,
            serde_json::json!({
                "model": "m", "max_tokens": 10,
                "messages": [{"role":"user","content":[{"type":"text","text":"to bob@example.com"}]}]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let token = manifest.entries[0].token_handle.clone();

        let resp = serde_json::json!({
            "content": [{"type":"text","text": format!("I'll write to {token} now")}],
            "model": "m"
        });
        let out = unmask_response(&e, &manifest, resp.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("bob@example.com"), "not unmasked: {s}");
        assert!(!s.contains(&token));
    }
}
