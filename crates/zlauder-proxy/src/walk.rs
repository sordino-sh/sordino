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
            // Phase 1 (ML-active only): collect every leaf in one read-only-equivalent
            // pass and batch-prewarm the detection cache, so the mask pass below pays
            // ONE batched inference instead of N serialized per-leaf ones. Gated on a
            // live model: with ML off there is nothing expensive to batch, so we skip
            // straight to the mask pass — byte-identical to before this change.
            prewarm_request(engine, &mut req);
            let stats = {
                let mut w = MaskWalker {
                    engine,
                    manifest: &mut manifest,
                    stats: MaskStats::default(),
                    collect: None,
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
                    collect: None,
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

/// Phase-1 prewarm: when a model is live, walk `req` in COLLECT mode to gather every
/// text leaf (cloned, with its surface) and hand them to one
/// [`MaskEngine::prewarm_batch`], which runs the cache-missing leaves through a
/// single batched ML forward and populates the detection cache. The subsequent mask
/// walk then hits cache on every prewarmed leaf and pays no per-leaf inference.
///
/// Best-effort and side-effect-free w.r.t. the masked output: COLLECT mode never
/// masks, and `prewarm_batch` is purely additive (see its docs), so this only ever
/// makes the mask pass faster — never different. Skipped entirely when ML is not
/// `Ready`, so the no-ML path keeps its exact prior behavior (no extra traversal,
/// no clones).
fn prewarm_request(engine: &MaskEngine, req: &mut ApiRequest) {
    if !engine.ml_active() {
        return;
    }
    let mut throwaway = UnmaskManifest::new();
    let mut collector = MaskWalker {
        engine,
        manifest: &mut throwaway,
        stats: MaskStats::default(),
        collect: Some(Vec::new()),
    };
    // COLLECT mode masks nothing and never calls the engine, so `request` cannot
    // error here; if it somehow did, just skip the prewarm (the mask pass is correct
    // on its own).
    if collector.request(req).is_err() {
        return;
    }
    let Some(leaves) = collector.collect.take() else {
        return;
    };
    let refs: Vec<(&str, Surface)> = leaves.iter().map(|(t, s)| (t.as_str(), *s)).collect();
    engine.prewarm_batch(&refs);
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
    #[error("masking refused: {0}")]
    Engine(#[source] EngineError),
}

struct MaskWalker<'a> {
    engine: &'a MaskEngine,
    manifest: &'a mut UnmaskManifest,
    /// Accumulated detection-cache stats across every leaf this walk masks.
    stats: MaskStats,
    /// When `Some`, the walker is in COLLECT mode: every leaf is cloned into this
    /// vec (with its surface) and NOTHING is mutated/masked, so a second, masking
    /// pass over the same request sees the original text. Used to gather all leaves
    /// for one batched [`MaskEngine::prewarm_batch`] before the real mask walk. The
    /// SAME traversal serves both phases, so collect can never visit a different
    /// leaf set than mask (zero divergence).
    collect: Option<Vec<(String, Surface)>>,
}

impl MaskWalker<'_> {
    fn request(&mut self, req: &mut ApiRequest) -> Result<(), EngineError> {
        if let Some(sys) = req.system.as_mut() {
            match sys {
                SystemContent::Text(t) => self.str(t, Surface::SystemPrompt)?,
                SystemContent::Blocks(blocks) => {
                    for b in blocks.iter_mut() {
                        self.str(&mut b.text, Surface::SystemPrompt)?;
                        warn_unknown_map(&b.extra, "system block");
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
            warn_unknown_map(&msg.extra, "message");
        }
        if let Some(tools) = req.tools.as_mut() {
            for tool in tools.iter_mut() {
                self.str(&mut tool.description, Surface::SystemPrompt)?;
                // input_schema is left verbatim: masking schema constraints could
                // break the model's tool-call validation.
                warn_unknown_map(&tool.extra, "tool");
            }
        }
        // `metadata.user_id` is API-protocol TELEMETRY, not natural-language content:
        // Anthropic populates it (Claude Code sets it to an opaque account/session
        // identifier) and uses it to correlate traffic for abuse detection. Masking it
        // CORRUPTS that telemetry on the wire — a session UUID trips `US_BANK_NUMBER`, so
        // the field would egress as `[US_BANK_NUMBER_…]`, change every session, and read
        // as deliberate evasion — for ZERO privacy benefit (the field is contractually
        // opaque and must never carry PII). So pass `user_id` through VERBATIM (cf. the
        // tool `input_schema` passthrough above), while still masking any other metadata
        // leaf an unexpected client might set (defense-in-depth, unchanged). The same
        // traversal serves COLLECT and MASK, so skipping `user_id` here skips it in both.
        if let Some(meta) = req.metadata.as_mut() {
            match meta {
                Value::Object(map) => {
                    for (key, v) in map.iter_mut() {
                        if key == "user_id" {
                            continue;
                        }
                        self.value(v, Surface::UserMessage)?;
                    }
                }
                other => self.value(other, Surface::UserMessage)?,
            }
        }
        if let Some(ctx) = req.context_management.as_mut() {
            self.context_management(ctx)?;
        }
        warn_unknown_map(&req.extra, "request");
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

    /// The single leaf sink for this walker. In COLLECT mode it clones the leaf for
    /// the prewarm batch and leaves the text untouched; in MASK mode it masks in
    /// place. Every text-bearing field routes through here (the `value*` walkers
    /// included), so the collect and mask passes are guaranteed to cover the exact
    /// same leaf set.
    fn str(&mut self, text: &mut String, surface: Surface) -> Result<(), EngineError> {
        if let Some(leaves) = self.collect.as_mut() {
            leaves.push((text.clone(), surface));
            return Ok(());
        }
        let outcome = self.engine.mask(text, surface)?;
        *text = outcome.masked_text;
        self.manifest.merge(outcome.manifest);
        self.stats.merge(&outcome.stats);
        Ok(())
    }

    fn value(&mut self, v: &mut Value, surface: Surface) -> Result<(), EngineError> {
        match v {
            Value::String(s) => self.str(s, surface)?,
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

    fn context_management(&mut self, v: &mut Value) -> Result<(), EngineError> {
        self.value_skipping_protocol_keys(v, Surface::SystemPrompt)
    }

    fn value_skipping_protocol_keys(
        &mut self,
        v: &mut Value,
        surface: Surface,
    ) -> Result<(), EngineError> {
        match v {
            Value::String(s) => self.str(s, surface)?,
            Value::Array(a) => {
                for item in a.iter_mut() {
                    self.value_skipping_protocol_keys(item, surface)?;
                }
            }
            Value::Object(o) => {
                for (k, val) in o.iter_mut() {
                    if is_context_management_protocol_key(k) {
                        continue;
                    }
                    self.value_skipping_protocol_keys(val, surface)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Like [`Self::value`] but skips the `data` field of base64 sources (any
    /// object with `"type": "base64"`), so it's safe to run over a whole
    /// unknown-shaped request without corrupting embedded images/documents.
    fn value_safe(&mut self, v: &mut Value, surface: Surface) -> Result<(), EngineError> {
        match v {
            Value::String(s) => self.str(s, surface)?,
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
                    if k == "context_management" {
                        self.context_management(val)?;
                    } else if k == "tools" {
                        self.tools_value_safe(val)?;
                    } else if preserves_contract_key(k) {
                        continue;
                    } else {
                        self.value_safe(val, surface)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn tools_value_safe(&mut self, v: &mut Value) -> Result<(), EngineError> {
        match v {
            Value::Array(tools) => {
                for tool in tools.iter_mut() {
                    self.tool_value_safe(tool)?;
                }
            }
            other => self.value_safe(other, Surface::SystemPrompt)?,
        }
        Ok(())
    }

    fn tool_value_safe(&mut self, v: &mut Value) -> Result<(), EngineError> {
        match v {
            Value::Object(o) => {
                for (k, val) in o.iter_mut() {
                    match k.as_str() {
                        "description" => self.value_safe(val, Surface::SystemPrompt)?,
                        "input_schema" | "cache_control" | "name" | "type" => {}
                        _ if preserves_contract_key(k) => {}
                        _ => self.value_safe(val, Surface::SystemPrompt)?,
                    }
                }
            }
            other => self.value_safe(other, Surface::SystemPrompt)?,
        }
        Ok(())
    }
}

fn preserves_contract_key(key: &str) -> bool {
    matches!(
        key,
        "model"
            | "tool_choice"
            | "thinking"
            | "output_config"
            | "format"
            | "json_schema"
            | "schema"
            | "input_schema"
            | "cache_control"
            | "id"
            | "tool_use_id"
            | "signature"
            | "data"
            | "media_type"
            | "type"
    )
}

fn is_context_management_protocol_key(key: &str) -> bool {
    matches!(
        key,
        // Anthropic validates these as exact enum/tool-name strings. They are
        // request-control metadata, not natural-language content.
        "type" | "keep" | "trigger" | "clear_at_least" | "clear_tool_inputs" | "exclude_tools"
    )
}

fn warn_unknown_map(m: &Map<String, Value>, location: &'static str) {
    if m.is_empty() {
        return;
    }
    let keys = m.keys().map(String::as_str).collect::<Vec<_>>().join(",");
    tracing::warn!(
        location,
        keys = %keys,
        "preserving unknown Anthropic request fields without masking"
    );
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
        let cfg = EngineConfig {
            reveal_marker: RevealMarker {
                enabled: true,
                prefix: "«".into(),
                suffix: "»".into(),
            },
            ..Default::default()
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

        // R2 — unknown fields are preserved verbatim and not inspected/mutated.
        assert_eq!(v["x_future_flag"], serde_json::json!(true));
        assert!(
            s.contains("carol@example.com"),
            "unknown-field value should pass through unchanged: {s}"
        );

        // Arrow 1 — user text masked.
        assert!(!s.contains("alice@example.com"), "user email leaked");
        // Arrow 4 — tool_result content masked.
        assert!(!s.contains("bob@example.com"), "tool_result email leaked");
        assert!(s.contains("[EMAIL_ADDRESS_"));
        assert_eq!(
            manifest.len(),
            2,
            "only known text-bearing fields are masked"
        );

        // The masked tool_result round-trips back to plaintext.
        let masked_tr = v["messages"][1]["content"][0]["content"].as_str().unwrap();
        let restored = e.unmask(masked_tr, &manifest).unwrap();
        assert_eq!(restored, "the admin is reachable at bob@example.com");
    }

    #[test]
    fn context_management_protocol_tags_are_not_masked() {
        let e = engine();
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 100,
            "context_management": {
                "edits": [
                    {
                        "type": "clear_thinking_20251015",
                        "keep": {"type": "thinking_turns", "value": 1}
                    },
                    {
                        "type": "clear_tool_uses_20250919",
                        "trigger": {"type": "input_tokens", "value": 150000},
                        "clear_at_least": {"type": "input_tokens", "value": 50000},
                        "clear_tool_inputs": ["Read", "Write"],
                        "exclude_tools": ["Bash"]
                    }
                ]
            },
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "email me at alice@example.com"}
            ]}]
        });

        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();

        assert_eq!(
            v["context_management"]["edits"][0]["type"],
            serde_json::json!("clear_thinking_20251015")
        );
        assert_eq!(
            v["context_management"]["edits"][0]["keep"]["type"],
            serde_json::json!("thinking_turns")
        );
        assert_eq!(
            v["context_management"]["edits"][1]["clear_tool_inputs"],
            serde_json::json!(["Read", "Write"])
        );
        assert_eq!(
            v["context_management"]["edits"][1]["exclude_tools"],
            serde_json::json!(["Bash"])
        );
        let s = String::from_utf8(masked).unwrap();
        assert!(!s.contains("alice@example.com"));
        assert_eq!(manifest.len(), 1);
    }

    #[test]
    fn context_management_protocol_tags_survive_fallback_walk() {
        let e = engine();
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 100,
            "context_management": {
                "edits": [{
                    "type": "clear_thinking_20251015",
                    "keep": {"type": "thinking_turns", "value": 1}
                }]
            },
            "messages": [
                {"role": "system", "content": "ops contact is sue@example.com"}
            ]
        });

        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();
        let s = String::from_utf8(masked).unwrap();

        assert_eq!(
            v["context_management"]["edits"][0]["type"],
            serde_json::json!("clear_thinking_20251015")
        );
        assert_eq!(
            v["context_management"]["edits"][0]["keep"]["type"],
            serde_json::json!("thinking_turns")
        );
        assert!(!s.contains("sue@example.com"));
        assert_eq!(manifest.len(), 1);
    }

    #[test]
    fn fallback_walk_preserves_contract_fields_but_masks_tool_description() {
        let e = engine();
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 100,
            "tools": [{
                "name": "send_email",
                "description": "Send mail to ops@example.com",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email", "const": "schema@example.com"}
                    }
                }
            }],
            "output_config": {
                "format": {
                    "type": "json_schema",
                    "schema": {"const": "schema2@example.com"}
                }
            },
            "messages": [
                {"role": "system", "content": "fallback contact is user@example.com"}
            ]
        });

        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();
        let s = String::from_utf8(masked).unwrap();

        assert_eq!(v["tools"][0]["name"], serde_json::json!("send_email"));
        assert_eq!(
            v["tools"][0]["input_schema"]["properties"]["email"]["const"],
            serde_json::json!("schema@example.com")
        );
        assert_eq!(
            v["output_config"]["format"]["schema"]["const"],
            serde_json::json!("schema2@example.com")
        );
        assert!(!s.contains("ops@example.com"));
        assert!(!s.contains("user@example.com"));
        assert_eq!(manifest.len(), 2);
    }

    #[test]
    fn user_bypass_is_plaintext_in_upstream_prompt_only_for_wrapped_span() {
        let e = engine();
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "send >>bob@example.com<< and cc alice@example.com"}
            ]}]
        });

        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(masked).unwrap();

        assert!(s.contains("bob@example.com"));
        assert!(!s.contains(">>"));
        assert!(!s.contains("<<"));
        assert!(!s.contains("alice@example.com"));
        assert_eq!(manifest.len(), 1);
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

    #[test]
    fn metadata_user_id_is_telemetry_passthrough_other_metadata_still_masked() {
        // Regression guard for the egress-correctness fix: Claude Code stuffs an opaque
        // account/session id into `metadata.user_id` (Anthropic's abuse-correlation
        // telemetry). That field must reach the provider VERBATIM — masking it mangles
        // the telemetry (and is the root cause of the `cc-[US_BANK_NUMBER_…]` ids) — while
        // any other metadata leaf an unexpected client sets still gets masked.
        let e = engine();
        let user_id = "user_acct_session contact bob@example.com 4111111111111111";
        let body = serde_json::json!({
            "model": "m", "max_tokens": 10,
            "metadata": { "user_id": user_id, "note": "ping bob@example.com" },
            "messages": [{"role":"user","content":[{"type":"text","text":"hi"}]}]
        });
        let (masked, _manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();
        // Telemetry passthrough: user_id is byte-for-byte unchanged on the wire, even
        // though it carries strings that WOULD otherwise mask (an email + a card number).
        assert_eq!(
            v["metadata"]["user_id"].as_str().unwrap(),
            user_id,
            "metadata.user_id must egress verbatim (telemetry), got: {}",
            v["metadata"]["user_id"]
        );
        // Defense-in-depth preserved: a non-telemetry metadata leaf is still masked.
        assert!(
            !v["metadata"]["note"].as_str().unwrap().contains("bob@example.com"),
            "other metadata leaves must still be masked: {}",
            v["metadata"]["note"]
        );
    }

    // With a model `Ready`, `mask_request` runs the COLLECT → prewarm → MASK two-phase
    // path. Every marker across every leaf kind — system, user, assistant, tool_result,
    // tool_use input, tool `description`, request `metadata`, and a duplicate — must
    // still be masked exactly as the per-leaf path would; a `>>bypass<<` must pass
    // through; structure (incl. tool `input_schema`) is preserved; and the result
    // round-trips. This is the walker-level guard that the prewarm collect pass neither
    // corrupts the request nor changes the masked output, across the full leaf surface.
    #[test]
    fn ml_active_prewarm_masks_every_leaf_and_round_trips() {
        let e = crate::test_support::engine_with_mock_ml("ZZMARK");
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 100,
            "system": [{"type": "text", "text": "sys ZZMARK here"}],
            "tools": [{
                "name": "send",
                "description": "tool desc ZZMARK here",
                // input_schema is structural and must NOT be masked even with a marker.
                "input_schema": {"type": "object", "properties": {"q": {"const": "ZZMARK"}}}
            }],
            "metadata": {"note": "meta ZZMARK value"},
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello ZZMARK world"}]},
                // Byte-identical duplicate ⇒ prewarm dedupe path; both must mask.
                {"role": "user", "content": [{"type": "text", "text": "hello ZZMARK world"}]},
                {"role": "assistant", "content": [{"type": "text", "text": "reply ZZMARK ok"}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "result ZZMARK end"}
                ]},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "u1", "name": "do", "input": {"q": "input ZZMARK val"}}
                ]},
                {"role": "user", "content": [{"type": "text", "text": "keep >>ZZMARK<< verbatim"}]}
            ]
        });
        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(masked.clone()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();

        // Structure preserved (model is never walked).
        assert_eq!(v["model"], serde_json::json!("claude-opus-4-8"));
        // tool input_schema is left verbatim, so its structural "ZZMARK" const survives.
        assert_eq!(
            v["tools"][0]["input_schema"]["properties"]["q"]["const"],
            serde_json::json!("ZZMARK")
        );
        // Markers were masked to email tokens.
        assert!(s.contains("[EMAIL_ADDRESS_"), "markers should be masked: {s}");
        // tool description + metadata markers were masked (not left as plaintext).
        assert!(
            !v["tools"][0]["description"].as_str().unwrap().contains("ZZMARK"),
            "tool description marker should be masked: {}",
            v["tools"][0]["description"]
        );
        assert!(
            !v["metadata"]["note"].as_str().unwrap().contains("ZZMARK"),
            "metadata marker should be masked: {}",
            v["metadata"]["note"]
        );
        // Exactly TWO raw markers survive: the `>>bypass<<` span and the structural
        // tool input_schema const (both correct passthroughs). Everything else masked.
        assert_eq!(
            s.matches("ZZMARK").count(),
            2,
            "only the bypass marker and the input_schema const should survive: {s}"
        );
        assert!(!s.contains(">>") && !s.contains("<<"), "bypass wrappers stripped: {s}");

        // The masked user text round-trips back to the original.
        let masked_user = v["messages"][0]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            e.unmask(masked_user, &manifest).unwrap(),
            "hello ZZMARK world"
        );
    }

    // The prewarm phase must NOT change the masked output relative to the per-leaf
    // path. We can't toggle prewarm off inside the walker, but we CAN assert the
    // ML-active walker output equals masking each leaf through `engine.mask` directly
    // (the proven per-leaf reference) on a fresh engine with the same mock + session.
    #[test]
    fn ml_active_prewarm_output_equals_per_leaf_reference() {
        let walked = {
            let e = crate::test_support::engine_with_mock_ml("ZZMARK");
            let body = serde_json::json!({
                "model": "m", "max_tokens": 10,
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": "a ZZMARK b"}]},
                    {"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": "t", "content": "c ZZMARK d"}
                    ]}
                ]
            });
            let (masked, _m) = mask_request(&e, body.to_string().as_bytes()).unwrap();
            let v: Value = serde_json::from_slice(&masked).unwrap();
            (
                v["messages"][0]["content"][0]["text"].as_str().unwrap().to_string(),
                v["messages"][1]["content"][0]["content"].as_str().unwrap().to_string(),
            )
        };
        // Per-leaf reference: same mock, same fixed session bytes ⇒ identical tokens.
        let reference = {
            let e = crate::test_support::engine_with_mock_ml("ZZMARK");
            (
                e.mask("a ZZMARK b", Surface::UserMessage).unwrap().masked_text,
                e.mask("c ZZMARK d", Surface::ToolResult).unwrap().masked_text,
            )
        };
        assert_eq!(walked, reference, "prewarm path diverged from per-leaf masking");
    }
}
