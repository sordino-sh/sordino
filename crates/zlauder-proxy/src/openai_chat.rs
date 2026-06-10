//! OpenAI Chat Completions masking/unmasking.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use http::{StatusCode, header::CONTENT_TYPE};
use openai_wire::{
    ChatCompletionsRequest, ChatCompletionsResponse, OpenAIChunk, OpenAIContent, OpenAIContentPart,
    OpenAIDelta, OpenAIFunctionDelta, OpenAIMessage, OpenAIStreamChoice, OpenAIToolCallDelta,
};
use serde_json::{Map, Value};
use sse_core::{SseClient, SseEvent};
use zlauder_engine::{
    EngineError, MAX_TOKEN_LEN, MaskEngine, MaskStats, Surface, UnmaskManifest, token_regex,
};

use crate::{headers, monitor, routes, sse, state::AppState, walk};

const MAX_BODY: usize = 64 * 1024 * 1024;

/// `/v1/chat/completions` — mask request, relay, unmask response (JSON or SSE).
pub async fn chat_completions(State(st): State<AppState>, req: Request) -> Response {
    chat_completions_inner(st, req, None).await
}

pub async fn chat_completions_session(
    State(st): State<AppState>,
    axum::extract::Path(conversation): axum::extract::Path<String>,
    req: Request,
) -> Response {
    chat_completions_inner(st, req, Some(conversation)).await
}

async fn chat_completions_inner(
    st: AppState,
    req: Request,
    conversation: Option<String>,
) -> Response {
    if let Some(resp) = routes::secrets_gate(&st) {
        return resp;
    }
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return routes::err(StatusCode::BAD_REQUEST, "failed to read request body"),
    };

    let (masked, manifest) = match mask_body(&st, &body_bytes).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let conversation = conversation.or_else(|| monitor::conversation_from_headers(&parts.headers));
    let ticket = st.monitor.record_llm_request(
        "/v1/chat/completions",
        parts.method.as_str(),
        conversation,
        &masked,
        &manifest,
    );
    let record_id = ticket.id().to_string();
    if let Err(resp) = monitor::maybe_approve(&st, ticket).await {
        return resp;
    }

    st.monitor.record_dispatched(&record_id);
    let resp = match routes::send_upstream(&st, &parts, masked, "/v1/chat/completions").await {
        Ok(r) => r,
        Err(resp) => {
            st.monitor
                .record_upstream_error(&record_id, "upstream request failed");
            return resp;
        }
    };

    let status = resp.status();
    let up_headers = resp.headers().clone();
    let is_sse = up_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("text/event-stream"))
        .unwrap_or(false);
    let out_headers = headers::downstream_response_headers(&up_headers, true);
    let manifest = Arc::new(manifest);

    if is_sse {
        let guard = monitor::CompletionGuard::new(
            st.monitor.clone(),
            record_id.clone(),
            status.as_u16(),
            manifest.as_ref(),
        );
        let body = unmask_sse_body(
            Box::pin(resp.bytes_stream()),
            st.engine.clone(),
            manifest,
            guard,
        );
        routes::respond(status, out_headers, body)
    } else {
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                st.monitor
                    .record_upstream_error(&record_id, "upstream body error");
                return routes::err(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream body error: {e}"),
                );
            }
        };
        let out = unmask_response(st.engine.as_ref(), &manifest, &bytes)
            .unwrap_or_else(|_| bytes.to_vec());
        st.monitor
            .record_response(&record_id, status.as_u16(), Some(&out));
        routes::respond(status, out_headers, Body::from(out))
    }
}

#[allow(clippy::result_large_err)]
async fn mask_body(st: &AppState, body: &[u8]) -> Result<(Vec<u8>, UnmaskManifest), Response> {
    let result = if st.engine.ml_should_offload() {
        let engine = st.engine.clone();
        let body = body.to_vec();
        match tokio::task::spawn_blocking(move || mask_request(engine.as_ref(), &body)).await {
            Ok(r) => r,
            Err(join) => {
                return Err(routes::err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("masking task failed: {join}"),
                ));
            }
        }
    } else {
        mask_request(st.engine.as_ref(), body)
    };

    match result {
        Ok(x) => Ok(x),
        Err(MaskError::Json(e)) => Err(routes::err(
            StatusCode::BAD_REQUEST,
            &format!("unparseable request body, refusing to forward: {e}"),
        )),
        Err(MaskError::Engine(e)) => Err(routes::err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("masking error, request refused: {e}"),
        )),
    }
}

pub fn mask_request(
    engine: &MaskEngine,
    body: &[u8],
) -> Result<(Vec<u8>, UnmaskManifest), MaskError> {
    let mut req: ChatCompletionsRequest = serde_json::from_slice(body).map_err(MaskError::Json)?;
    let mut manifest = UnmaskManifest::new();
    // Phase 1 (ML-active only): collect every leaf and batch-prewarm the detection
    // cache so the mask pass below pays ONE batched inference, not N per-leaf ones.
    // No-op (and zero extra cost) when ML is off — byte-identical to before.
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

/// Phase-1 prewarm for the chat-completions walker — see the Anthropic walker's
/// `prewarm_request` for the full rationale. Collects every leaf in COLLECT mode and
/// hands them to one [`MaskEngine::prewarm_batch`]; skipped entirely when ML is not
/// `Ready`.
///
/// NOTE: `MaskWalker::request` folds `extra_thinking` into `extra` before walking.
/// That fold is idempotent (`or_insert` + the source is `take`n), so running it once
/// here in COLLECT mode and again in the mask pass yields the same `extra` the
/// single-pass path produced — and the prewarm covers those folded leaves.
fn prewarm_request(engine: &MaskEngine, req: &mut ChatCompletionsRequest) {
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
    if collector.request(req).is_err() {
        return;
    }
    let Some(leaves) = collector.collect.take() else {
        return;
    };
    let refs: Vec<(&str, Surface)> = leaves.iter().map(|(t, s)| (t.as_str(), *s)).collect();
    engine.prewarm_batch(&refs);
}

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
        "openai chat mask walk detection-cache stats"
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
    stats: MaskStats,
    /// When `Some`, the walker is in COLLECT mode: every leaf is cloned here (with its
    /// surface) and nothing is masked, so the prewarm pass can gather all leaves over
    /// the SAME traversal the mask pass uses. See `prewarm_request`.
    collect: Option<Vec<(String, Surface)>>,
}

impl MaskWalker<'_> {
    fn request(&mut self, req: &mut ChatCompletionsRequest) -> Result<(), EngineError> {
        if let Some(extra_thinking) = req.extra_thinking.take() {
            for (k, v) in extra_thinking {
                req.extra.entry(k).or_insert(v);
            }
        }
        for msg in req.messages.iter_mut() {
            self.message(msg)?;
        }
        if let Some(user) = req.user.as_mut() {
            self.str(user, Surface::UserMessage)?;
        }
        self.map_safe(&mut req.extra, Surface::UserMessage)?;
        Ok(())
    }

    fn message(&mut self, msg: &mut OpenAIMessage) -> Result<(), EngineError> {
        let surface = surface_for_role(&msg.role);
        if let Some(content) = msg.content.as_mut() {
            self.content(content, surface)?;
        }
        if msg.role == "tool"
            && let Some(id) = msg.tool_call_id.as_mut()
        {
            self.str(id, Surface::ToolResult)?;
        }
        if let Some(name) = msg.name.as_mut() {
            self.str(name, Surface::UserMessage)?;
        }
        if let Some(tool_calls) = msg.tool_calls.as_mut() {
            for call in tool_calls.iter_mut() {
                self.str(&mut call.function.arguments, Surface::ToolUseInput)?;
            }
        }
        self.map_safe(&mut msg.extra, surface)?;
        Ok(())
    }

    fn content(
        &mut self,
        content: &mut OpenAIContent,
        surface: Surface,
    ) -> Result<(), EngineError> {
        match content {
            OpenAIContent::Text(t) => self.str(t, surface)?,
            OpenAIContent::Parts(parts) => {
                for part in parts.iter_mut() {
                    match part {
                        OpenAIContentPart::Text { text, .. } => self.str(text, surface)?,
                        OpenAIContentPart::ImageUrl { image_url } => {
                            if !image_url.url.starts_with("data:") {
                                self.str(&mut image_url.url, surface)?;
                            }
                            self.map_safe(&mut image_url.extra, surface)?;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Single leaf sink: COLLECT mode clones the leaf for the prewarm batch (no
    /// mutation); MASK mode masks in place. `value_safe` routes through here too, so
    /// collect and mask cover the identical leaf set.
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
                    if preserves_contract_key(k) {
                        continue;
                    }
                    self.value_safe(val, surface)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn map_safe(
        &mut self,
        m: &mut Map<String, Value>,
        surface: Surface,
    ) -> Result<(), EngineError> {
        for (k, val) in m.iter_mut() {
            if preserves_contract_key(k) {
                continue;
            }
            self.value_safe(val, surface)?;
        }
        Ok(())
    }
}

fn preserves_contract_key(k: &str) -> bool {
    matches!(
        k,
        "model"
            | "tools"
            | "tool_choice"
            | "response_format"
            | "json_schema"
            | "schema"
            | "input_schema"
            | "parameters"
            | "guided_regex"
            | "guided_grammar"
            | "guided_choice"
    )
}

fn surface_for_role(role: &str) -> Surface {
    match role {
        "assistant" => Surface::AssistantText,
        "tool" => Surface::ToolResult,
        "system" | "developer" => Surface::SystemPrompt,
        _ => Surface::UserMessage,
    }
}

pub fn unmask_response(
    engine: &MaskEngine,
    manifest: &UnmaskManifest,
    body: &[u8],
) -> Result<Vec<u8>, serde_json::Error> {
    let mut resp: ChatCompletionsResponse = serde_json::from_slice(body)?;
    for choice in resp.choices.iter_mut() {
        unmask_message(engine, manifest, &mut choice.message);
        unmask_map(engine, manifest, &mut choice.extra);
    }
    unmask_map(engine, manifest, &mut resp.extra);
    serde_json::to_vec(&resp)
}

fn unmask_message(engine: &MaskEngine, manifest: &UnmaskManifest, msg: &mut OpenAIMessage) {
    if let Some(content) = msg.content.as_mut() {
        match content {
            OpenAIContent::Text(s) => unmask_str_assistant(engine, manifest, s),
            OpenAIContent::Parts(parts) => {
                for part in parts.iter_mut() {
                    if let OpenAIContentPart::Text { text, .. } = part {
                        unmask_str_assistant(engine, manifest, text);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(calls) = msg.tool_calls.as_mut() {
        for call in calls.iter_mut() {
            walk::unmask_str(engine, manifest, &mut call.function.arguments);
        }
    }
    unmask_map(engine, manifest, &mut msg.extra);
}

fn unmask_str_assistant(engine: &MaskEngine, manifest: &UnmaskManifest, text: &mut String) {
    if let Ok(out) = engine.unmask_assistant(text, manifest) {
        *text = out;
    }
}

fn unmask_map(engine: &MaskEngine, manifest: &UnmaskManifest, m: &mut Map<String, Value>) {
    for (_k, val) in m.iter_mut() {
        walk::unmask_value(engine, manifest, val);
    }
}

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

struct StreamState {
    client: SseClient<ByteStream, reqwest::Error>,
    engine: Arc<MaskEngine>,
    manifest: Arc<UnmaskManifest>,
    xform: OpenAISseUnmasker,
    queue: VecDeque<Bytes>,
    done: bool,
    guard: monitor::CompletionGuard,
}

pub fn unmask_sse_body(
    upstream: ByteStream,
    engine: Arc<MaskEngine>,
    manifest: Arc<UnmaskManifest>,
    guard: monitor::CompletionGuard,
) -> Body {
    let state = StreamState {
        client: SseClient::new(upstream),
        engine,
        manifest,
        xform: OpenAISseUnmasker::default(),
        queue: VecDeque::new(),
        done: false,
        guard,
    };

    let stream = futures::stream::unfold(state, |mut st| async move {
        loop {
            if let Some(b) = st.queue.pop_front() {
                return Some((Ok::<Bytes, std::convert::Infallible>(b), st));
            }
            if st.done {
                return None;
            }
            match st.client.next().await {
                Some(Ok(sse)) => enqueue(&mut st, sse),
                Some(Err(_)) => {
                    st.guard.upstream_error("upstream stream error");
                    st.done = true;
                }
                None => {
                    // Upstream closed without a [DONE] sentinel: still flush held tails
                    // (no-op if [DONE] already drained them) before finalizing.
                    flush_held(&mut st);
                    st.guard.complete();
                    st.done = true;
                }
            }
        }
    });

    Body::from_stream(stream)
}

/// Envelope (id/model/created/…) of the most recent chunk, so a flushed held tail can be
/// re-emitted as a valid chunk carrying the same stream identity, not a bare `{choices}`.
#[derive(Default, Clone)]
struct ChunkEnvelope {
    id: Option<String>,
    object: Option<String>,
    created: Option<u64>,
    model: Option<String>,
    system_fingerprint: Option<String>,
}

impl ChunkEnvelope {
    fn chunk(&self, choice: OpenAIStreamChoice) -> OpenAIChunk {
        OpenAIChunk {
            id: self.id.clone(),
            object: self.object.clone(),
            created: self.created,
            model: self.model.clone(),
            system_fingerprint: self.system_fingerprint.clone(),
            choices: vec![choice],
            ..Default::default()
        }
    }
    fn content_chunk(&self, index: i64, content: String) -> OpenAIChunk {
        self.chunk(OpenAIStreamChoice {
            index,
            delta: OpenAIDelta {
                content: Some(content),
                ..Default::default()
            },
            ..Default::default()
        })
    }
    fn tool_chunk(&self, choice: i64, call: i64, arguments: String) -> OpenAIChunk {
        self.chunk(OpenAIStreamChoice {
            index: choice,
            delta: OpenAIDelta {
                tool_calls: Some(vec![OpenAIToolCallDelta {
                    index: call,
                    function: Some(OpenAIFunctionDelta {
                        arguments: Some(arguments),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        })
    }
}

#[derive(Default)]
struct OpenAISseUnmasker {
    content_carry: HashMap<i64, String>,
    tool_carry: HashMap<(i64, i64), String>,
    /// Envelope of the latest chunk, used to mint a valid flushed-tail chunk at stream end.
    envelope: ChunkEnvelope,
}

impl OpenAISseUnmasker {
    fn process(
        &mut self,
        mut chunk: OpenAIChunk,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> OpenAIChunk {
        // Remember this chunk's envelope so a held-tail flush can reuse its identity.
        self.envelope = ChunkEnvelope {
            id: chunk.id.clone(),
            object: chunk.object.clone(),
            created: chunk.created,
            model: chunk.model.clone(),
            system_fingerprint: chunk.system_fingerprint.clone(),
        };
        for choice in chunk.choices.iter_mut() {
            if let Some(content) = choice.delta.content.take() {
                choice.delta.content =
                    self.buffered_content(choice.index, content, engine, manifest);
            }
            if let Some(calls) = choice.delta.tool_calls.as_mut() {
                for call in calls.iter_mut() {
                    if let Some(function) = call.function.as_mut()
                        && let Some(args) = function.arguments.take()
                    {
                        function.arguments =
                            self.buffered_tool(choice.index, call.index, args, engine, manifest);
                    }
                }
            }
            unmask_map(engine, manifest, &mut choice.delta.extra);
            unmask_map(engine, manifest, &mut choice.extra);
        }
        unmask_map(engine, manifest, &mut chunk.extra);
        chunk
    }

    fn buffered_content(
        &mut self,
        index: i64,
        incoming: String,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> Option<String> {
        let buf = {
            let c = self.content_carry.entry(index).or_default();
            c.push_str(&incoming);
            std::mem::take(c)
        };
        let (safe, held) = split_safe(&buf);
        self.content_carry.insert(index, held.to_string());
        let emitted = engine
            .unmask_assistant(safe, manifest)
            .unwrap_or_else(|_| safe.to_string());
        if emitted.is_empty() {
            None
        } else {
            Some(emitted)
        }
    }

    fn buffered_tool(
        &mut self,
        choice: i64,
        call: i64,
        incoming: String,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> Option<String> {
        let key = (choice, call);
        let buf = {
            let c = self.tool_carry.entry(key).or_default();
            c.push_str(&incoming);
            std::mem::take(c)
        };
        let (safe, held) = split_safe(&buf);
        self.tool_carry.insert(key, held.to_string());
        let emitted = engine
            .unmask(safe, manifest)
            .unwrap_or_else(|_| safe.to_string());
        if emitted.is_empty() {
            None
        } else {
            Some(emitted)
        }
    }

    /// Drain any still-held partial-token tails at stream end: content tails per choice
    /// index, tool-arg tails per (choice, call). Mirrors the Anthropic relay's drain so a
    /// stream ending mid-incomplete-token does not silently drop its final fragment.
    fn drain(&mut self) -> (Vec<(i64, String)>, Vec<((i64, i64), String)>) {
        let content: Vec<(i64, String)> =
            self.content_carry.drain().filter(|(_, v)| !v.is_empty()).collect();
        let tool: Vec<((i64, i64), String)> =
            self.tool_carry.drain().filter(|(_, v)| !v.is_empty()).collect();
        (content, tool)
    }
}

/// Flush held partial-token tails (content + tool args) BEFORE the stream's terminal
/// sentinel — re-emitting each downstream as a valid chunk (reusing the last envelope) and
/// capturing it into the monitor through the same keys as the streaming path, so neither
/// the client nor the monitor loses a reply that ends mid-incomplete-token. Idempotent: a
/// second call after `drain()` emptied the carries is a no-op.
fn flush_held(st: &mut StreamState) {
    let (content, tool) = st.xform.drain();
    for (index, held) in content {
        let emitted = st
            .engine
            .unmask_assistant(&held, st.manifest.as_ref())
            .unwrap_or(held);
        if emitted.is_empty() {
            continue;
        }
        // Monitor copy is cleaned (marker + ANSI peeled); the forwarded chunk keeps it.
        let clean = sse::clean_capture(st.engine.as_ref(), &emitted);
        st.guard
            .capture(&format!("c{index}"), monitor::CapKind::Text, "assistant", &clean);
        let chunk = st.xform.envelope.content_chunk(index, emitted);
        if let Ok(data) = serde_json::to_string(&chunk) {
            st.queue.push_back(frame(None, &data));
        }
    }
    for ((choice, call), held) in tool {
        let emitted = st
            .engine
            .unmask(&held, st.manifest.as_ref())
            .unwrap_or(held);
        if emitted.is_empty() {
            continue;
        }
        st.guard.capture(
            &format!("c{choice}t{call}"),
            monitor::CapKind::ToolUse,
            "tool_call",
            &emitted,
        );
        let chunk = st.xform.envelope.tool_chunk(choice, call, emitted);
        if let Ok(data) = serde_json::to_string(&chunk) {
            st.queue.push_back(frame(None, &data));
        }
    }
}

fn enqueue(st: &mut StreamState, sse: SseEvent) {
    if sse.data.trim() == "[DONE]" {
        // Flush any held tail BEFORE the terminal sentinel — a client stops reading at
        // [DONE], so a tail emitted after it would be lost.
        flush_held(st);
        st.queue.push_back(frame(sse.event.as_deref(), "[DONE]"));
        return;
    }
    match serde_json::from_str::<OpenAIChunk>(&sse.data) {
        Ok(chunk) => {
            let out = st
                .xform
                .process(chunk, st.engine.as_ref(), st.manifest.as_ref());
            // Mirror the unmasked reply onto the monitor record as it streams.
            capture_chunk(&mut st.guard, st.engine.as_ref(), &out);
            // A finish_reason (or trailing usage) chunk is protocol-terminal for a client;
            // flush any held tail BEFORE it so a client that stops at finish_reason still
            // receives the final fragment, not only one that reads through to [DONE].
            let terminal =
                out.usage.is_some() || out.choices.iter().any(|c| c.finish_reason.is_some());
            let has_content = out
                .choices
                .iter()
                .any(|c| c.delta.content.is_some() || c.delta.tool_calls.is_some());
            let event = sse.event.as_deref();
            if terminal && has_content {
                // One chunk carrying BOTH content and a terminal marker (non-standard, but
                // some OpenAI-compatible backends do it): emit its content FIRST, then the
                // held tail, then a terminal-only chunk — otherwise the flushed tail jumps
                // ahead of the very content it trails, reversing the wire and diverging it
                // from the captured order.
                let mut content_part = out.clone();
                content_part.usage = None;
                for c in content_part.choices.iter_mut() {
                    c.finish_reason = None;
                }
                if let Ok(data) = serde_json::to_string(&content_part) {
                    st.queue.push_back(frame(event, &data));
                }
                flush_held(st);
                let mut term_part = out;
                for c in term_part.choices.iter_mut() {
                    c.delta = OpenAIDelta::default();
                }
                if let Ok(data) = serde_json::to_string(&term_part) {
                    st.queue.push_back(frame(event, &data));
                }
            } else {
                if terminal {
                    flush_held(st);
                }
                if let Ok(data) = serde_json::to_string(&out) {
                    st.queue.push_back(frame(event, &data));
                }
            }
        }
        Err(_) => st.queue.push_back(frame(sse.event.as_deref(), &sse.data)),
    }
}

/// Capture the unmasked assistant content + tool-call args from one re-emitted chunk into
/// the monitor's response accumulator (one block per choice / per tool call). Assistant
/// content is cleaned of reveal-marker + ANSI for the monitor copy (the forwarded chunk
/// keeps its decoration); the tool NAME (carried on the first delta of a tool call) is
/// recorded so the captured surface renders `name(args)` and folds out of the next delta.
fn capture_chunk(guard: &mut monitor::CompletionGuard, engine: &MaskEngine, chunk: &OpenAIChunk) {
    for choice in &chunk.choices {
        if let Some(content) = &choice.delta.content {
            let clean = sse::clean_capture(engine, content);
            guard.capture(
                &format!("c{}", choice.index),
                monitor::CapKind::Text,
                "assistant",
                &clean,
            );
        }
        if let Some(calls) = &choice.delta.tool_calls {
            for call in calls {
                let key = format!("c{}t{}", choice.index, call.index);
                // The function name rides only on the first delta of a tool call; record
                // it under the args key so the capture renders `name(canonical_args)`.
                if let Some(name) = call.function.as_ref().and_then(|f| f.name.as_deref())
                    && !name.is_empty()
                {
                    guard.start_tool(&key, name);
                }
                if let Some(args) = call.function.as_ref().and_then(|f| f.arguments.as_ref()) {
                    guard.capture(&key, monitor::CapKind::ToolUse, "tool_call", args);
                }
            }
        }
    }
}

fn frame(event: Option<&str>, data: &str) -> Bytes {
    let mut s = String::new();
    if let Some(event) = event {
        s.push_str("event: ");
        s.push_str(event);
        s.push('\n');
    }
    s.push_str("data: ");
    s.push_str(data);
    s.push_str("\n\n");
    Bytes::from(s)
}

enum Classify {
    Complete,
    Partial,
    No,
}

fn classify(tail: &str) -> Classify {
    if let Some(m) = token_regex().find(tail)
        && m.start() == 0
    {
        return Classify::Complete;
    }
    if tail.len() > MAX_TOKEN_LEN {
        return Classify::No;
    }
    for &c in &tail.as_bytes()[1..] {
        let ok = c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_' || c.is_ascii_hexdigit();
        if !ok {
            return Classify::No;
        }
    }
    Classify::Partial
}

fn split_safe(buf: &str) -> (&str, &str) {
    match buf.rfind('[') {
        None => (buf, ""),
        Some(i) => match classify(&buf[i..]) {
            Classify::Partial => (&buf[..i], &buf[i..]),
            Classify::Complete | Classify::No => (buf, ""),
        },
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
                prefix: "<".into(),
                suffix: ">".into(),
            },
            ..Default::default()
        };
        MaskEngine::new(cfg).unwrap()
    }

    #[test]
    fn masks_messages_multipart_tool_results_and_request_tool_args() {
        let e = engine();
        let body = serde_json::json!({
            "model": "gpt-test",
            "user": "alice@example.com",
            "messages": [
                {"role": "system", "content": "ops: sys@example.com"},
                {"role": "user", "content": [
                    {"type": "text", "text": "mail bob@example.com"},
                    {"type": "image_url", "image_url": {"url": "https://x.test/u/carol@example.com.png"}}
                ]},
                {"role": "tool", "tool_call_id": "call_1", "content": "tool saw dana@example.com"},
                {"role": "assistant", "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"email\":\"erin@example.com\"}"}
                }]}
            ],
            "x_note": {"owner": "frank@example.com"}
        });

        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(masked).unwrap();

        for plain in [
            "alice@example.com",
            "sys@example.com",
            "bob@example.com",
            "carol@example.com",
            "dana@example.com",
            "erin@example.com",
            "frank@example.com",
        ] {
            assert!(!s.contains(plain), "leaked {plain}: {s}");
        }
        assert!(s.contains("[EMAIL_ADDRESS_"));
        assert_eq!(manifest.len(), 7);
    }

    #[test]
    fn preserves_tool_schemas_structured_outputs_model_ids_and_base64() {
        let e = engine();
        let body = serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "contact a@example.com"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "send_email",
                    "description": "Send email to someone@example.com",
                    "parameters": {
                        "type": "object",
                        "properties": {"email": {"type": "string", "format": "email"}}
                    }
                }
            }],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "Contact", "schema": {"const": "schema@example.com"}}
            },
            "x_blob": {"type": "base64", "data": "YWxpY2VAZXhhbXBsZS5jb20="}
        });

        let (masked, _manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();

        assert_eq!(v["model"], "gpt-test");
        assert_eq!(
            v["tools"][0]["function"]["description"],
            "Send email to someone@example.com"
        );
        assert_eq!(
            v["response_format"]["json_schema"]["schema"]["const"],
            "schema@example.com"
        );
        assert_eq!(v["x_blob"]["data"], "YWxpY2VAZXhhbXBsZS5jb20=");
        assert!(
            !v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("a@example.com")
        );
    }

    #[test]
    fn unmask_response_decorates_content_not_tool_arguments() {
        let e = engine_marked();
        let (_masked, manifest) = mask_request(
            &e,
            serde_json::json!({
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "write bob@example.com"}]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let token = manifest.entries[0].token_handle.clone();
        let resp = serde_json::json!({
            "id": "chatcmpl_1",
            "object": "chat.completion",
            "model": "gpt-test",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": format!("ok {token}"),
                    "tool_calls": [{
                        "id": "call_1", "type": "function",
                        "function": {"name": "send", "arguments": format!("{{\"email\":\"{token}\"}}")}
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });

        let out = unmask_response(&e, &manifest, resp.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            v["choices"][0]["message"]["content"],
            "ok <bob@example.com>"
        );
        assert_eq!(
            v["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
            "{\"email\":\"bob@example.com\"}"
        );
    }

    #[test]
    fn sse_preserves_done_usage_and_unmasks_chunk() {
        let e = engine();
        let masked = e.mask("bob@example.com", Surface::UserMessage).unwrap();
        let token = masked.manifest.entries[0].token_handle.clone();
        let mut x = OpenAISseUnmasker::default();

        let chunk = serde_json::from_value::<OpenAIChunk>(serde_json::json!({
            "id": "1",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"content": format!("hi {token}")}, "finish_reason": null}]
        }))
        .unwrap();
        let out = x.process(chunk, &e, &masked.manifest);
        assert_eq!(
            out.choices[0].delta.content.as_deref(),
            Some("hi bob@example.com")
        );

        let usage = serde_json::from_value::<OpenAIChunk>(serde_json::json!({
            "choices": [],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
        }))
        .unwrap();
        let out = x.process(usage, &e, &masked.manifest);
        assert!(out.choices.is_empty());
        assert_eq!(out.usage.unwrap().total_tokens, 3);
    }

    // With a model `Ready`, `mask_request` runs the COLLECT → prewarm → MASK two-phase
    // path. Confirms every marker — across user/assistant/tool messages, a duplicate,
    // AND a top-level provider field (which `request` folds from `extra_thinking` into
    // `extra` on BOTH passes — the fold is idempotent) — is masked, and structure is
    // preserved.
    #[test]
    fn ml_active_prewarm_masks_messages_and_extra() {
        let e = crate::test_support::engine_with_mock_ml("ZZMARK");
        let body = serde_json::json!({
            "model": "gpt-4o",
            "x_provider_note": "note ZZMARK here", // unknown top-level ⇒ extra/extra_thinking
            "messages": [
                {"role": "system", "content": "sys ZZMARK"},
                {"role": "user", "content": "hi ZZMARK there"},
                {"role": "user", "content": "hi ZZMARK there"}, // duplicate
                {"role": "assistant", "content": "ok ZZMARK done"},
                {"role": "tool", "tool_call_id": "c1", "content": "tool ZZMARK out"}
            ]
        });
        let (masked, _manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(masked.clone()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();

        assert_eq!(v["model"], serde_json::json!("gpt-4o"));
        assert!(s.contains("[EMAIL_ADDRESS_"), "markers masked: {s}");
        // No raw marker leaks anywhere (messages OR the folded top-level field).
        assert_eq!(s.matches("ZZMARK").count(), 0, "no marker should leak: {s}");
    }
}
