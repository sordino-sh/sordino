//! OpenAI Responses API masking/unmasking.

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
    ResponseCompletedEvent, ResponseContentPart, ResponseFunctionCallArgumentsDeltaEvent,
    ResponseFunctionCallItem, ResponseFunctionCallOutputItem, ResponseInputItem,
    ResponseMessageContent, ResponseMessageItem, ResponseObject, ResponseOutputItem,
    ResponseOutputTextDeltaEvent, ResponseStreamEvent, ResponsesInput, ResponsesRequest,
};
use serde_json::{Map, Value};
use sse_core::{SseClient, SseEvent};
use zlauder_engine::{
    EngineError, MAX_TOKEN_LEN, MaskEngine, MaskStats, Surface, UnmaskManifest, token_regex,
};

use crate::{headers, monitor, routes, sse, state::AppState, walk};

const MAX_BODY: usize = 64 * 1024 * 1024;

/// `/v1/responses` — mask request, relay, unmask response (JSON or SSE).
pub async fn responses(State(st): State<AppState>, req: Request) -> Response {
    responses_inner(st, req, None).await
}

pub async fn responses_session(
    State(st): State<AppState>,
    axum::extract::Path(conversation): axum::extract::Path<String>,
    req: Request,
) -> Response {
    responses_inner(st, req, Some(conversation)).await
}

async fn responses_inner(st: AppState, req: Request, conversation: Option<String>) -> Response {
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
        "/v1/responses",
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
    let resp = match routes::send_upstream(&st, &parts, masked, "/v1/responses").await {
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
    let mut req: ResponsesRequest = serde_json::from_slice(body).map_err(MaskError::Json)?;
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

/// Phase-1 prewarm for the responses walker — see the Anthropic walker's
/// `prewarm_request` for the full rationale. Collects every leaf in COLLECT mode and
/// hands them to one [`MaskEngine::prewarm_batch`]; skipped entirely when ML is not
/// `Ready`.
fn prewarm_request(engine: &MaskEngine, req: &mut ResponsesRequest) {
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
        "openai responses mask walk detection-cache stats"
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
    fn request(&mut self, req: &mut ResponsesRequest) -> Result<(), EngineError> {
        if let Some(input) = req.input.as_mut() {
            self.input(input)?;
        }
        if let Some(instructions) = req.instructions.as_mut() {
            self.str(instructions, Surface::SystemPrompt)?;
        }
        if let Some(metadata) = req.metadata.as_mut() {
            self.value_safe(metadata, Surface::UserMessage)?;
        }
        if let Some(user) = req.user.as_mut() {
            self.str(user, Surface::UserMessage)?;
        }
        self.map_safe(&mut req.extra, Surface::UserMessage)?;
        Ok(())
    }

    fn input(&mut self, input: &mut ResponsesInput) -> Result<(), EngineError> {
        match input {
            ResponsesInput::Text(text) => self.str(text, Surface::UserMessage)?,
            ResponsesInput::Items(items) => {
                for item in items {
                    self.input_item(item)?;
                }
            }
            ResponsesInput::Other(v) => self.value_safe(v, Surface::UserMessage)?,
            _ => {}
        }
        Ok(())
    }

    fn input_item(&mut self, item: &mut ResponseInputItem) -> Result<(), EngineError> {
        match item {
            ResponseInputItem::Message(msg) => self.message(msg)?,
            ResponseInputItem::FunctionCall(call) => self.function_call(call)?,
            ResponseInputItem::FunctionCallOutput(out) => self.function_output(out)?,
            ResponseInputItem::Other(v) => self.value_safe(v, Surface::UserMessage)?,
            _ => {}
        }
        Ok(())
    }

    fn message(&mut self, msg: &mut ResponseMessageItem) -> Result<(), EngineError> {
        let surface = surface_for_role(&msg.role);
        if let Some(content) = msg.content.as_mut() {
            self.content(content, surface)?;
        }
        self.map_safe(&mut msg.extra, surface)?;
        Ok(())
    }

    fn content(
        &mut self,
        content: &mut ResponseMessageContent,
        surface: Surface,
    ) -> Result<(), EngineError> {
        match content {
            ResponseMessageContent::Text(text) => self.str(text, surface)?,
            ResponseMessageContent::Parts(parts) => {
                for part in parts {
                    match part {
                        ResponseContentPart::InputText { text, extra }
                        | ResponseContentPart::OutputText { text, extra, .. } => {
                            self.str(text, surface)?;
                            self.map_safe(extra, surface)?;
                        }
                        ResponseContentPart::Refusal { refusal, extra } => {
                            self.str(refusal, Surface::AssistantText)?;
                            self.map_safe(extra, Surface::AssistantText)?;
                        }
                        ResponseContentPart::InputImage {
                            image_url, extra, ..
                        } => {
                            if let Some(url) = image_url.as_mut()
                                && !url.starts_with("data:")
                            {
                                self.str(url, surface)?;
                            }
                            self.map_safe(extra, surface)?;
                        }
                        ResponseContentPart::InputFile { extra, .. } => {
                            self.map_safe(extra, surface)?;
                        }
                        ResponseContentPart::Other(v) => self.value_safe(v, surface)?,
                        _ => {}
                    }
                }
            }
            ResponseMessageContent::Other(v) => self.value_safe(v, surface)?,
            _ => {}
        }
        Ok(())
    }

    fn function_call(&mut self, call: &mut ResponseFunctionCallItem) -> Result<(), EngineError> {
        self.str(&mut call.arguments, Surface::ToolUseInput)?;
        self.map_safe(&mut call.extra, Surface::ToolUseInput)?;
        Ok(())
    }

    fn function_output(
        &mut self,
        out: &mut ResponseFunctionCallOutputItem,
    ) -> Result<(), EngineError> {
        self.str(&mut out.output, Surface::ToolResult)?;
        self.map_safe(&mut out.extra, Surface::ToolResult)?;
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
                for item in a {
                    self.value_safe(item, surface)?;
                }
            }
            Value::Object(o) => {
                let is_base64 = o.get("type").and_then(Value::as_str) == Some("base64");
                for (k, val) in o {
                    if (is_base64 && k == "data") || preserves_contract_key(k) {
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
        for (k, val) in m {
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
            | "text"
            | "format"
            | "json_schema"
            | "schema"
            | "input_schema"
            | "parameters"
            | "id"
            | "item_id"
            | "call_id"
            | "file_id"
            | "filename"
            | "file_data"
            | "image_file"
            | "input_image"
            | "encrypted_content"
            | "signature"
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
    let mut resp: ResponseObject = serde_json::from_slice(body)?;
    unmask_response_object(engine, manifest, &mut resp);
    serde_json::to_vec(&resp)
}

fn unmask_response_object(
    engine: &MaskEngine,
    manifest: &UnmaskManifest,
    resp: &mut ResponseObject,
) {
    for item in &mut resp.output {
        unmask_output_item(engine, manifest, item);
    }
    if let Some(text) = resp.output_text.as_mut() {
        unmask_str_assistant(engine, manifest, text);
    }
    unmask_map(engine, manifest, &mut resp.extra);
}

fn unmask_output_item(
    engine: &MaskEngine,
    manifest: &UnmaskManifest,
    item: &mut ResponseOutputItem,
) {
    match item {
        ResponseOutputItem::Message(msg) => unmask_message(engine, manifest, msg),
        ResponseOutputItem::FunctionCall(call) => {
            walk::unmask_str(engine, manifest, &mut call.arguments);
            unmask_map(engine, manifest, &mut call.extra);
        }
        ResponseOutputItem::FunctionCallOutput(out) => {
            walk::unmask_str(engine, manifest, &mut out.output);
            unmask_map(engine, manifest, &mut out.extra);
        }
        ResponseOutputItem::Other(v) => walk::unmask_value(engine, manifest, v),
        _ => {}
    }
}

fn unmask_message(engine: &MaskEngine, manifest: &UnmaskManifest, msg: &mut ResponseMessageItem) {
    if let Some(content) = msg.content.as_mut() {
        match content {
            ResponseMessageContent::Text(text) => unmask_str_assistant(engine, manifest, text),
            ResponseMessageContent::Parts(parts) => {
                for part in parts {
                    match part {
                        ResponseContentPart::OutputText { text, extra, .. } => {
                            unmask_str_assistant(engine, manifest, text);
                            unmask_map(engine, manifest, extra);
                        }
                        ResponseContentPart::InputText { text, extra } => {
                            walk::unmask_str(engine, manifest, text);
                            unmask_map(engine, manifest, extra);
                        }
                        ResponseContentPart::Refusal { refusal, extra } => {
                            unmask_str_assistant(engine, manifest, refusal);
                            unmask_map(engine, manifest, extra);
                        }
                        ResponseContentPart::InputImage { extra, .. }
                        | ResponseContentPart::InputFile { extra, .. } => {
                            unmask_map(engine, manifest, extra);
                        }
                        ResponseContentPart::Other(v) => walk::unmask_value(engine, manifest, v),
                        _ => {}
                    }
                }
            }
            ResponseMessageContent::Other(v) => walk::unmask_value(engine, manifest, v),
            _ => {}
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
    for (_k, val) in m {
        walk::unmask_value(engine, manifest, val);
    }
}

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

struct StreamState {
    client: SseClient<ByteStream, reqwest::Error>,
    engine: Arc<MaskEngine>,
    manifest: Arc<UnmaskManifest>,
    xform: ResponsesSseUnmasker,
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
        xform: ResponsesSseUnmasker::default(),
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

type TextCarryKey = (Option<String>, Option<u64>, Option<u64>);
type ArgsCarryKey = (Option<String>, Option<u64>);

#[derive(Default)]
struct ResponsesSseUnmasker {
    text_carry: HashMap<TextCarryKey, String>,
    args_carry: HashMap<ArgsCarryKey, String>,
}

impl ResponsesSseUnmasker {
    fn process(
        &mut self,
        mut ev: ResponseStreamEvent,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> Vec<ResponseStreamEvent> {
        match &mut ev {
            ResponseStreamEvent::ResponseOutputTextDelta(delta) => {
                delta.delta = self.buffered_text(
                    (
                        delta.item_id.clone(),
                        delta.output_index,
                        delta.content_index,
                    ),
                    std::mem::take(&mut delta.delta),
                    engine,
                    manifest,
                );
                if delta.delta.is_empty() {
                    Vec::new()
                } else {
                    vec![ev]
                }
            }
            ResponseStreamEvent::ResponseFunctionCallArgumentsDelta(delta) => {
                delta.delta = self.buffered_args(
                    (delta.item_id.clone(), delta.output_index),
                    std::mem::take(&mut delta.delta),
                    engine,
                    manifest,
                );
                if delta.delta.is_empty() {
                    Vec::new()
                } else {
                    vec![ev]
                }
            }
            ResponseStreamEvent::ResponseOutputItemDone(done) => {
                if let Some(item) = done.item.as_mut() {
                    unmask_output_item(engine, manifest, item);
                }
                vec![ev]
            }
            ResponseStreamEvent::ResponseCompleted(completed)
            | ResponseStreamEvent::ResponseFailed(completed)
            | ResponseStreamEvent::ResponseIncomplete(completed) => {
                unmask_completed(engine, manifest, completed);
                vec![ev]
            }
            ResponseStreamEvent::Other(v) => {
                walk::unmask_value(engine, manifest, v);
                vec![ev]
            }
            _ => vec![ev],
        }
    }

    fn buffered_text(
        &mut self,
        key: (Option<String>, Option<u64>, Option<u64>),
        incoming: String,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> String {
        let buf = {
            let c = self.text_carry.entry(key.clone()).or_default();
            c.push_str(&incoming);
            std::mem::take(c)
        };
        let (safe, held) = split_safe(&buf);
        self.text_carry.insert(key, held.to_string());
        engine
            .unmask_assistant(safe, manifest)
            .unwrap_or_else(|_| safe.to_string())
    }

    fn buffered_args(
        &mut self,
        key: (Option<String>, Option<u64>),
        incoming: String,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> String {
        let buf = {
            let c = self.args_carry.entry(key.clone()).or_default();
            c.push_str(&incoming);
            std::mem::take(c)
        };
        let (safe, held) = split_safe(&buf);
        self.args_carry.insert(key, held.to_string());
        engine
            .unmask(safe, manifest)
            .unwrap_or_else(|_| safe.to_string())
    }

    /// Drain any still-held partial-token tails at stream end: output-text tails per
    /// (item_id, output_index, content_index), function-arg tails per (item_id,
    /// output_index). Mirrors the Anthropic relay so a stream ending mid-incomplete-token
    /// does not silently drop its final fragment.
    fn drain(&mut self) -> (Vec<(TextCarryKey, String)>, Vec<(ArgsCarryKey, String)>) {
        let text: Vec<(TextCarryKey, String)> =
            self.text_carry.drain().filter(|(_, v)| !v.is_empty()).collect();
        let args: Vec<(ArgsCarryKey, String)> =
            self.args_carry.drain().filter(|(_, v)| !v.is_empty()).collect();
        (text, args)
    }
}

/// Flush held partial-token tails (output text + function args) BEFORE the stream's
/// terminal sentinel — re-emitting each downstream as its true delta event and capturing
/// it through the same keys as the streaming path, so neither the client nor the monitor
/// loses a reply that ends mid-incomplete-token. Idempotent (a second call finds the
/// carries already drained).
fn flush_held(st: &mut StreamState) {
    let (text, args) = st.xform.drain();
    for ((item_id, output_index, content_index), held) in text {
        let emitted = st
            .engine
            .unmask_assistant(&held, st.manifest.as_ref())
            .unwrap_or(held);
        if emitted.is_empty() {
            continue;
        }
        // Same key shape as capture_event so the tail concatenates onto the right block.
        let key = format!("t:{item_id:?}:{output_index:?}:{content_index:?}");
        // Monitor copy is cleaned (marker + ANSI peeled); the forwarded event keeps it.
        let clean = sse::clean_capture(st.engine.as_ref(), &emitted);
        st.guard
            .capture(&key, monitor::CapKind::Text, "assistant", &clean);
        let ev = ResponseStreamEvent::ResponseOutputTextDelta(ResponseOutputTextDeltaEvent {
            item_id,
            output_index,
            content_index,
            delta: emitted,
            ..Default::default()
        });
        if let Ok(data) = serde_json::to_string(&ev) {
            st.queue
                .push_back(frame(Some("response.output_text.delta"), &data));
        }
    }
    for ((item_id, output_index), held) in args {
        let emitted = st
            .engine
            .unmask(&held, st.manifest.as_ref())
            .unwrap_or(held);
        if emitted.is_empty() {
            continue;
        }
        let key = format!("a:{item_id:?}:{output_index:?}");
        st.guard
            .capture(&key, monitor::CapKind::ToolUse, "tool_call", &emitted);
        let ev = ResponseStreamEvent::ResponseFunctionCallArgumentsDelta(
            ResponseFunctionCallArgumentsDeltaEvent {
                item_id,
                output_index,
                delta: emitted,
                ..Default::default()
            },
        );
        if let Ok(data) = serde_json::to_string(&ev) {
            st.queue
                .push_back(frame(Some("response.function_call_arguments.delta"), &data));
        }
    }
}

fn unmask_completed(
    engine: &MaskEngine,
    manifest: &UnmaskManifest,
    completed: &mut ResponseCompletedEvent,
) {
    if let Some(resp) = completed.response.as_mut() {
        unmask_response_object(engine, manifest, resp);
    }
    unmask_map(engine, manifest, &mut completed.extra);
}

fn enqueue(st: &mut StreamState, sse: SseEvent) {
    if sse.data.trim() == "[DONE]" {
        // Flush held tails BEFORE the terminal sentinel (a client stops at [DONE]).
        flush_held(st);
        st.queue.push_back(frame(sse.event.as_deref(), "[DONE]"));
        return;
    }
    match serde_json::from_str::<ResponseStreamEvent>(&sse.data) {
        Ok(ev) => {
            let out = st
                .xform
                .process(ev, st.engine.as_ref(), st.manifest.as_ref());
            // Mirror the unmasked reply onto the monitor record as it streams.
            for o in &out {
                capture_event(&mut st.guard, st.engine.as_ref(), o);
            }
            // A response.completed/failed/incomplete event is stream-terminal for a client;
            // flush any held tail BEFORE it so a delta-accumulating client that stops there
            // still receives the final fragment, not only one that reads through to [DONE].
            let terminal = out.iter().any(|o| {
                matches!(
                    o,
                    ResponseStreamEvent::ResponseCompleted(_)
                        | ResponseStreamEvent::ResponseFailed(_)
                        | ResponseStreamEvent::ResponseIncomplete(_)
                )
            });
            if terminal {
                flush_held(st);
            }
            for o in out {
                if let Ok(data) = serde_json::to_string(&o) {
                    st.queue.push_back(frame(sse.event.as_deref(), &data));
                }
            }
        }
        Err(_) => st.queue.push_back(frame(sse.event.as_deref(), &sse.data)),
    }
}

/// Capture the unmasked output-text + function-call args from one re-emitted Responses
/// event into the monitor's response accumulator (keyed per item / output index).
fn capture_event(
    guard: &mut monitor::CompletionGuard,
    engine: &MaskEngine,
    ev: &ResponseStreamEvent,
) {
    match ev {
        ResponseStreamEvent::ResponseOutputTextDelta(d) => {
            let key = format!("t:{:?}:{:?}:{:?}", d.item_id, d.output_index, d.content_index);
            // Monitor copy is the clean reply (marker + ANSI peeled); the forwarded event
            // keeps its decoration. Args are never decorated and are captured verbatim.
            let clean = sse::clean_capture(engine, &d.delta);
            guard.capture(&key, monitor::CapKind::Text, "assistant", &clean);
        }
        ResponseStreamEvent::ResponseFunctionCallArgumentsDelta(d) => {
            let key = format!("a:{:?}:{:?}", d.item_id, d.output_index);
            guard.capture(&key, monitor::CapKind::ToolUse, "tool_call", &d.delta);
        }
        // The function NAME rides on the item-done event (this Responses wire version has
        // no typed `output_item.added`). Record it under the SAME key the args deltas use
        // — `a:{item.id}:{output_index}`, since the args delta's `item_id` IS the item's
        // `id` — so the captured surface renders `name(canonical_args)` and folds out of
        // the next delta. A key mismatch just leaves it args-only (safe over-show).
        ResponseStreamEvent::ResponseOutputItemDone(done) => {
            if let Some(ResponseOutputItem::FunctionCall(call)) = done.item.as_ref()
                && !call.name.is_empty()
            {
                let key = format!("a:{:?}:{:?}", call.id, done.output_index);
                guard.start_tool(&key, &call.name);
            }
        }
        _ => {}
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
    fn masks_responses_request_text_surfaces_and_preserves_contracts() {
        let e = engine();
        let body = serde_json::json!({
            "model": "gpt-test",
            "instructions": "system contact sys@example.com",
            "input": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "mail user@example.com"}]},
                {"type": "function_call", "call_id": "call_1", "name": "lookup", "arguments": "{\"email\":\"toolin@example.com\"}"},
                {"type": "function_call_output", "call_id": "call_1", "output": "tool saw toolout@example.com"}
            ],
            "tools": [{"type": "function", "function": {"name": "send", "description": "send schema@example.com"}}],
            "text": {"format": {"type": "json_schema", "schema": {"const": "schema@example.com"}}},
            "x_note": {"owner": "extra@example.com"},
            "x_blob": {"type": "base64", "data": "dXNlckBleGFtcGxlLmNvbQ=="}
        });

        let (masked, manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(masked).unwrap();
        for plain in [
            "sys@example.com",
            "user@example.com",
            "toolin@example.com",
            "toolout@example.com",
            "extra@example.com",
        ] {
            assert!(!s.contains(plain), "leaked {plain}: {s}");
        }
        assert!(s.contains("schema@example.com"));
        assert!(s.contains("dXNlckBleGFtcGxlLmNvbQ=="));
        assert!(s.contains("[EMAIL_ADDRESS_"));
        assert_eq!(manifest.len(), 5);
    }

    #[test]
    fn unmask_response_decorates_output_text_not_tool_arguments() {
        let e = engine_marked();
        let masked = e.mask("bob@example.com", Surface::UserMessage).unwrap();
        let token = masked.manifest.entries[0].token_handle.clone();
        let resp = serde_json::json!({
            "id": "resp_1",
            "object": "response",
            "model": "gpt-test",
            "output": [
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": format!("ok {token}")}]},
                {"type": "function_call", "call_id": "call_1", "name": "send", "arguments": format!("{{\"email\":\"{token}\"}}")}
            ],
            "output_text": format!("summary {token}")
        });

        let out = unmask_response(&e, &masked.manifest, resp.to_string().as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["output"][0]["content"][0]["text"], "ok <bob@example.com>");
        assert_eq!(
            v["output"][1]["arguments"],
            "{\"email\":\"bob@example.com\"}"
        );
        assert_eq!(v["output_text"], "summary <bob@example.com>");
    }

    #[test]
    fn sse_buffers_split_output_text_and_tool_argument_tokens() {
        let e = engine();
        let masked = e.mask("stream@example.com", Surface::UserMessage).unwrap();
        let token = masked.manifest.entries[0].token_handle.clone();
        let split = token.len() / 2;
        let (a, b) = token.split_at(split);
        let mut x = ResponsesSseUnmasker::default();

        let ev1: ResponseStreamEvent = serde_json::from_value(serde_json::json!({
            "type": "response.output_text.delta",
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "delta": format!("hi {a}")
        }))
        .unwrap();
        let out = x.process(ev1, &e, &masked.manifest);
        let ResponseStreamEvent::ResponseOutputTextDelta(delta) = &out[0] else {
            panic!("expected text delta");
        };
        assert_eq!(delta.delta, "hi ");

        let ev2: ResponseStreamEvent = serde_json::from_value(serde_json::json!({
            "type": "response.output_text.delta",
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "delta": format!("{b} done")
        }))
        .unwrap();
        let out = x.process(ev2, &e, &masked.manifest);
        let ResponseStreamEvent::ResponseOutputTextDelta(delta) = &out[0] else {
            panic!("expected text delta");
        };
        assert_eq!(delta.delta, "stream@example.com done");

        let ev3: ResponseStreamEvent = serde_json::from_value(serde_json::json!({
            "type": "response.function_call_arguments.delta",
            "item_id": "call_1",
            "output_index": 1,
            "delta": format!("{{\"email\":\"{token}\"}}")
        }))
        .unwrap();
        let out = x.process(ev3, &e, &masked.manifest);
        let ResponseStreamEvent::ResponseFunctionCallArgumentsDelta(delta) = &out[0] else {
            panic!("expected args delta");
        };
        assert_eq!(delta.delta, "{\"email\":\"stream@example.com\"}");
    }

    // With a model `Ready`, `mask_request` runs the COLLECT → prewarm → MASK two-phase
    // path. Confirms markers across instructions, message input, a function call's
    // arguments, a function-call output, and a duplicate are all masked, with
    // structure preserved.
    #[test]
    fn ml_active_prewarm_masks_input_items() {
        let e = crate::test_support::engine_with_mock_ml("ZZMARK");
        let body = serde_json::json!({
            "model": "gpt-4o",
            "instructions": "follow ZZMARK rules",
            "input": [
                {"type": "message", "role": "user",
                 "content": [{"type": "input_text", "text": "ask ZZMARK now"}]},
                {"type": "message", "role": "user",
                 "content": [{"type": "input_text", "text": "ask ZZMARK now"}]}, // duplicate
                {"type": "function_call", "call_id": "c1", "name": "do",
                 "arguments": "{\"q\":\"arg ZZMARK\"}"},
                {"type": "function_call_output", "call_id": "c1", "output": "res ZZMARK"}
            ]
        });
        let (masked, _manifest) = mask_request(&e, body.to_string().as_bytes()).unwrap();
        let s = String::from_utf8(masked.clone()).unwrap();
        let v: Value = serde_json::from_slice(&masked).unwrap();

        assert_eq!(v["model"], serde_json::json!("gpt-4o"));
        assert!(s.contains("[EMAIL_ADDRESS_"), "markers masked: {s}");
        assert_eq!(s.matches("ZZMARK").count(), 0, "no marker should leak: {s}");
    }
}
