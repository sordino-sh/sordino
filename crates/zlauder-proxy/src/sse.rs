//! Streaming (SSE) response unmasking.
//!
//! A token like `[EMAIL_ADDRESS_ab12cd34ef90]` can be split across two
//! `text_delta` frames. We unmask at the JSON-text level with a per-content-
//! block carry buffer: emit only the prefix that provably cannot contain a
//! straddling token; hold the rest until it closes (then unmask) or grows past
//! the max token length (then it's provably not a token and is released).

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;

use anthropic_wire::ApiContentBlock;
use anthropic_wire::parser::{ContentBlockDelta, StreamEvent};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use sse_core::{SseClient, SseEvent};
use zlauder_engine::{MAX_TOKEN_LEN, MaskEngine, UnmaskManifest, token_regex};

use crate::monitor::{CapKind, CompletionGuard};
use crate::walk::unmask_value;

// ---------------------------------------------------------------------------
// Token-boundary core (pure)
// ---------------------------------------------------------------------------

enum Classify {
    /// `tail` begins with a complete, closed token.
    Complete,
    /// `tail` is a viable but incomplete token prefix — hold it.
    Partial,
    /// `tail` is provably not (the start of) a token — safe to release.
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
    // Every byte after the opening '[' must be a possible token character
    // (entity part is A-Z/0-9/_, hash part is 0-9a-f). Anything else — a space,
    // a ']' that didn't close a valid token, a non-hex letter — means not a token.
    for &c in &tail.as_bytes()[1..] {
        let ok = c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_' || c.is_ascii_hexdigit();
        if !ok {
            return Classify::No;
        }
    }
    Classify::Partial
}

/// Split `buf` into `(safe_to_emit, must_hold)`. The held part is at most one
/// partial token; everything before it is safe.
fn split_safe(buf: &str) -> (&str, &str) {
    match buf.rfind('[') {
        None => (buf, ""),
        Some(i) => match classify(&buf[i..]) {
            Classify::Partial => (&buf[..i], &buf[i..]),
            Classify::Complete | Classify::No => (buf, ""),
        },
    }
}

// ---------------------------------------------------------------------------
// Per-stream transform
// ---------------------------------------------------------------------------

/// Whether an unmasked delta is decorated with the reveal marker. Only assistant
/// prose (`text_delta`) is `Reveal`; tool-input/compaction deltas are `Plain`.
#[derive(Clone, Copy)]
enum Wrap {
    Reveal,
    Plain,
}

/// The delta kind of a content block, remembered per block index so a HELD partial-token
/// tail is flushed (at `ContentBlockStop` / stream drain) as the block's TRUE kind — not
/// blindly as a `text_delta`. Without this, a held tool-args / compaction tail was
/// re-emitted downstream as assistant text AND captured into the monitor as assistant
/// prose, mis-attributing machine context to the reply.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldKind {
    Text,
    Compaction,
    InputJson,
}

impl HeldKind {
    /// Reveal-marker policy for the SAFE (resolvable) prefix of this block: assistant
    /// prose is decorated; machine context (compaction / tool input) is left plain.
    fn wrap(self) -> Wrap {
        match self {
            HeldKind::Text => Wrap::Reveal,
            HeldKind::Compaction | HeldKind::InputJson => Wrap::Plain,
        }
    }

    /// Rebuild a [`ContentBlockDelta`] of this kind around `text`.
    fn delta(self, text: String) -> ContentBlockDelta {
        match self {
            HeldKind::Text => ContentBlockDelta::TextDelta { text },
            HeldKind::Compaction => ContentBlockDelta::CompactionDelta { content: text },
            HeldKind::InputJson => ContentBlockDelta::InputJsonDelta { partial_json: text },
        }
    }
}

/// Stateful per-response unmasker. One per streamed response.
#[derive(Default)]
pub struct SseUnmasker {
    /// Held partial-token tail per content-block index.
    carry: HashMap<u32, String>,
    /// The delta kind of each content-block index, so a held tail flushes as its true kind.
    held_kind: HashMap<u32, HeldKind>,
}

impl SseUnmasker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Transform one parsed stream event into zero or more events to re-emit.
    pub fn process(
        &mut self,
        ev: StreamEvent,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> Vec<StreamEvent> {
        match ev {
            StreamEvent::ContentBlockStart { index, .. } => {
                self.carry.insert(index, String::new());
                vec![ev]
            }
            StreamEvent::ContentBlockStop { index } => {
                let mut out = Vec::new();
                if let Some(held) = self.carry.remove(&index)
                    && !held.is_empty()
                {
                    let flushed = engine.unmask(&held, manifest).unwrap_or(held);
                    if !flushed.is_empty() {
                        // Flush as the block's TRUE kind, not blindly as text.
                        let kind = self.held_kind.get(&index).copied().unwrap_or(HeldKind::Text);
                        out.push(StreamEvent::ContentBlockDelta {
                            index,
                            delta: kind.delta(flushed),
                        });
                    }
                }
                self.held_kind.remove(&index);
                out.push(StreamEvent::ContentBlockStop { index });
                out
            }
            StreamEvent::ContentBlockDelta { index, delta } => {
                self.delta(index, delta, engine, manifest)
            }
            // message_start / message_delta / message_stop / ping / error / unknown
            other => vec![other],
        }
    }

    fn delta(
        &mut self,
        index: u32,
        delta: ContentBlockDelta,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> Vec<StreamEvent> {
        match delta {
            // Assistant prose → display: the only delta the reveal marker decorates.
            ContentBlockDelta::TextDelta { text } => {
                self.buffered(index, text, HeldKind::Text, engine, manifest)
            }
            // Machine context that is re-sent upstream: never decorate.
            ContentBlockDelta::CompactionDelta { content } => {
                self.buffered(index, content, HeldKind::Compaction, engine, manifest)
            }
            ContentBlockDelta::InputJsonDelta { partial_json } => {
                // Token chars are all JSON-safe (never escaped), so a token can
                // only be split by a chunk boundary, not a JSON-escape boundary.
                // Tool input is consumed verbatim by a tool → never decorate.
                self.buffered(index, partial_json, HeldKind::InputJson, engine, manifest)
            }
            ContentBlockDelta::CitationsDelta { mut citation } => {
                unmask_value(engine, manifest, &mut citation);
                vec![StreamEvent::ContentBlockDelta {
                    index,
                    delta: ContentBlockDelta::CitationsDelta { citation },
                }]
            }
            // Thinking + signature stay tokenized (opaque); unknown deltas pass through.
            other => vec![StreamEvent::ContentBlockDelta {
                index,
                delta: other,
            }],
        }
    }

    fn buffered(
        &mut self,
        index: u32,
        incoming: String,
        kind: HeldKind,
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
    ) -> Vec<StreamEvent> {
        // Remember this block's kind so a later stop/drain flush re-emits its held tail
        // as the same kind (not as text).
        self.held_kind.insert(index, kind);
        let buf = {
            let c = self.carry.entry(index).or_default();
            c.push_str(&incoming);
            std::mem::take(c)
        };
        let (safe, held) = split_safe(&buf);
        // Only the `safe` prefix is unmasked here; `held` is at most one INCOMPLETE
        // token tail (never a resolvable token), so the reveal marker only ever needs
        // to apply on this path — the stop/drain flushes below stay plain.
        let emitted = match kind.wrap() {
            Wrap::Reveal => engine.unmask_assistant(safe, manifest),
            Wrap::Plain => engine.unmask(safe, manifest),
        }
        .unwrap_or_else(|_| safe.to_string());
        self.carry.insert(index, held.to_string());
        if emitted.is_empty() {
            Vec::new()
        } else {
            vec![StreamEvent::ContentBlockDelta {
                index,
                delta: kind.delta(emitted),
            }]
        }
    }

    /// Drain any still-held carry buffers (call on upstream end), each tagged with the
    /// block's kind so the caller re-emits/captures it as text / compaction / tool input.
    fn drain(&mut self) -> Vec<(u32, HeldKind, String)> {
        let held: Vec<(u32, String)> = self.carry.drain().filter(|(_, v)| !v.is_empty()).collect();
        held.into_iter()
            .map(|(i, v)| {
                let kind = self.held_kind.get(&i).copied().unwrap_or(HeldKind::Text);
                (i, kind, v)
            })
            .collect()
    }
}

#[cfg(test)]
fn text_delta(index: u32, text: String) -> StreamEvent {
    StreamEvent::ContentBlockDelta {
        index,
        delta: ContentBlockDelta::TextDelta { text },
    }
}

// ---------------------------------------------------------------------------
// SSE frame (re-)emission
// ---------------------------------------------------------------------------

fn event_name(ev: &StreamEvent) -> &'static str {
    match ev {
        StreamEvent::MessageStart { .. } => "message_start",
        StreamEvent::ContentBlockStart { .. } => "content_block_start",
        StreamEvent::ContentBlockDelta { .. } => "content_block_delta",
        StreamEvent::ContentBlockStop { .. } => "content_block_stop",
        StreamEvent::MessageDelta { .. } => "message_delta",
        StreamEvent::MessageStop => "message_stop",
        StreamEvent::Ping => "ping",
        StreamEvent::Error { .. } => "error",
        _ => "unknown",
    }
}

fn frame(name: &str, data: &str) -> Bytes {
    let mut s = String::with_capacity(name.len() + data.len() + 16);
    s.push_str("event: ");
    s.push_str(name);
    s.push('\n');
    s.push_str("data: ");
    s.push_str(data);
    s.push_str("\n\n");
    Bytes::from(s)
}

fn frame_for(ev: &StreamEvent) -> Bytes {
    match serde_json::to_string(ev) {
        Ok(data) => frame(event_name(ev), &data),
        Err(_) => Bytes::new(),
    }
}

// ---------------------------------------------------------------------------
// Body builder
// ---------------------------------------------------------------------------

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

struct StreamState {
    client: SseClient<ByteStream, reqwest::Error>,
    engine: Arc<MaskEngine>,
    manifest: Arc<UnmaskManifest>,
    xform: SseUnmasker,
    queue: VecDeque<Bytes>,
    done: bool,
    /// Finalizes the monitor record: drain → Completed, upstream error →
    /// UpstreamError, drop-while-armed (client disconnect) → Aborted.
    guard: CompletionGuard,
}

/// Build an axum body that relays the upstream SSE stream, unmasking tokens in
/// text/tool-input/compaction deltas across frame boundaries. `guard` finalizes
/// the monitor lifecycle when the stream ends or the client disconnects.
pub fn unmask_sse_body(
    upstream: ByteStream,
    engine: Arc<MaskEngine>,
    manifest: Arc<UnmaskManifest>,
    guard: CompletionGuard,
) -> axum::body::Body {
    let state = StreamState {
        client: SseClient::new(upstream),
        engine,
        manifest,
        xform: SseUnmasker::new(),
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
                    for (index, kind, held) in st.xform.drain() {
                        let flushed = st
                            .engine
                            .unmask(&held, st.manifest.as_ref())
                            .unwrap_or(held);
                        if !flushed.is_empty() {
                            // Re-emit the held tail as its TRUE kind and capture through the
                            // same classifier as the streaming path (compaction → not
                            // captured; tool input → tool_use; text → assistant prose).
                            let ev = StreamEvent::ContentBlockDelta {
                                index,
                                delta: kind.delta(flushed),
                            };
                            capture_event(&mut st.guard, st.engine.as_ref(), &ev);
                            st.queue.push_back(frame_for(&ev));
                        }
                    }
                    st.guard.complete();
                    st.done = true;
                }
            }
        }
    });

    axum::body::Body::from_stream(stream)
}

fn enqueue(st: &mut StreamState, sse: SseEvent) {
    match serde_json::from_str::<StreamEvent>(&sse.data) {
        Ok(ev) => {
            let out = st
                .xform
                .process(ev, st.engine.as_ref(), st.manifest.as_ref());
            // Mirror exactly what we forward downstream onto the monitor record (already
            // unmasked), so the operator sees the reply on THIS turn as it streams.
            for o in &out {
                capture_event(&mut st.guard, st.engine.as_ref(), o);
            }
            for o in out {
                st.queue.push_back(frame_for(&o));
            }
        }
        // Unparseable payload: relay verbatim rather than break the stream.
        Err(_) => st
            .queue
            .push_back(frame(sse.event.as_deref().unwrap_or("message"), &sse.data)),
    }
}

/// Clean an assistant-text fragment for the MONITOR copy: peel the configured reveal
/// marker, then strip terminal/ANSI escapes. The forwarded stream keeps the decoration
/// (the user's in-conversation unmask insight); the captured copy is the clean reply, so
/// it matches the re-masked re-send and folds out of the next turn's delta. Shared by all
/// three relay paths (Anthropic here + both OpenAI relays). Tool args are never decorated,
/// so they are captured verbatim and do NOT go through this.
pub(crate) fn clean_capture(engine: &MaskEngine, text: &str) -> String {
    let demarked = engine.strip_reveal_marker(text);
    strip_terminal_codes(&demarked).into_owned()
}

/// Strip ANSI/VT terminal escape sequences (a CSI `ESC [ … final-byte`, plus a lone
/// `ESC`). The monitor capture holds the CLEAN reply — terminal control bytes are the
/// client's display concern, never part of the stored reply, and they would stop a
/// captured reply from matching the un-decorated re-send. Independent of the
/// configurable reveal marker (default `⟦`/`⟧`; ANSI is a user option this still strips).
/// Borrow-free when no `ESC`.
fn strip_terminal_codes(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains('\u{1b}') {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // ESC: for a CSI (`ESC [`) consume through the final byte (0x40..=0x7E);
        // for any other escape just drop the ESC itself.
        if chars.peek() == Some(&'[') {
            chars.next(); // '['
            for p in chars.by_ref() {
                if ('@'..='~').contains(&p) {
                    break;
                }
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Capture the unmasked assistant text / tool-call args from one re-emitted stream event
/// into the monitor's response accumulator. Thinking/signature blocks stay opaque and are
/// not captured; compaction deltas are machine context (re-sent upstream), not the reply.
fn capture_event(guard: &mut CompletionGuard, engine: &MaskEngine, ev: &StreamEvent) {
    // A tool-call's NAME rides only on the block start (the InputJsonDelta fragments
    // carry args only). Record it under the SAME key the args capture uses (`j{index}`)
    // so the captured surface renders as `name(args)` and folds out of the next delta.
    if let StreamEvent::ContentBlockStart { index, content_block } = ev
        && let ApiContentBlock::ToolUse { name, .. } = content_block
    {
        guard.start_tool(&format!("j{index}"), name);
    }
    if let StreamEvent::ContentBlockDelta { index, delta } = ev {
        match delta {
            ContentBlockDelta::TextDelta { text } => {
                // The forwarded stream keeps the reveal decoration (the user's
                // in-conversation unmask insight). The MONITOR copy is the CLEAN reply:
                // peel the configured reveal marker (symmetric with the engine's
                // strip-on-resend, so a custom marker is handled too) AND any terminal
                // escape codes (symmetric with the client storing an un-decorated
                // transcript). That clean form matches the re-masked re-send, so a
                // captured reply folds out of the next turn's delta.
                let clean = clean_capture(engine, text);
                guard.capture(&format!("t{index}"), CapKind::Text, "assistant", &clean);
            }
            ContentBlockDelta::InputJsonDelta { partial_json } => {
                // Tool args are never decorated and are consumed verbatim by tools.
                guard.capture(
                    &format!("j{index}"),
                    CapKind::ToolUse,
                    &format!("tool_use[{index}]"),
                    partial_json,
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anthropic_wire::ApiContentBlock;
    use zlauder_engine::{EngineConfig, Surface};

    fn engine() -> MaskEngine {
        // Neutral test engine: reveal marker OFF (it is ON by default) so unmask-mechanics
        // assertions see bare values; marker behavior is exercised by dedicated marker tests.
        let cfg = EngineConfig {
            reveal_marker: zlauder_engine::RevealMarker {
                enabled: false,
                ..Default::default()
            },
            ..EngineConfig::default()
        };
        MaskEngine::new(cfg).unwrap()
    }

    fn collect_text(evs: Vec<StreamEvent>) -> String {
        let mut s = String::new();
        for ev in evs {
            if let StreamEvent::ContentBlockDelta {
                delta: ContentBlockDelta::TextDelta { text },
                ..
            } = ev
            {
                s.push_str(&text);
            }
        }
        s
    }

    // R1 gating test: split the token-bearing text at EVERY byte boundary.
    #[test]
    fn sse_split_token_every_boundary() {
        let e = engine();
        let m = e.mask("person@example.com", Surface::UserMessage).unwrap();
        let token = &m.manifest.entries[0].token_handle;
        let full = format!("contact {token} right now");
        let expected = e.unmask(&full, &m.manifest).unwrap();
        assert!(expected.contains("person@example.com"));

        for split in 0..=full.len() {
            if !full.is_char_boundary(split) {
                continue;
            }
            let (a, b) = full.split_at(split);
            let mut x = SseUnmasker::new();
            let start = StreamEvent::ContentBlockStart {
                index: 0,
                content_block: ApiContentBlock::Text {
                    text: String::new(),
                    cache_control: None,
                },
            };
            let mut got = String::new();
            x.process(start, &e, &m.manifest);
            for piece in [a, b] {
                got.push_str(&collect_text(x.process(
                    text_delta(0, piece.to_string()),
                    &e,
                    &m.manifest,
                )));
            }
            got.push_str(&collect_text(x.process(
                StreamEvent::ContentBlockStop { index: 0 },
                &e,
                &m.manifest,
            )));
            assert_eq!(got, expected, "mismatch at split index {split}");
        }
    }

    // The reveal marker wraps a streamed assistant value even when the token is
    // split across delta boundaries (it is unmasked once whole, in the safe prefix).
    #[test]
    fn sse_text_delta_wraps_revealed_value_across_split() {
        let cfg = EngineConfig {
            reveal_marker: zlauder_engine::RevealMarker {
                enabled: true,
                prefix: "<".into(),
                suffix: ">".into(),
            },
            ..Default::default()
        };
        let e = MaskEngine::new(cfg).unwrap();
        let m = e.mask("person@example.com", Surface::UserMessage).unwrap();
        let token = m.manifest.entries[0].token_handle.clone();
        let full = format!("contact {token} now");

        for split in 0..=full.len() {
            if !full.is_char_boundary(split) {
                continue;
            }
            let (a, b) = full.split_at(split);
            let mut x = SseUnmasker::new();
            x.process(
                StreamEvent::ContentBlockStart {
                    index: 0,
                    content_block: ApiContentBlock::Text {
                        text: String::new(),
                        cache_control: None,
                    },
                },
                &e,
                &m.manifest,
            );
            let mut got = String::new();
            for piece in [a, b] {
                got.push_str(&collect_text(x.process(
                    text_delta(0, piece.to_string()),
                    &e,
                    &m.manifest,
                )));
            }
            got.push_str(&collect_text(x.process(
                StreamEvent::ContentBlockStop { index: 0 },
                &e,
                &m.manifest,
            )));
            assert_eq!(
                got, "contact <person@example.com> now",
                "mismatch at split index {split}"
            );
        }
    }

    // Stray '[' in prose must not stall and must pass through unchanged.
    #[test]
    fn sse_stray_bracket_no_stall() {
        let e = engine();
        let m = UnmaskManifest::new();
        let mut x = SseUnmasker::new();
        x.process(
            StreamEvent::ContentBlockStart {
                index: 0,
                content_block: ApiContentBlock::Text {
                    text: String::new(),
                    cache_control: None,
                },
            },
            &e,
            &m,
        );
        let mut got = String::new();
        for piece in ["the cost is [50 ", "dollars] total"] {
            got.push_str(&collect_text(x.process(
                text_delta(0, piece.to_string()),
                &e,
                &m,
            )));
        }
        got.push_str(&collect_text(x.process(
            StreamEvent::ContentBlockStop { index: 0 },
            &e,
            &m,
        )));
        assert_eq!(got, "the cost is [50 dollars] total");
    }

    // A stream that ends mid-token flushes the held remainder verbatim.
    #[test]
    fn sse_flush_partial_on_stop() {
        let e = engine();
        let m = UnmaskManifest::new();
        let mut x = SseUnmasker::new();
        x.process(
            StreamEvent::ContentBlockStart {
                index: 0,
                content_block: ApiContentBlock::Text {
                    text: String::new(),
                    cache_control: None,
                },
            },
            &e,
            &m,
        );
        let mut got = collect_text(x.process(text_delta(0, "see [EMAIL_ab".to_string()), &e, &m));
        got.push_str(&collect_text(x.process(
            StreamEvent::ContentBlockStop { index: 0 },
            &e,
            &m,
        )));
        assert_eq!(got, "see [EMAIL_ab");
    }

    // A held partial-token tail must flush at ContentBlockStop as the block's TRUE delta
    // kind — NOT blindly as a text_delta. Otherwise a tool-args / compaction tail is both
    // mis-emitted downstream as assistant text and mis-captured into the monitor reply.
    #[test]
    fn held_tail_flushes_as_its_true_kind() {
        let e = engine();
        let m = UnmaskManifest::new();

        let start = || StreamEvent::ContentBlockStart {
            index: 0,
            content_block: ApiContentBlock::Text {
                text: String::new(),
                cache_control: None,
            },
        };
        let stop_kind = |out: &[StreamEvent]| -> Option<&'static str> {
            out.iter().find_map(|ev| match ev {
                StreamEvent::ContentBlockDelta { delta, .. } => Some(match delta {
                    ContentBlockDelta::TextDelta { .. } => "text",
                    ContentBlockDelta::CompactionDelta { .. } => "compaction",
                    ContentBlockDelta::InputJsonDelta { .. } => "input_json",
                    _ => "other",
                }),
                _ => None,
            })
        };

        // Tool input ending mid-incomplete-token: held "[EMAIL_ab" must flush as InputJson.
        let mut x = SseUnmasker::new();
        x.process(start(), &e, &m);
        x.process(
            StreamEvent::ContentBlockDelta {
                index: 0,
                delta: ContentBlockDelta::InputJsonDelta {
                    partial_json: "{\"x\":\"[EMAIL_ab".to_string(),
                },
            },
            &e,
            &m,
        );
        let out = x.process(StreamEvent::ContentBlockStop { index: 0 }, &e, &m);
        assert_eq!(stop_kind(&out), Some("input_json"), "tool tail flushes as tool input, not text");

        // Compaction ending mid-incomplete-token: held tail must flush as Compaction.
        let mut x = SseUnmasker::new();
        x.process(start(), &e, &m);
        x.process(
            StreamEvent::ContentBlockDelta {
                index: 0,
                delta: ContentBlockDelta::CompactionDelta {
                    content: "ctx [EMAIL_ab".to_string(),
                },
            },
            &e,
            &m,
        );
        let out = x.process(StreamEvent::ContentBlockStop { index: 0 }, &e, &m);
        assert_eq!(stop_kind(&out), Some("compaction"), "compaction tail flushes as compaction, not text");
    }
}
