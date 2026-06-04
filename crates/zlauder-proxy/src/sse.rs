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

use anthropic_wire::parser::{ContentBlockDelta, StreamEvent};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use sse_core::{SseClient, SseEvent};
use zlauder_engine::{MAX_TOKEN_LEN, MaskEngine, UnmaskManifest, token_regex};

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

/// Stateful per-response unmasker. One per streamed response.
#[derive(Default)]
pub struct SseUnmasker {
    /// Held partial-token tail per content-block index.
    carry: HashMap<u32, String>,
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
                        out.push(text_delta(index, flushed));
                    }
                }
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
            ContentBlockDelta::TextDelta { text } => {
                self.buffered(index, text, engine, manifest, |t| {
                    ContentBlockDelta::TextDelta { text: t }
                })
            }
            ContentBlockDelta::CompactionDelta { content } => {
                self.buffered(index, content, engine, manifest, |t| {
                    ContentBlockDelta::CompactionDelta { content: t }
                })
            }
            ContentBlockDelta::InputJsonDelta { partial_json } => {
                // Token chars are all JSON-safe (never escaped), so a token can
                // only be split by a chunk boundary, not a JSON-escape boundary.
                self.buffered(index, partial_json, engine, manifest, |t| {
                    ContentBlockDelta::InputJsonDelta { partial_json: t }
                })
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
        engine: &MaskEngine,
        manifest: &UnmaskManifest,
        make: impl Fn(String) -> ContentBlockDelta,
    ) -> Vec<StreamEvent> {
        let buf = {
            let c = self.carry.entry(index).or_default();
            c.push_str(&incoming);
            std::mem::take(c)
        };
        let (safe, held) = split_safe(&buf);
        let emitted = engine
            .unmask(safe, manifest)
            .unwrap_or_else(|_| safe.to_string());
        self.carry.insert(index, held.to_string());
        if emitted.is_empty() {
            Vec::new()
        } else {
            vec![StreamEvent::ContentBlockDelta {
                index,
                delta: make(emitted),
            }]
        }
    }

    /// Drain any still-held carry buffers (call on upstream end).
    fn drain(&mut self) -> Vec<(u32, String)> {
        self.carry.drain().filter(|(_, v)| !v.is_empty()).collect()
    }
}

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
}

/// Build an axum body that relays the upstream SSE stream, unmasking tokens in
/// text/tool-input/compaction deltas across frame boundaries.
pub fn unmask_sse_body(
    upstream: ByteStream,
    engine: Arc<MaskEngine>,
    manifest: Arc<UnmaskManifest>,
) -> axum::body::Body {
    let state = StreamState {
        client: SseClient::new(upstream),
        engine,
        manifest,
        xform: SseUnmasker::new(),
        queue: VecDeque::new(),
        done: false,
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
                Some(Err(_)) => st.done = true,
                None => {
                    for (index, held) in st.xform.drain() {
                        let flushed = st
                            .engine
                            .unmask(&held, st.manifest.as_ref())
                            .unwrap_or(held);
                        if !flushed.is_empty() {
                            st.queue.push_back(frame_for(&text_delta(index, flushed)));
                        }
                    }
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
            for out in st
                .xform
                .process(ev, st.engine.as_ref(), st.manifest.as_ref())
            {
                st.queue.push_back(frame_for(&out));
            }
        }
        // Unparseable payload: relay verbatim rather than break the stream.
        Err(_) => st
            .queue
            .push_back(frame(sse.event.as_deref().unwrap_or("message"), &sse.data)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anthropic_wire::ApiContentBlock;
    use zlauder_engine::{EngineConfig, Surface};

    fn engine() -> MaskEngine {
        MaskEngine::new(EngineConfig::default()).unwrap()
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
}
