//! Monitor state: ring buffer, broadcast channel, approval waiters, and the
//! conversation/turn index. Holds all state-mutating methods.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, oneshot};
use zlauder_engine::UnmaskManifest;

use crate::zdr::PinnedMode;

use super::capture::{CapKind, ResponseCapture};
use super::delta::compute_delta;
use super::model::{
    ApprovalDecision, ConversationMeta, MonitorEvent, MonitorMode, MonitorSnapshot,
    RequestDecision, RequestRecord, ResponseProgress, Surface, TokenClass, TokenLedgerEntry,
    TokenPreview, TurnDelta,
};
use super::spans::{
    json_body_expand, json_body_redaction_pairs, now_ms, preview, redact_secret_values,
    redaction_pairs, spans_from_manifest, spans_from_values, token_previews,
};
use super::surfaces::{surfaces_from_body, surfaces_from_response_body};

const MAX_RECORDS: usize = 500;
/// Bytes of newly-captured streamed response text that must accumulate before the next
/// live progress frame is pushed. Coalesces the model's many small text deltas into a
/// handful of UI repaints per response (the upstream may stream a token at a time).
const PROGRESS_FLUSH_BYTES: usize = 160;
const APPROVAL_TIMEOUT_SECS: u64 = 300;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(APPROVAL_TIMEOUT_SECS);
const DEFAULT_MAX_PENDING_APPROVALS: usize = 32;
/// Cap on the per-conversation tracking maps (`conversation_anchors`, `labels`,
/// `turn_counts`, `last_seen`, …), evicted as a set by least-recently-seen.
const MAX_TRACKED_CONVERSATIONS: usize = 1024;
/// Hard cap on the durable session-token ledger. Generous (the secrets ledger
/// should hold a whole session's distinct values), oldest-evicted past it — a real
/// bound, logged when it trips, never a silent truncation.
const MAX_SESSION_TOKENS: usize = 5000;

/// Domain-level failure of a state mutation keyed by request id. The web layer
/// maps this to an HTTP status; the state layer stays framework-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecideError {
    /// No such request id (absent, or — for `decide` — not pending).
    Unknown,
}

/// Shared, cheaply-cloneable handle to the monitor.
#[derive(Clone)]
pub struct Monitor {
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<MonitorEvent>,
}

struct Inner {
    mode: MonitorMode,
    max_pending_approvals: usize,
    next_seq: u64,
    /// Newest-first ring buffer of records.
    records: VecDeque<RequestRecord>,
    waiters: HashMap<String, oneshot::Sender<ApprovalDecision>>,
    /// Per-conversation turn counter (monotonic, 1-based) — the source of
    /// `turn_index`. Evicted ONLY together with the conversation's anchor for the
    /// same LRU-cold victim (see [`evict_stale_conversation_state`]): a live
    /// conversation has a recent `last_seen` so it is never the victim, and a cold
    /// one re-mints from scratch on return anyway (its anchor is gone too), so the
    /// counter is never dropped out from under an in-flight lineage.
    turn_counts: HashMap<String, u32>,
    /// Per-conversation HUMAN-turn counter (monotonic, 1-based) — the source of
    /// `RequestRecord::human_turn_index`. Incremented only when a request carries MORE
    /// `user_input` surfaces than the prior turn (a genuine new human prompt), so the N
    /// tool-cycle requests of one prompt share its index. Evicted as a SET with the other
    /// per-conversation maps (see [`evict_stale_conversation_state`]); a returning cold
    /// conversation re-mints a fresh id anyway, so the counter is never dropped under an
    /// in-flight lineage.
    human_turn_counts: HashMap<String, u32>,
    /// Per-conversation count of `user_input` surfaces in the most recent turn. A new human
    /// turn is "this turn has MORE user_input surfaces than last" — counting (not a
    /// hash-delta) so a repeated byte-identical prompt still registers, and persisting it
    /// here (rather than reading the prior record) keeps the signal alive after the prior
    /// turn's record is evicted from the ring. Evicted with the per-conversation map set.
    prev_user_input_counts: HashMap<String, u32>,
    /// Content-derived conversation anchors: auto-id → the conversation's current
    /// ordered sequence of non-system surface `block_hash`es. A new request with
    /// no explicit id is matched to the conversation whose anchor is a clean
    /// prefix of the request's surface sequence (longest wins); see
    /// [`resolve_content_conversation`]. Bounded by [`MAX_TRACKED_CONVERSATIONS`].
    conversation_anchors: HashMap<String, Vec<String>>,
    /// Per-conversation last-seen timestamp (ms), used as the LRU key when
    /// evicting `conversation_anchors` / `labels`.
    last_seen: HashMap<String, u128>,
    /// Per-conversation display label, cached at mint time (a snippet of the
    /// first user message). Recomputing it from the ring is wrong — records are
    /// newest-first and turn-1 evicts — so it is stored once when minted.
    labels: HashMap<String, String>,
    /// Durable, session-scoped ledger of every distinct masked value, keyed by token
    /// handle. Fed at the masking site (not the recording site) so it survives the
    /// 500-record ring eviction and also captures count_tokens traffic that never
    /// becomes a record. Bounded by [`MAX_SESSION_TOKENS`] (oldest-evicted).
    session_tokens: HashMap<String, TokenLedgerEntry>,
    /// Session-stable `Local` ("owner-reveal") `(plaintext, handle)` pairs (today the proxy
    /// admin key). A `Local` value is REVEALED on the display path, so it can surface in a
    /// captured reply CROSS-TURN — when the model echoes the token in a turn whose request
    /// carries no plaintext there is no `local` manifest entry that turn, so the manifest-only
    /// `redaction_pairs`/`json_body_redaction_pairs` would miss it. The capture scrub also
    /// re-masks against this set, so the admin key never persists in a monitor record. Seeded
    /// from the engine when the reserved admin-key rule (and any future Local secret) installs.
    local_redactions: Vec<(String, String)>,
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                mode: MonitorMode::Off,
                max_pending_approvals: DEFAULT_MAX_PENDING_APPROVALS,
                next_seq: 1,
                records: VecDeque::new(),
                waiters: HashMap::new(),
                turn_counts: HashMap::new(),
                human_turn_counts: HashMap::new(),
                prev_user_input_counts: HashMap::new(),
                conversation_anchors: HashMap::new(),
                last_seen: HashMap::new(),
                labels: HashMap::new(),
                session_tokens: HashMap::new(),
                local_redactions: Vec::new(),
            })),
            events,
        }
    }

    /// Install the session-stable `Local` ("owner-reveal") `(plaintext, handle)` pairs the
    /// capture scrub re-masks against (see [`Inner::local_redactions`]). The proxy calls this
    /// when the reserved admin-key rule (and any future Local secret) installs — synchronously
    /// BEFORE the listener serves, so no captured reply can predate it.
    pub fn set_local_redactions(&self, pairs: Vec<(String, String)>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.local_redactions = pairs;
        }
    }

    /// Snapshot of the session `Local` scrub pairs (cheap; one entry per Local secret).
    fn local_redactions(&self) -> Vec<(String, String)> {
        self.inner
            .lock()
            .map(|i| i.local_redactions.clone())
            .unwrap_or_default()
    }

    pub fn snapshot(&self) -> MonitorSnapshot {
        let inner = self.inner.lock().expect("monitor mutex poisoned");
        let mut session_tokens: Vec<TokenLedgerEntry> =
            inner.session_tokens.values().cloned().collect();
        session_tokens.sort_by_key(|e| e.first_seen_ms);
        MonitorSnapshot {
            mode: inner.mode,
            pending_count: inner.waiters.len(),
            max_pending_approvals: inner.max_pending_approvals,
            records: inner.records.iter().cloned().collect(),
            conversations: conversations_from_records(&inner.records, &inner.labels),
            approval_timeout_secs: APPROVAL_TIMEOUT_SECS,
            session_tokens,
        }
    }

    /// Fold a request's masking manifest into the durable session-token ledger.
    /// Called from BOTH [`Self::record_llm_request`] (inlined, under the same lock)
    /// and directly from the `count_tokens` mask path (which masks + forwards but
    /// never records) — so the ledger is complete across all masked egress.
    pub fn ingest_session_tokens(&self, manifest: &UnmaskManifest) {
        if manifest.is_empty() {
            return;
        }
        let now = now_ms();
        let mut inner = self.inner.lock().expect("monitor mutex poisoned");
        // The count_tokens path masks + forwards but never builds surfaces, so there is no
        // provenance to attach here. The ledger still records the value (exhaustive); its
        // lane stays `None` ("unclassified", always shown) until a real recorded request
        // re-sights it in a classified surface and upgrades it.
        ingest_tokens_into(&mut inner, manifest, now, &HashMap::new());
    }

    pub fn set_mode(
        &self,
        mode: MonitorMode,
        max_pending_approvals: Option<usize>,
    ) -> MonitorSnapshot {
        {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            inner.mode = mode;
            if let Some(max) = max_pending_approvals {
                inner.max_pending_approvals = max;
            }
        }
        let snap = self.snapshot();
        self.emit(MonitorEvent::Snapshot(Box::new(snap.clone())));
        snap
    }

    pub fn record_llm_request(
        &self,
        endpoint: &'static str,
        method: &str,
        conversation_id: Option<String>,
        masked_body: &[u8],
        manifest: &UnmaskManifest,
        pinned: &PinnedMode,
    ) -> ReviewTicket {
        // Compute everything that does NOT depend on shared state BEFORE taking the
        // lock. The masked body can be 100KB+ and `surfaces_from_body` parses it as
        // JSON and blake3-hashes every surface; doing that under the global mutex
        // would serialize the realtime hot path (every request blocks on every
        // other request's parse). Only the seq/turn/delta bookkeeping needs `inner`.
        let now = now_ms();
        // Value-free captured destination: the target NAME only (never the ZdrKey — a
        // ZdrTarget is not Serialize). Derived from the mode CAPTURED at routing time and
        // threaded in here, NOT a re-read of the live ZDR selection (EV-A discipline), so a
        // silently-degraded request (no selection → routed Normal) records "anthropic".
        let upstream = Some(match pinned {
            PinnedMode::Normal => "anthropic".to_string(),
            PinnedMode::Zdr(t) => format!("zdr:{}", t.name),
        });
        let request_preview = preview(masked_body);
        let tokens = token_previews(manifest);
        let request_spans = spans_from_manifest(manifest, &request_preview);
        let request_surfaces = surfaces_from_body(masked_body, &tokens);
        // This turn's surface hashes — used to overlap-select the genuine predecessor turn
        // (see `previous_turn_surfaces`). Computed before the lock (blake3 over each surface).
        let this_turn_hashes: Vec<String> = request_surfaces
            .iter()
            .map(|s| s.block_hash.clone())
            .collect();
        // Content anchor for the conversation heuristic: the ordered hashes of the
        // conversation-specific surfaces. Exclude `system`/`instructions` — Claude
        // Code's system prompt is shared across all conversations and is the
        // dominant false-merge vector. `message` + `tool_use` + `tool_result`
        // remain, so the prefix still grows in tool-only agentic turns.
        let anchor_seq: Vec<String> = request_surfaces
            .iter()
            .filter(|s| s.kind != "system" && s.kind != "instructions")
            .map(|s| s.block_hash.clone())
            .collect();
        // Claude Code's authoritative per-conversation session id (from the body's
        // `metadata.user_id`) — the exact conversation key when present. Parsed before
        // the lock (it is a JSON parse of a possibly-100KB+ body).
        let body_session_id = session_id_from_body(masked_body);
        // Map each masked token handle to the highest-signal provenance lane it appears in
        // this request, so the durable ledger can GROUP (never gate) by lane. Built from the
        // already-computed surfaces, before the lock. A handle seen in multiple lanes takes
        // the most-sensitive (least-foldable) one, so a value ever seen in USERCTX/TOOL_io/
        // USER_input is never folded as harness scaffolding.
        let token_provenance = token_provenance_map(&request_surfaces);

        let mut inner = self.inner.lock().expect("monitor mutex poisoned");
        // Fold this request's masked values into the durable ledger under the same
        // lock (a separate `ingest_session_tokens` call would deadlock the std mutex).
        ingest_tokens_into(&mut inner, manifest, now, &token_provenance);
        let id = format!("req-{}", inner.next_seq);
        inner.next_seq += 1;

        // Resolve the conversation id. Precedence: an explicit id (session URL /
        // header) always wins; else Claude Code's authoritative `session_id` (exact,
        // and stable across `/compact` and content drift, where the content heuristic
        // fragments); else the transcript-prefix heuristic; else the shared `"unknown"`
        // bucket for a body with no anchorable surface (never mint from an empty head).
        // EVERY caller-controlled id (explicit header/URL and the body session_id) is run
        // through `bound_id` so none can inject an oversized / control-character key.
        let conversation_id = match conversation_id {
            Some(id) => bound_id(&id),
            None => match body_session_id {
                Some(sid) => format!("cc-{sid}"),
                None if anchor_seq.is_empty() => "unknown".to_string(),
                None => resolve_content_conversation(&mut inner.conversation_anchors, &anchor_seq),
            },
        };
        let should_hold = match inner.mode {
            MonitorMode::Off => false,
            MonitorMode::ManualAllLlm => true,
            MonitorMode::ManualOnDetection => !manifest.is_empty(),
        };

        // Assign this request's 1-based turn index within its conversation.
        let turn_index = {
            let c = inner
                .turn_counts
                .entry(conversation_id.clone())
                .or_insert(0);
            *c += 1;
            *c
        };

        // Delta vs the genuine PREDECESSOR turn of this conversation.
        //
        // The baseline is the prior turn whose request surfaces overlap THIS turn's the
        // most (tie-broken by recency), NOT merely the highest prior turn_index. A
        // side-branch that shares the conversation id but diverges in content — most
        // notably Claude Code's background title / "memory" generation fork, which rides
        // the same `metadata.user_id` session_id and so lands in this conversation —
        // otherwise becomes the baseline for the next REAL turn and mis-flags the whole
        // resent transcript as new (the "T2 = entire conversation is delta" bug). Overlap
        // selection skips it: the true predecessor is a near-superset of this turn and shares
        // far more surfaces than a divergent fork. Safe either way — a surface only folds when
        // it byte-matches one in a REAL prior recorded turn, and a fully divergent turn just
        // over-shows (never hides).
        //
        // This requires the predecessor's LIVE record (full surface compare). Once every prior
        // record of the conversation has aged out of the ring there is nothing to overlap-select
        // against — and a single cached hash set cannot be trusted as the baseline (it may be the
        // fork, in which case folding against it could HIDE a genuinely-new surface that happens
        // to byte-match a fork surface). So we never fold from one unverified cache: a non-first
        // turn with no live predecessor is `prev_unavailable` (audit the full request — over-show,
        // never hide), and only the genuine first turn (turn_index == 1) is `is_first`.
        let current_hashes: HashSet<&str> =
            this_turn_hashes.iter().map(String::as_str).collect();
        let delta = if let Some((pt, prev_req, prev_resp)) =
            previous_turn_surfaces(&inner.records, &conversation_id, turn_index, &current_hashes)
        {
            compute_delta(&request_surfaces, Some((pt, &prev_req, &prev_resp)))
        } else if turn_index == 1 {
            TurnDelta::first()
        } else {
            TurnDelta::prev_unavailable(turn_index - 1)
        };

        // Bracket tool-cycle requests under their human turn. The full transcript is resent
        // every turn, so a NEW human turn is one that carries MORE `user_input` surfaces than
        // the prior turn — counting (not a hash-delta) so a repeated byte-identical prompt
        // still registers, and reading the persisted prior count (not the prior record) keeps
        // the signal alive after that record is evicted from the ring. Drives UI nesting only
        // — never detection. (Monotonic within a conversation since the transcript only grows;
        // a `/compact` rewrite that shrinks the count just resets the baseline and fails
        // toward showing — a genuine later prompt still exceeds it.)
        let user_input_count = request_surfaces
            .iter()
            .filter(|s| s.provenance == "user_input")
            .count() as u32;
        let prev_user_input = inner
            .prev_user_input_counts
            .insert(conversation_id.clone(), user_input_count)
            .unwrap_or(0);
        let new_human_turn = user_input_count > prev_user_input;
        let human_turn_index = {
            let c = inner
                .human_turn_counts
                .entry(conversation_id.clone())
                .or_insert(0);
            if new_human_turn {
                *c += 1;
            }
            *c
        };

        // Stamp last-seen (the LRU eviction key) and cache the conversation label once (from
        // the resent transcript's first user message — works on any turn).
        {
            // Reborrow through the guard so the field accesses are seen as
            // disjoint by the borrow checker.
            let inner = &mut *inner;
            inner.last_seen.insert(conversation_id.clone(), now);
            if !inner.labels.contains_key(&conversation_id) {
                let label = first_message_label(&request_surfaces, endpoint, &conversation_id);
                inner.labels.insert(conversation_id.clone(), label);
            }
            evict_stale_conversation_state(inner);
        }

        let pending_full = should_hold && inner.waiters.len() >= inner.max_pending_approvals;
        let (status, rx, immediate_reject) = if pending_full {
            (
                RequestDecision::BackpressureRejected,
                None,
                Some(format!(
                    "pending approval limit reached ({})",
                    inner.max_pending_approvals
                )),
            )
        } else if should_hold {
            let (tx, rx) = oneshot::channel();
            inner.waiters.insert(id.clone(), tx);
            (RequestDecision::Pending, Some(rx), None)
        } else {
            (RequestDecision::AutoAccepted, None, None)
        };
        let record = RequestRecord {
            id: id.clone(),
            conversation_id,
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            started_ms: now,
            updated_ms: now,
            decision: status,
            request_preview,
            request_spans,
            response_preview: None,
            response_spans: Vec::new(),
            response_status: None,
            tokens,
            tags: Vec::new(),
            rejection_reason: immediate_reject.clone(),
            turn_index,
            dispatched_ms: None,
            request_surfaces,
            response_surfaces: Vec::new(),
            delta,
            human_turn_index,
            upstream,
        };
        push_record(&mut inner.records, record.clone());
        drop(inner);
        self.emit(MonitorEvent::Record(Box::new(record.clone())));
        ReviewTicket {
            id,
            rx,
            immediate_reject,
        }
    }

    pub fn record_response(
        &self,
        id: &str,
        status: u16,
        body: Option<&[u8]>,
        manifest: &UnmaskManifest,
    ) {
        // The body is UNMASKED here (walk::unmask_response replaced every [ENTITY_xxxx]
        // handle with its plaintext for the client). Scrub the MONITOR copy of any
        // non-peekable secret value back to its handle so the record never persists a
        // CVV/secret the request side withholds — peekable PII stays re-hydrated. Computed
        // off the lock; the forwarded `out` buffer is untouched. The body is serialized
        // JSON, so match both the raw and JSON-escaped forms of each secret value.
        let mut pairs = json_body_redaction_pairs(manifest);
        // Re-mask any session `Local` ("owner-reveal") value too: the admin key revealed
        // CROSS-TURN carries no `local` manifest entry this turn, so the manifest-derived
        // pairs miss it — without this it would persist UNMASKED in the captured reply.
        pairs.extend(json_body_expand(self.local_redactions()));
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let scrubbed: Option<Vec<u8>> = body.map(|b| {
            redact_secret_values(&String::from_utf8_lossy(b), &pairs).into_bytes()
        });
        self.update_record(id, |r| {
            // Terminal-idempotent: a late drain or a drop-guard firing after the
            // record already reached a terminal verdict must NOT resurrect
            // `Completed` over an error/abort or re-stamp the response surfaces.
            if r.decision.is_terminal() {
                return;
            }
            r.response_status = Some(status);
            r.response_preview = scrubbed.as_deref().map(preview);
            r.response_spans = r
                .response_preview
                .as_deref()
                .map(|p| spans_from_values(&r.tokens, p))
                .unwrap_or_default();
            // Segment by the canonical VALUE, not the handle (the body is unmasked, modulo
            // the secret-class scrub above which turns those back into plain handle text).
            r.response_surfaces = scrubbed
                .as_deref()
                .map(|b| surfaces_from_response_body(b, &r.tokens))
                .unwrap_or_default();
            r.decision = RequestDecision::Completed;
        });
    }

    /// Live, NON-terminal update of a streaming response (see [`ResponseProgress`]).
    /// Persists the accumulated unmasked reply onto the record (so a snapshot taken
    /// mid-stream reflects it) and emits a lightweight `ResponseProgress` frame — NOT the
    /// whole record — so open UIs paint the model's reply as it streams. The decision is
    /// left untouched (stays `InFlight`); a no-op once the record is terminal.
    pub fn record_response_progress(&self, id: &str, status: u16, preview: String, surfaces: Vec<Surface>) {
        {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            let Some(r) = inner.records.iter_mut().find(|r| r.id == id) else {
                return;
            };
            if r.decision.is_terminal() {
                return;
            }
            r.response_status = Some(status);
            r.response_spans = spans_from_values(&r.tokens, &preview);
            r.response_preview = Some(preview.clone());
            r.response_surfaces = surfaces.clone();
            r.updated_ms = now_ms();
        }
        self.emit(MonitorEvent::ResponseProgress(Box::new(ResponseProgress {
            id: id.to_string(),
            status,
            response_preview: preview,
            response_surfaces: surfaces,
        })));
    }

    /// Finalize a STREAMED response: stamp the captured reply and flip to `Completed`,
    /// emitting a full `Record` frame. Terminal-idempotent like [`Self::record_response`]
    /// — a late drain or a drop-guard firing after an abort/error must not resurrect
    /// `Completed`. `preview == None` (an empty capture) leaves any partial already
    /// persisted by progress frames in place and just records completion.
    pub fn complete_response(
        &self,
        id: &str,
        status: u16,
        preview: Option<String>,
        surfaces: Vec<Surface>,
    ) {
        self.update_record(id, |r| {
            if r.decision.is_terminal() {
                return;
            }
            r.response_status = Some(status);
            if let Some(p) = &preview {
                r.response_spans = spans_from_values(&r.tokens, p);
                r.response_preview = Some(p.clone());
                r.response_surfaces = surfaces.clone();
            }
            r.decision = RequestDecision::Completed;
        });
    }

    /// Mark a request as released upstream (awaiting / streaming the response).
    /// Only advances from an accepted/approved state — never over a terminal one.
    pub fn record_dispatched(&self, id: &str) {
        self.update_record(id, |r| {
            if matches!(
                r.decision,
                RequestDecision::AutoAccepted | RequestDecision::Approved
            ) {
                r.decision = RequestDecision::InFlight;
                r.dispatched_ms = Some(now_ms());
            }
        });
    }

    /// The downstream client disconnected before the streamed response finished.
    pub fn record_aborted(&self, id: &str) {
        self.update_record(id, |r| {
            if r.decision.is_terminal() {
                return;
            }
            r.decision = RequestDecision::Aborted;
            r.rejection_reason = Some("client disconnected before response completed".to_string());
        });
    }

    pub fn record_upstream_error(&self, id: &str, msg: &str) {
        self.update_record(id, |r| {
            if r.decision.is_terminal() {
                return;
            }
            r.decision = RequestDecision::UpstreamError;
            r.rejection_reason = Some(msg.to_string());
        });
    }

    pub(crate) async fn wait_for_approval(&self, ticket: ReviewTicket) -> ApprovalDecision {
        let Some(rx) = ticket.rx else {
            if let Some(reason) = ticket.immediate_reject {
                return ApprovalDecision::Reject { reason };
            }
            return ApprovalDecision::Approve;
        };
        match tokio::time::timeout(APPROVAL_TIMEOUT, rx).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) => ApprovalDecision::Reject {
                reason: "approval channel closed".to_string(),
            },
            Err(_) => {
                let mut inner = self.inner.lock().expect("monitor mutex poisoned");
                inner.waiters.remove(&ticket.id);
                drop(inner);
                self.update_record(&ticket.id, |r| {
                    r.decision = RequestDecision::TimedOut;
                    r.rejection_reason = Some("approval timed out".to_string());
                });
                ApprovalDecision::Reject {
                    reason: "approval timed out".to_string(),
                }
            }
        }
    }

    pub(crate) fn decide(
        &self,
        id: &str,
        decision: ApprovalDecision,
    ) -> Result<RequestRecord, DecideError> {
        let waiter = {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            inner.waiters.remove(id)
        };
        let Some(waiter) = waiter else {
            return Err(DecideError::Unknown);
        };
        let _ = waiter.send(decision.clone());
        let mut out = None;
        self.update_record(id, |r| {
            match &decision {
                ApprovalDecision::Approve => r.decision = RequestDecision::Approved,
                ApprovalDecision::Reject { reason } => {
                    r.decision = RequestDecision::Rejected;
                    r.rejection_reason = Some(reason.clone());
                }
            }
            out = Some(r.clone());
        });
        out.ok_or(DecideError::Unknown)
    }

    pub(crate) fn update_tags(
        &self,
        id: &str,
        tags: Vec<String>,
    ) -> Result<RequestRecord, DecideError> {
        let mut out = None;
        self.update_record(id, |r| {
            r.tags = tags.clone();
            out = Some(r.clone());
        });
        out.ok_or(DecideError::Unknown)
    }

    fn update_record(&self, id: &str, f: impl FnOnce(&mut RequestRecord)) {
        let mut changed = None;
        {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            if let Some(r) = inner.records.iter_mut().find(|r| r.id == id) {
                f(r);
                r.updated_ms = now_ms();
                changed = Some(r.clone());
            }
        }
        if let Some(record) = changed {
            self.emit(MonitorEvent::Record(Box::new(record)));
        }
    }

    fn emit(&self, event: MonitorEvent) {
        let _ = self.events.send(event);
    }

    /// Push the live masking policy to every monitor subscriber. The `snapshot`
    /// payload is the `GET /zlauder/config` JSON (`{ config, ml, … }`). Called by
    /// every control-plane writer after a successful change so open policy panels
    /// re-render to match — whether the change came from the UI itself, the
    /// `/zlauder:privacy` CLI, a profile apply, an ML toggle, or a file reload.
    pub fn broadcast_policy(&self, snapshot: serde_json::Value) {
        self.emit(MonitorEvent::Policy(Box::new(snapshot)));
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.events.subscribe()
    }
}

/// RAII guard that finalizes a streamed response's lifecycle. Held inside the
/// per-response SSE stream state so it is dropped when the stream ends OR the
/// downstream client disconnects mid-flight. A natural drain calls
/// [`CompletionGuard::complete`]; an upstream stream error calls
/// [`CompletionGuard::upstream_error`]; a drop while still armed (client
/// disconnect) records `Aborted`. Single-fire via the `armed` flag.
pub struct CompletionGuard {
    monitor: Monitor,
    id: String,
    status: u16,
    armed: bool,
    /// Token previews (handle → plaintext) for this request, so the captured reply can be
    /// segmented by VALUE (the stream is already unmasked). Built once from the manifest.
    tokens: Vec<TokenPreview>,
    /// `(plaintext → handle)` pairs for non-peekable (secret-class) tokens, so a secret the
    /// reply echoes — forwarded UNMASKED to the client — is scrubbed back to its handle
    /// before it lands in the monitor capture. Held only on this in-flight guard, never on
    /// the persisted record. Empty (and free) when the request minted no secret-class token.
    redactions: Vec<(String, String)>,
    /// The unmasked assistant reply accumulated as it streams downstream.
    capture: ResponseCapture,
    /// `capture.total_len()` at the last live progress flush (the throttle baseline).
    flushed_len: usize,
}

impl CompletionGuard {
    pub fn new(monitor: Monitor, id: String, status: u16, manifest: &UnmaskManifest) -> Self {
        // Streaming scrub runs on already-extracted reply fragments (not a JSON body), so
        // the raw `Local` pairs suffice here (no json-escape expansion). Union them with the
        // manifest pairs so a CROSS-TURN-revealed admin key is re-masked before it is captured.
        let mut redactions = redaction_pairs(manifest);
        redactions.extend(monitor.local_redactions());
        redactions.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self {
            monitor,
            id,
            status,
            armed: true,
            tokens: token_previews(manifest),
            redactions,
            capture: ResponseCapture::new(),
            flushed_len: 0,
        }
    }

    /// Capture one already-unmasked downstream fragment (assistant prose or a tool-call
    /// argument blob) keyed by its content block, flushing a live progress frame once
    /// enough new text has accumulated since the last flush. Called by the SSE relay for
    /// every chunk it forwards, so the monitor mirrors exactly what the client receives.
    pub fn capture(&mut self, key: &str, kind: CapKind, label: &str, text: &str) {
        if !self.armed {
            return;
        }
        // Scrub any non-peekable (secret-class, e.g. CVV) plaintext back to its handle BEFORE
        // it lands in the capture. The relay forwarded the reply UNMASKED to the client, but
        // the monitor copy must mirror the request side and never persist a secret value.
        // Peekable PII is left intact (it is intentionally re-hydrated for the operator).
        let scrubbed = redact_secret_values(text, &self.redactions);
        self.capture.push(key, kind, label, &scrubbed);
        if self.capture.total_len().saturating_sub(self.flushed_len) >= PROGRESS_FLUSH_BYTES {
            self.flush_progress();
        }
    }

    /// Record a streamed tool call's NAME (carried only on the content-block start) so the
    /// captured surface renders as `name(args)` and folds out of the next turn's delta.
    /// No-op once disarmed.
    pub fn start_tool(&mut self, key: &str, name: &str) {
        if !self.armed {
            return;
        }
        self.capture.start_tool(key, name);
    }

    /// Push the captured-so-far reply as a live progress frame (non-terminal).
    fn flush_progress(&mut self) {
        if !self.armed || self.capture.is_empty() {
            return;
        }
        let (preview, surfaces) = self.capture.render(&self.tokens);
        self.flushed_len = self.capture.total_len();
        self.monitor
            .record_response_progress(&self.id, self.status, preview, surfaces);
    }

    /// Persist whatever streamed so far onto the record WITHOUT finalizing — used by the
    /// abort / upstream-error paths so a partial reply isn't lost when the stream dies.
    fn persist_partial(&self) {
        if self.capture.is_empty() {
            return;
        }
        let (preview, surfaces) = self.capture.render(&self.tokens);
        self.monitor
            .record_response_progress(&self.id, self.status, preview, surfaces);
    }

    /// The stream drained normally: finalize with the captured reply and disarm. An empty
    /// capture finalizes with no body — byte-identical to the historical `record_response`
    /// (None) call, so a response with no text surface still records `Completed`.
    pub fn complete(&mut self) {
        if std::mem::replace(&mut self.armed, false) {
            let (preview, surfaces) = self.capture.render(&self.tokens);
            let body = if self.capture.is_empty() { None } else { Some(preview) };
            self.monitor
                .complete_response(&self.id, self.status, body, surfaces);
        }
    }

    /// The upstream stream errored mid-flight: persist the partial reply, record
    /// `UpstreamError`, and disarm.
    pub fn upstream_error(&mut self, msg: &str) {
        if std::mem::replace(&mut self.armed, false) {
            self.persist_partial();
            self.monitor.record_upstream_error(&self.id, msg);
        }
    }
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        if self.armed {
            // Client disconnected mid-stream: keep whatever reply streamed before the drop,
            // then mark Aborted (which preserves the response fields, only flipping decision).
            self.persist_partial();
            self.monitor.record_aborted(&self.id);
        }
    }
}

/// Approval handle returned by [`Monitor::record_llm_request`].
pub struct ReviewTicket {
    id: String,
    rx: Option<oneshot::Receiver<ApprovalDecision>>,
    immediate_reject: Option<String>,
}

impl ReviewTicket {
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Map each masked token handle in `surfaces` to the highest-signal provenance lane it
/// appears in (merge rule: a handle in several lanes keeps the least-foldable one). This
/// is presentation grouping metadata for the durable ledger — it never gates detection.
fn token_provenance_map(surfaces: &[Surface]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for s in surfaces {
        for run in &s.runs {
            if let Some(tref) = &run.token {
                let cur = map
                    .entry(tref.token.clone())
                    .or_insert_with(|| s.provenance.clone());
                if provenance_rank(&s.provenance) > provenance_rank(cur) {
                    *cur = s.provenance.clone();
                }
            }
        }
    }
    map
}

/// Signal rank of a provenance lane for ledger grouping (higher = more likely a real
/// exposure to verify; the two lowest are display-foldable scaffolding). An unknown lane
/// ranks as `user_input` — shown, never folded (fail toward showing).
fn provenance_rank(lane: &str) -> u8 {
    match lane {
        "userctx" => 5,
        "tool_io" => 4,
        "user_input" => 3,
        "assistant" => 2,
        "harness_frame" => 1,
        "harness_meta" => 0,
        _ => 3,
    }
}

/// Accumulate a manifest's entries into the durable session-token ledger held in
/// `inner`. New tokens are inserted with their first-/last-seen timestamp; repeats
/// bump the count AND refresh `last_seen_ms`. Over [`MAX_SESSION_TOKENS`] the
/// LEAST-RECENTLY-seen entries are evicted (logged) — so a value that is still
/// actively masked is never evicted out from under the session, and every entry in
/// the request being ingested right now (newest `last_seen_ms`) is eviction-safe.
///
/// FORWARD-COMPAT SEAM (plan A): classification lives here, the single ingest point.
/// Detector/keyword PII is [`TokenClass::AutoPii`] (peekable); CVV is the live
/// exception — it is classified [`TokenClass::Sad`] (non-peekable), so its plaintext is
/// withheld from the ledger (`value` left empty) even when it rode the reversible
/// `Token` path (an overridden CVV operator; the default `Redact` mints no manifest
/// entry and never reaches here). When the secrets engine tags manifest entries with a
/// source, extend the switch in [`TokenClass::for_manifest_entry`] to set
/// [`TokenClass::Guard`]/`Broker`; `is_peekable()` then suppresses both the stored
/// plaintext and UI peek — so a brokered secret that interns into the manifest never
/// reaches the snapshot in cleartext.
///
/// `prov` maps each masked handle to its highest-signal provenance lane (built by
/// [`token_provenance_map`] from the request surfaces); it only annotates the ledger
/// entry for display grouping and never affects detection, masking, or eviction.
fn ingest_tokens_into(
    inner: &mut Inner,
    manifest: &UnmaskManifest,
    now: u128,
    prov: &HashMap<String, String>,
) {
    for e in &manifest.entries {
        if let Some(existing) = inner.session_tokens.get_mut(&e.token_handle) {
            existing.count = existing.count.saturating_add(1);
            // Refresh the eviction key so an actively-reused value stays warm and is
            // not the eviction victim while still masking. `first_seen_ms` (the
            // display sort key) is deliberately left untouched.
            existing.last_seen_ms = now;
            // Promote (never demote) the ledger lane: a value re-sighted in a
            // higher-signal lane (e.g. first folded via count_tokens, then seen in
            // TOOL_io) must surface — "any non-frame sighting disqualifies suppression".
            if let Some(lane) = prov.get(&e.token_handle) {
                let upgrade = match &existing.provenance {
                    Some(cur) => provenance_rank(lane) > provenance_rank(cur),
                    None => true,
                };
                if upgrade {
                    existing.provenance = Some(lane.clone());
                }
            }
            continue;
        }
        let class = TokenClass::for_manifest_entry(e);
        let peekable = class.is_peekable();
        let value = if peekable {
            e.canonical_form.clone()
        } else {
            String::new()
        };
        inner.session_tokens.insert(
            e.token_handle.clone(),
            TokenLedgerEntry {
                token: e.token_handle.clone(),
                value,
                entity_kind: e.entity_kind.clone(),
                class,
                peekable,
                first_seen_ms: now,
                last_seen_ms: now,
                count: 1,
                provenance: prov.get(&e.token_handle).cloned(),
            },
        );
    }
    if inner.session_tokens.len() > MAX_SESSION_TOKENS {
        let over = inner.session_tokens.len() - MAX_SESSION_TOKENS;
        tracing::warn!(
            "session-token ledger over cap ({MAX_SESSION_TOKENS}); evicting {over} least-recently-seen entr{}",
            if over == 1 { "y" } else { "ies" }
        );
        // O(n) eviction: quickselect the `over` victims into the prefix, then drop them
        // — cheaper than a min-scan-per-victim loop (O(over*n)) or a full sort
        // (O(n log n)), and it runs under the global mutex, so the common one-over case
        // stays linear (one request can mint thousands of entries). Victims are chosen
        // by `(is_current, last_seen_ms)` ascending: NON-current entries first (oldest
        // first), and a current-manifest entry only when non-current candidates cannot
        // cover `over` (a single request minting > cap distinct values). Keying on
        // `last_seen_ms` makes an actively-reused value the newest; explicitly ranking
        // current-manifest entries last closes the residual same-millisecond tie where
        // unstable selection could otherwise drop a value being masked right now
        // (a prior ingest that shares this `now`).
        let current: HashSet<&str> = manifest
            .entries
            .iter()
            .map(|e| e.token_handle.as_str())
            .collect();
        let mut by_age: Vec<(bool, u128, String)> = inner
            .session_tokens
            .values()
            .map(|e| (current.contains(e.token.as_str()), e.last_seen_ms, e.token.clone()))
            .collect();
        let over = over.min(by_age.len());
        if over > 0 {
            by_age.select_nth_unstable_by(over - 1, |a, b| (a.0, a.1).cmp(&(b.0, b.1)));
            for (_, _, tok) in by_age.into_iter().take(over) {
                inner.session_tokens.remove(&tok);
            }
        }
    }
}

/// Find the genuine PREDECESSOR record in the same conversation: among prior turns
/// (turn_index < `turn_index`), the one whose request surfaces overlap `current_hashes`
/// the most, tie-broken by recency (highest turn_index). Returns its turn index and a
/// clone of its request + captured-response surfaces.
///
/// Selecting by overlap rather than by raw turn_index keeps a content-divergent
/// side-branch that merely shares the conversation id — e.g. Claude Code's background
/// title/"memory" fork riding the same session_id — from becoming the delta baseline:
/// the true predecessor is a near-superset of this turn and shares far more surfaces,
/// while the fork shares almost none. In the common monotone-growth case the
/// immediately-prior turn has both the largest overlap and the highest turn_index, so the
/// recency tie-break preserves the old behavior exactly.
fn previous_turn_surfaces(
    records: &VecDeque<RequestRecord>,
    conversation_id: &str,
    turn_index: u32,
    current_hashes: &HashSet<&str>,
) -> Option<(u32, Vec<Surface>, Vec<Surface>)> {
    records
        .iter()
        .filter(|r| r.conversation_id == conversation_id && r.turn_index < turn_index)
        .max_by_key(|r| {
            let overlap = r
                .request_surfaces
                .iter()
                .filter(|s| current_hashes.contains(s.block_hash.as_str()))
                .count();
            (overlap, r.turn_index)
        })
        .map(|r| {
            (
                r.turn_index,
                r.request_surfaces.clone(),
                // Fold the captured reply into the next turn's baseline so the
                // echoed reply drops out of its delta (see `compute_delta`).
                r.response_surfaces.clone(),
            )
        })
}

/// Bound every per-conversation map by evicting the least-recently-seen
/// conversations until back under cap. All six maps (`turn_counts`,
/// `human_turn_counts`, `prev_user_input_counts`, `last_seen`,
/// `conversation_anchors`, `labels`) are evicted as a SET for the same victim, so they
/// never disagree. Choosing the victim by
/// `last_seen` (recency) — not by turn count — guarantees the victim is genuinely
/// cold: a live conversation has a recent `last_seen` and is never selected. A
/// cold conversation that later returns re-mints a fresh id (its anchor is gone),
/// so retaining only its turn counter would be dead weight AND an unbounded leak.
fn evict_stale_conversation_state(inner: &mut Inner) {
    while inner.last_seen.len() > MAX_TRACKED_CONVERSATIONS {
        let Some(victim) = inner
            .last_seen
            .iter()
            .min_by_key(|(_, t)| **t)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        inner.last_seen.remove(&victim);
        inner.turn_counts.remove(&victim);
        inner.human_turn_counts.remove(&victim);
        inner.prev_user_input_counts.remove(&victim);
        inner.conversation_anchors.remove(&victim);
        inner.labels.remove(&victim);
    }
}

/// Length of the clean prefix `anchor` forms of `seq`: `anchor.len()` when
/// `anchor` matches the head of `seq` exactly, else 0 (a partial/divergent
/// overlap does not count — only a clean prefix joins a conversation).
fn anchor_prefix_len(anchor: &[String], seq: &[String]) -> usize {
    if anchor.is_empty() || anchor.len() > seq.len() {
        return 0;
    }
    if anchor.iter().zip(seq).all(|(a, s)| a == s) {
        anchor.len()
    } else {
        0
    }
}

/// Resolve a content-derived conversation id for a request that carried no
/// explicit id. Matches the tracked conversation whose anchor is the longest
/// clean prefix of `seq` (tie-broken by id for determinism); a strictly-longer
/// match advances that anchor to `seq`. An exact-length match joins the lineage
/// WITHOUT overwriting its anchor (so a colliding turn-1 cannot steal it). No
/// match mints a fresh `auto-<head>` id, disambiguated by a digest of the full
/// sequence when that base key is already taken by a different lineage.
///
/// ACCEPTED LIMITATION (paired review): two genuinely-distinct conversations
/// whose first user message is byte-identical after masking share the same turn-1
/// `seq`, so the second joins the first's lineage for turn 1 and only separates
/// once their transcripts diverge on a later turn (a one-time relabel). There is
/// no out-of-band signal to tell them apart at turn 1; this is inherent to
/// content-derived identity and is preferable to scattering every turn into its
/// own bucket (the bug this whole heuristic replaces).
fn resolve_content_conversation(anchors: &mut HashMap<String, Vec<String>>, seq: &[String]) -> String {
    let best = anchors
        .iter()
        .filter_map(|(id, anchor)| {
            let n = anchor_prefix_len(anchor, seq);
            (n > 0).then(|| (n, id.clone()))
        })
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
    if let Some((n, id)) = best {
        if n < seq.len() {
            anchors.insert(id.clone(), seq.to_vec());
        }
        return id;
    }
    let head = &seq[0];
    let base = format!("auto-{head}");
    let id = if anchors.contains_key(&base) {
        let disc: String = blake3::hash(seq.join("|").as_bytes())
            .to_hex()
            .as_str()
            .chars()
            .take(8)
            .collect();
        format!("auto-{head}-{disc}")
    } else {
        base
    };
    anchors.insert(id.clone(), seq.to_vec());
    id
}

/// Extract Claude Code's authoritative per-conversation session id from the request
/// body's `metadata.user_id` — itself a JSON string carrying `{device_id, account_uuid,
/// session_id}`. A normal `session_id` is returned verbatim (masked or plaintext, it is
/// stable within a session, so it is an exact conversation key); an oversized or
/// control-character id is hashed to a bounded printable handle (stable grouping kept).
/// `None` when the body carries no parseable session id (any non-Anthropic / malformed).
fn session_id_from_body(body: &[u8]) -> Option<String> {
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;
    let user_id = root.get("metadata")?.get("user_id")?.as_str()?;
    let inner: serde_json::Value = serde_json::from_str(user_id).ok()?;
    let sid = inner.get("session_id")?.as_str()?.trim();
    if sid.is_empty() {
        return None;
    }
    Some(bound_id(sid))
}

/// Bound a caller-controlled conversation id to a printable, length-capped key. A
/// well-formed id (non-empty, `<=128` bytes, no control chars) passes through verbatim;
/// an empty id becomes `"unknown"`; anything else is hashed to a stable `h-<16hex>`
/// handle (same input → same key, so grouping is preserved). Applied to EVERY externally
/// supplied id source — the `x-zlauder-conversation` header, the session URL segment, and
/// the body `session_id` — so none can inject an oversized / control-character id into the
/// conversation HashMap keys, the SSE stream, or the UI titles (defense-in-depth: these are
/// only HTML-escaped downstream, not length/charset-bounded).
fn bound_id(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return "unknown".to_string();
    }
    if raw.len() <= 128 && raw.chars().all(|c| !c.is_control()) {
        return raw.to_string();
    }
    let h: String = blake3::hash(raw.as_bytes())
        .to_hex()
        .as_str()
        .chars()
        .take(16)
        .collect();
    format!("h-{h}")
}

/// A human conversation label: a short snippet of the first GENUINE user message —
/// the first `user_input`-provenance surface, so the injected `<system-reminder>` /
/// CLAUDE.md / slash-command wrappers (identical across every session) are skipped in
/// favour of what the human actually typed. Falls back to any message, then the
/// endpoint + id tail. Computed from `request_surfaces`, which on every turn carry the
/// full resent transcript, so the first message is present even on a cold start.
fn first_message_label(surfaces: &[Surface], endpoint: &str, conversation_id: &str) -> String {
    let is_harness = |s: &&Surface| s.provenance == "harness_frame" || s.provenance == "harness_meta";
    let snippet = surfaces
        .iter()
        .find(|s| s.provenance == "user_input")
        // Fallbacks (provenance missed): still skip recognized harness scaffolding so a
        // misclassification never lets the label fall back onto the system-reminder.
        .or_else(|| {
            surfaces
                .iter()
                .find(|s| s.kind == "message" && s.role.as_deref() == Some("user") && !is_harness(s))
        })
        .or_else(|| surfaces.iter().find(|s| s.kind == "message" && !is_harness(s)))
        .map(|s| s.runs.iter().map(|r| r.text.as_str()).collect::<String>());
    match snippet {
        Some(t) => {
            let collapsed = t.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.is_empty() {
                conversation_label(endpoint, conversation_id)
            } else if collapsed.chars().count() > 48 {
                let head: String = collapsed.chars().take(48).collect();
                format!("{head}…")
            } else {
                collapsed
            }
        }
        None => conversation_label(endpoint, conversation_id),
    }
}

fn push_record(records: &mut VecDeque<RequestRecord>, record: RequestRecord) {
    records.push_front(record);
    while records.len() > MAX_RECORDS {
        records.pop_back();
    }
}

/// Derive a friendlier channel label than the raw conversation id.
///
/// Real conversation ids are opaque UUIDs/hashes; the triage rail reads better
/// as the endpoint's terminal segment plus a short id tail (e.g.
/// `messages · a1b2c3`). Falls back to the bare id when it is already short.
fn conversation_label(endpoint: &str, conversation_id: &str) -> String {
    let leaf = endpoint
        .rsplit(['/', ':'])
        .find(|s| !s.is_empty())
        .unwrap_or(endpoint);
    let id = conversation_id.trim();
    if id == "unknown" || id.is_empty() {
        return format!("{leaf} · unknown");
    }
    // Last six chars give a stable, human-scannable tail without leaking the
    // full id into the rail (the full id stays available via the row title).
    let tail: String = {
        let chars: Vec<char> = id.chars().collect();
        let n = chars.len();
        chars[n.saturating_sub(6)..].iter().collect()
    };
    if tail == id {
        id.to_string()
    } else {
        format!("{leaf} · {tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn body(msgs: &[(&str, Value)]) -> Vec<u8> {
        let arr: Vec<Value> = msgs
            .iter()
            .map(|(role, content)| json!({ "role": role, "content": content }))
            .collect();
        serde_json::to_vec(&json!({ "messages": arr })).unwrap()
    }

    fn record(m: &Monitor, b: &[u8]) -> String {
        let manifest = UnmaskManifest::new();
        m.record_llm_request("/v1/messages", "POST", None, b, &manifest, &PinnedMode::Normal)
            .id()
            .to_string()
    }

    fn convo_of(m: &Monitor, id: &str) -> String {
        m.snapshot()
            .records
            .into_iter()
            .find(|r| r.id == id)
            .unwrap()
            .conversation_id
    }

    fn turn_of(m: &Monitor, id: &str) -> u32 {
        m.snapshot()
            .records
            .into_iter()
            .find(|r| r.id == id)
            .unwrap()
            .turn_index
    }

    #[test]
    fn anchor_prefix_len_requires_clean_prefix() {
        let a = vec!["h1".to_string(), "h2".to_string()];
        assert_eq!(anchor_prefix_len(&a, &["h1".into(), "h2".into(), "h3".into()]), 2);
        assert_eq!(anchor_prefix_len(&a, &["h1".into(), "h2".into()]), 2);
        // Divergent at index 1 → not a clean prefix.
        assert_eq!(anchor_prefix_len(&a, &["h1".into(), "X".into(), "h3".into()]), 0);
        // Anchor longer than seq → 0.
        assert_eq!(anchor_prefix_len(&a, &["h1".into()]), 0);
        assert_eq!(anchor_prefix_len(&[], &["h1".into()]), 0);
    }

    #[test]
    fn growing_transcript_keeps_one_conversation_with_incrementing_turns() {
        let m = Monitor::new();
        let t1 = record(&m, &body(&[("user", json!("fix the build"))]));
        let t2 = record(
            &m,
            &body(&[
                ("user", json!("fix the build")),
                ("assistant", json!("on it")),
                ("user", json!("now run tests")),
            ]),
        );
        assert_eq!(convo_of(&m, &t1), convo_of(&m, &t2));
        assert_eq!(turn_of(&m, &t1), 1);
        assert_eq!(turn_of(&m, &t2), 2);
        assert_eq!(m.snapshot().conversations.len(), 1);
    }

    #[test]
    fn divergent_opening_messages_split_into_two_conversations() {
        let m = Monitor::new();
        let a = record(&m, &body(&[("user", json!("conversation A opener"))]));
        let b = record(&m, &body(&[("user", json!("a totally different opener B"))]));
        assert_ne!(convo_of(&m, &a), convo_of(&m, &b));
        assert_eq!(turn_of(&m, &a), 1);
        assert_eq!(turn_of(&m, &b), 1);
        assert_eq!(m.snapshot().conversations.len(), 2);
    }

    #[test]
    fn tool_result_only_turn_still_grows_the_same_conversation() {
        let m = Monitor::new();
        let t1 = record(&m, &body(&[("user", json!("call a tool"))]));
        // Turn 2 appends an assistant tool_use + a user tool_result; no new plain
        // user message text, but the anchor (which includes tool_use/tool_result)
        // grows, so it must stay the same conversation.
        let t2 = record(
            &m,
            &body(&[
                ("user", json!("call a tool")),
                (
                    "assistant",
                    json!([{ "type": "tool_use", "id": "toolu_1", "name": "Bash", "input": { "cmd": "ls" } }]),
                ),
                (
                    "user",
                    json!([{ "type": "tool_result", "tool_use_id": "toolu_1", "content": "file.txt" }]),
                ),
            ]),
        );
        assert_eq!(convo_of(&m, &t1), convo_of(&m, &t2));
        assert_eq!(turn_of(&m, &t2), 2);
    }

    #[test]
    fn explicit_conversation_id_wins_over_content() {
        let m = Monitor::new();
        let manifest = UnmaskManifest::new();
        let id = m
            .record_llm_request(
                "/v1/messages",
                "POST",
                Some("session-xyz".to_string()),
                &body(&[("user", json!("hi"))]),
                &manifest,
                &PinnedMode::Normal,
            )
            .id()
            .to_string();
        assert_eq!(convo_of(&m, &id), "session-xyz");
    }

    #[test]
    fn empty_anchor_falls_back_to_unknown() {
        let m = Monitor::new();
        // A body with no message/tool surfaces (only metadata-ish content).
        let manifest = UnmaskManifest::new();
        let b = serde_json::to_vec(&json!({ "metadata": { "k": "v" } })).unwrap();
        let id = m
            .record_llm_request("/v1/messages", "POST", None, &b, &manifest, &PinnedMode::Normal)
            .id()
            .to_string();
        assert_eq!(convo_of(&m, &id), "unknown");
    }

    #[test]
    fn label_is_first_user_message_snippet() {
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("refactor the CPU hot loop"))]));
        let cid = convo_of(&m, &id);
        let label = m
            .snapshot()
            .conversations
            .into_iter()
            .find(|c| c.id == cid)
            .unwrap()
            .label;
        assert_eq!(label, "refactor the CPU hot loop");
    }

    /// A body carrying Claude Code's `metadata.user_id.session_id`.
    fn body_with_session(sid: &str, msgs: &[(&str, Value)]) -> Vec<u8> {
        let arr: Vec<Value> = msgs
            .iter()
            .map(|(role, content)| json!({ "role": role, "content": content }))
            .collect();
        let user_id = serde_json::to_string(
            &json!({ "device_id": "d", "account_uuid": "a", "session_id": sid }),
        )
        .unwrap();
        serde_json::to_vec(&json!({ "messages": arr, "metadata": { "user_id": user_id } })).unwrap()
    }

    #[test]
    fn session_id_overrides_content_identity() {
        let m = Monitor::new();
        // Two DISTINCT sessions whose first message is byte-identical — content
        // anchoring would merge them; the authoritative session_id keeps them apart.
        let a = record(&m, &body_with_session("sess-A", &[("user", json!("identical opener"))]));
        let b = record(&m, &body_with_session("sess-B", &[("user", json!("identical opener"))]));
        assert_eq!(convo_of(&m, &a), "cc-sess-A");
        assert_ne!(convo_of(&m, &a), convo_of(&m, &b));
        // Same session across turns stays one conversation with incrementing turns,
        // even though the per-turn transcript grows.
        let a2 = record(
            &m,
            &body_with_session(
                "sess-A",
                &[
                    ("user", json!("identical opener")),
                    ("assistant", json!("ok")),
                    ("user", json!("next")),
                ],
            ),
        );
        assert_eq!(convo_of(&m, &a2), "cc-sess-A");
        assert_eq!(turn_of(&m, &a2), 2);
    }

    #[test]
    fn delta_baseline_picks_genuine_predecessor_over_divergent_fork() {
        // Regression for the "T2 marked the entire conversation as delta" bug. Claude Code's
        // background title / "memory" generation fork rides the SAME session_id, so it lands in
        // this conversation and takes a turn_index between two real turns. The next real turn
        // must diff against its genuine predecessor (turn 1), not the fork (turn 2).
        let m = Monitor::new();
        // Turn 1: the real opener, with a model reply already in the resent transcript.
        record(
            &m,
            &body_with_session(
                "sess-1",
                &[
                    ("user", json!("the real conversation opener")),
                    ("assistant", json!("real reply")),
                ],
            ),
        );
        // Turn 2: the divergent fork — same session_id, unrelated content (shares no surface).
        record(
            &m,
            &body_with_session(
                "sess-1",
                &[("user", json!("Generate a concise title for the conversation"))],
            ),
        );
        // Turn 3: a genuine continuation of turn 1 plus one new user message.
        let t3 = record(
            &m,
            &body_with_session(
                "sess-1",
                &[
                    ("user", json!("the real conversation opener")),
                    ("assistant", json!("real reply")),
                    ("user", json!("a genuinely new message")),
                ],
            ),
        );
        let r3 = find(&m, &t3);
        // Baseline is the genuine predecessor (turn 1, overlap 2), not the fork (turn 2, overlap 0).
        assert_eq!(r3.delta.prev_turn, Some(1));
        // Only the genuinely-new message is flagged new; the resent opener + reply fold out.
        // Diffing against the fork (the old max-turn_index behavior) would flag all three.
        assert_eq!(r3.delta.added_surface_hashes.len(), 1);
    }

    #[test]
    fn session_id_oversized_or_control_is_bounded() {
        let m = Monitor::new();
        // An absurdly long session id is hashed to a short, stable handle.
        let huge = "x".repeat(5000);
        let id = record(&m, &body_with_session(&huge, &[("user", json!("hi"))]));
        let cid = convo_of(&m, &id);
        assert!(cid.starts_with("cc-h-"), "oversized id is hashed: {cid}");
        assert!(cid.len() <= 24, "bounded length: {cid}");
        // Control characters likewise route through the bounded hash, never verbatim.
        let ctrl = record(&m, &body_with_session("a\nb\tc\u{7}", &[("user", json!("hi2"))]));
        assert!(convo_of(&m, &ctrl).starts_with("cc-h-"));
        // A normal session id is preserved verbatim (exact grouping).
        let ok = record(
            &m,
            &body_with_session("5c37888a-371d-4623-9a60-3a900986da07", &[("user", json!("hi3"))]),
        );
        assert_eq!(convo_of(&m, &ok), "cc-5c37888a-371d-4623-9a60-3a900986da07");
    }

    #[test]
    fn explicit_conversation_id_is_bounded() {
        // The higher-precedence explicit id (x-zlauder-conversation header / session URL
        // segment) must also be bounded — it wins over the body session_id, so leaving it
        // unbounded would reopen the same HashMap/SSE/UI footgun (paired-audit finding).
        let m = Monitor::new();
        let manifest = UnmaskManifest::new();
        let huge = "y".repeat(9000);
        let id = m
            .record_llm_request("/v1/messages", "POST", Some(huge), &body(&[("user", json!("hi"))]), &manifest, &PinnedMode::Normal)
            .id()
            .to_string();
        let cid = convo_of(&m, &id);
        assert!(cid.starts_with("h-"), "oversized explicit id is hashed: {cid}");
        assert!(cid.len() <= 18, "bounded length: {cid}");
        // A normal explicit id still passes through verbatim and still wins over content.
        let ok = m
            .record_llm_request("/v1/messages", "POST", Some("session-xyz".to_string()), &body(&[("user", json!("hi"))]), &manifest, &PinnedMode::Normal)
            .id()
            .to_string();
        assert_eq!(convo_of(&m, &ok), "session-xyz");
    }

    #[test]
    fn label_skips_injected_reminder_for_the_real_prompt() {
        let m = Monitor::new();
        // Turn-1 transcript as Claude Code actually sends it: the first user message is
        // the injected CLAUDE.md system-reminder; the real prompt is the next message.
        let id = record(
            &m,
            &body(&[
                (
                    "user",
                    json!("<system-reminder> As you answer the user's questions, you can use the following context: # claudeMd ... </system-reminder>"),
                ),
                ("user", json!("refactor the CPU hot loop")),
            ]),
        );
        let cid = convo_of(&m, &id);
        let label = m
            .snapshot()
            .conversations
            .into_iter()
            .find(|c| c.id == cid)
            .unwrap()
            .label;
        assert_eq!(label, "refactor the CPU hot loop");
    }

    #[test]
    fn dispatch_then_complete_lifecycle() {
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        // Off mode → AutoAccepted.
        assert!(matches!(
            convo_decision(&m, &id),
            RequestDecision::AutoAccepted
        ));
        m.record_dispatched(&id);
        let r = find(&m, &id);
        assert!(matches!(r.decision, RequestDecision::InFlight));
        assert!(r.dispatched_ms.is_some());
        m.record_response(&id, 200, None, &UnmaskManifest::new());
        assert!(matches!(find(&m, &id).decision, RequestDecision::Completed));
    }

    #[test]
    fn terminal_idempotence_blocks_resurrection() {
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        m.record_dispatched(&id);
        // Client disconnect → Aborted; a late drain must NOT flip it to Completed.
        m.record_aborted(&id);
        assert!(matches!(find(&m, &id).decision, RequestDecision::Aborted));
        m.record_response(&id, 200, None, &UnmaskManifest::new());
        assert!(matches!(find(&m, &id).decision, RequestDecision::Aborted));
        // Upstream error stays terminal under a stray completion too.
        let id2 = record(&m, &body(&[("user", json!("go2"))]));
        m.record_dispatched(&id2);
        m.record_upstream_error(&id2, "boom");
        m.record_response(&id2, 200, None, &UnmaskManifest::new());
        assert!(matches!(
            find(&m, &id2).decision,
            RequestDecision::UpstreamError
        ));
    }

    #[test]
    fn completion_guard_drain_completes_and_is_single_fire() {
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        m.record_dispatched(&id);
        let mut g = CompletionGuard::new(m.clone(), id.clone(), 200, &UnmaskManifest::new());
        g.complete();
        assert!(matches!(find(&m, &id).decision, RequestDecision::Completed));
        drop(g); // already disarmed → Drop must NOT flip it to Aborted
        assert!(matches!(find(&m, &id).decision, RequestDecision::Completed));
    }

    #[test]
    fn completion_guard_drop_while_armed_aborts() {
        // Simulates the downstream client disconnecting mid-stream: axum drops the
        // body's stream state, dropping the guard while still armed.
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        m.record_dispatched(&id);
        {
            let _g = CompletionGuard::new(m.clone(), id.clone(), 200, &UnmaskManifest::new());
        }
        assert!(matches!(find(&m, &id).decision, RequestDecision::Aborted));
    }

    #[test]
    fn completion_guard_upstream_error_is_terminal() {
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        m.record_dispatched(&id);
        let mut g = CompletionGuard::new(m.clone(), id.clone(), 200, &UnmaskManifest::new());
        g.upstream_error("boom");
        drop(g); // disarmed → stays UpstreamError, not Aborted
        assert!(matches!(
            find(&m, &id).decision,
            RequestDecision::UpstreamError
        ));
    }

    #[test]
    fn streamed_capture_populates_response_on_complete() {
        // The headline fix: a STREAMED reply lands on its own record at completion, instead
        // of only appearing once the next request resends it as transcript.
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        m.record_dispatched(&id);
        // The relay forwards already-UNMASKED assistant text (plaintext present).
        let manifest = manifest_with("[EMAIL_0001]", "alice@example.com");
        let mut g = CompletionGuard::new(m.clone(), id.clone(), 200, &manifest);
        g.capture("t0", CapKind::Text, "assistant", "mail alice@");
        g.capture("t0", CapKind::Text, "assistant", "example.com now");
        g.complete();
        let r = find(&m, &id);
        assert!(matches!(r.decision, RequestDecision::Completed));
        assert_eq!(r.response_preview.as_deref(), Some("mail alice@example.com now"));
        assert_eq!(r.response_surfaces.len(), 1);
        assert_eq!(r.response_surfaces[0].role.as_deref(), Some("assistant"));
        // The echoed plaintext is wrapped as a token run (segmented by value).
        assert!(r.response_surfaces[0].runs.iter().any(|run| run.token.is_some()));
    }

    #[test]
    fn streamed_capture_persists_partial_on_abort() {
        // A client disconnect mid-stream keeps whatever streamed before the drop.
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        m.record_dispatched(&id);
        {
            let mut g = CompletionGuard::new(m.clone(), id.clone(), 200, &UnmaskManifest::new());
            g.capture("t0", CapKind::Text, "assistant", "partial before disconnect");
        } // drop while armed → Aborted, partial preserved
        let r = find(&m, &id);
        assert!(matches!(r.decision, RequestDecision::Aborted));
        assert_eq!(r.response_preview.as_deref(), Some("partial before disconnect"));
        assert_eq!(r.response_surfaces.len(), 1);
    }

    fn manifest_with(token: &str, value: &str) -> UnmaskManifest {
        let mut m = UnmaskManifest::new();
        m.push(zlauder_engine::ManifestEntry {
            canonical_form: value.to_string(),
            token_handle: token.to_string(),
            entity_kind: "EMAIL_ADDRESS".to_string(),
            arrow_origin: zlauder_engine::Surface::UserMessage,
            exposed_at: None,
            broker: false,
            local: false,
        });
        m
    }

    /// A non-peekable CVV (`TokenClass::Sad`) token alongside a peekable email — the
    /// response-scrub fixture: the CVV must re-mask in the monitor copy, the email stays
    /// re-hydrated.
    fn manifest_cvv_and_email() -> UnmaskManifest {
        let mut m = manifest_with("[EMAIL_0001]", "joe@example.com");
        m.push(zlauder_engine::ManifestEntry {
            canonical_form: "987".to_string(),
            token_handle: "[CVV_0001]".to_string(),
            entity_kind: zlauder_engine::ENTITY_CVV.to_string(),
            arrow_origin: zlauder_engine::Surface::UserMessage,
            exposed_at: None,
            broker: false,
            local: false,
        });
        m
    }

    #[test]
    fn streamed_capture_scrubs_secret_class_keeps_peekable() {
        // A secret-class value (CVV) the reply echoes is forwarded UNMASKED to the client, but
        // must NOT be persisted in the monitor capture: it re-masks to its handle, while a
        // peekable email in the same reply stays re-hydrated for operator review. Without the
        // scrub, `token_previews` emptying the CVV value left its plaintext un-redacted here.
        let m = Monitor::new();
        let manifest = manifest_cvv_and_email();
        let id = m
            .record_llm_request("/v1/messages", "POST", None, &body(&[("user", json!("go"))]), &manifest, &PinnedMode::Normal)
            .id()
            .to_string();
        m.record_dispatched(&id);
        let mut g = CompletionGuard::new(m.clone(), id.clone(), 200, &manifest);
        g.capture("t0", CapKind::Text, "assistant", "your cvv 987 mailed to joe@example.com");
        g.complete();
        let r = find(&m, &id);
        let preview = r.response_preview.as_deref().unwrap();
        assert!(!preview.contains("987"), "secret-class CVV must not be persisted: {preview}");
        assert!(preview.contains("[CVV_0001]"), "CVV re-masked to its handle: {preview}");
        assert!(preview.contains("joe@example.com"), "peekable email stays re-hydrated: {preview}");
    }

    #[test]
    fn non_streaming_response_scrubs_secret_class_keeps_peekable() {
        // Same invariant on the NON-streaming path (`record_response`): the unmasked reply
        // body is scrubbed of secret-class plaintext before it lands on the record.
        let m = Monitor::new();
        let manifest = manifest_cvv_and_email();
        let id = m
            .record_llm_request("/v1/messages", "POST", None, &body(&[("user", json!("go"))]), &manifest, &PinnedMode::Normal)
            .id()
            .to_string();
        m.record_dispatched(&id);
        let reply = serde_json::to_vec(&json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "your cvv 987 mailed to joe@example.com"}]
        }))
        .unwrap();
        m.record_response(&id, 200, Some(&reply), &manifest);
        let r = find(&m, &id);
        let preview = r.response_preview.as_deref().unwrap();
        assert!(!preview.contains("987"), "secret-class CVV must not be persisted: {preview}");
        assert!(preview.contains("[CVV_0001]"), "CVV re-masked to its handle: {preview}");
        assert!(preview.contains("joe@example.com"), "peekable email stays re-hydrated: {preview}");
    }

    #[test]
    fn cross_turn_revealed_local_scrubbed_via_session_set() {
        // Regression: a `Local` (owner-reveal) admin key revealed CROSS-TURN in a reply has NO
        // `local` manifest entry that turn (the request carried only the token, not the
        // plaintext), so the manifest-only scrub misses it. The monitor's session `Local` set
        // (seeded from the engine) must still re-mask it, so the admin key never persists.
        let m = Monitor::new();
        m.set_local_redactions(vec![(
            "AdminKeyPlain123".to_string(),
            "[ZLAUDER_ADMIN_KEY_aabbccdd]".to_string(),
        )]);
        // The turn's request carries NO local plaintext → empty manifest (the gap condition).
        let manifest = UnmaskManifest::new();
        let id = m
            .record_llm_request("/v1/messages", "POST", None, &body(&[("user", json!("show the url"))]), &manifest, &PinnedMode::Normal)
            .id()
            .to_string();
        m.record_dispatched(&id);
        // The relay forwarded the reply UNMASKED → the revealed admin key plaintext is present.
        let reply = serde_json::to_vec(&json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "the monitor url key is AdminKeyPlain123 here"}]
        }))
        .unwrap();
        m.record_response(&id, 200, Some(&reply), &manifest);
        let preview = find(&m, &id).response_preview.unwrap();
        assert!(!preview.contains("AdminKeyPlain123"), "admin key must NOT persist: {preview}");
        assert!(
            preview.contains("[ZLAUDER_ADMIN_KEY_aabbccdd]"),
            "cross-turn admin key re-masked to its handle: {preview}"
        );
    }

    #[test]
    fn cross_turn_revealed_local_scrubbed_in_stream() {
        // Same gap on the STREAMING path (`CompletionGuard`): the session `Local` set re-masks
        // a cross-turn-revealed admin key captured from a streamed fragment.
        let m = Monitor::new();
        m.set_local_redactions(vec![(
            "AdminKeyPlain123".to_string(),
            "[ZLAUDER_ADMIN_KEY_aabbccdd]".to_string(),
        )]);
        let id = record(&m, &body(&[("user", json!("show the url"))]));
        m.record_dispatched(&id);
        // Empty manifest this turn (cross-turn reveal); the stream fragment carries the plaintext.
        let mut g = CompletionGuard::new(m.clone(), id.clone(), 200, &UnmaskManifest::new());
        g.capture("t0", CapKind::Text, "assistant", "url key AdminKeyPlain123 done");
        g.complete();
        let preview = find(&m, &id).response_preview.unwrap();
        assert!(!preview.contains("AdminKeyPlain123"), "admin key must NOT persist (stream): {preview}");
        assert!(
            preview.contains("[ZLAUDER_ADMIN_KEY_aabbccdd]"),
            "cross-turn admin key re-masked to its handle (stream): {preview}"
        );
    }

    #[test]
    fn session_token_survives_record_ring_eviction() {
        let m = Monitor::new();
        // A request masking a distinct value seeds the ledger.
        let early = manifest_with("[EMAIL_0001]", "alice@example.com");
        m.record_llm_request("/v1/messages", "POST", None, &body(&[("user", json!("hi"))]), &early, &PinnedMode::Normal);

        // Flood the 500-record ring so the seeding record is evicted.
        for i in 0..(MAX_RECORDS + 5) {
            let b = body(&[("user", json!(format!("turn {i}")))]);
            m.record_llm_request("/v1/messages", "POST", Some(format!("c{i}")), &b, &UnmaskManifest::new(), &PinnedMode::Normal);
        }

        let snap = m.snapshot();
        assert!(
            snap.records.len() <= MAX_RECORDS,
            "ring is bounded ({} records)",
            snap.records.len()
        );
        // The value's originating record is long gone, but the ledger retains it.
        let entry = snap
            .session_tokens
            .iter()
            .find(|e| e.token == "[EMAIL_0001]")
            .expect("session token survives record eviction");
        assert_eq!(entry.value, "alice@example.com");
        assert!(entry.peekable);
    }

    #[test]
    fn session_token_count_aggregates_and_ledger_is_sorted() {
        let m = Monitor::new();
        m.ingest_session_tokens(&manifest_with("[EMAIL_0001]", "a@x.com"));
        m.ingest_session_tokens(&manifest_with("[PHONE_0002]", "555-0100"));
        m.ingest_session_tokens(&manifest_with("[EMAIL_0001]", "a@x.com")); // repeat
        let snap = m.snapshot();
        let email = snap.session_tokens.iter().find(|e| e.token == "[EMAIL_0001]").unwrap();
        let phone = snap.session_tokens.iter().find(|e| e.token == "[PHONE_0002]").unwrap();
        // Ledger is sorted by first_seen_ms (non-decreasing) and the email — ingested
        // first — never sorts after the phone.
        assert!(email.first_seen_ms <= phone.first_seen_ms);
        let seens: Vec<u128> = snap.session_tokens.iter().map(|e| e.first_seen_ms).collect();
        assert!(seens.windows(2).all(|w| w[0] <= w[1]), "ledger sorted by first_seen_ms");
        assert_eq!(email.count, 2, "repeat masks bump the count");
    }

    #[test]
    fn session_token_ledger_is_capped() {
        let m = Monitor::new();
        // One manifest that overshoots the cap exercises the quickselect eviction path.
        let mut man = UnmaskManifest::new();
        for i in 0..(MAX_SESSION_TOKENS + 50) {
            man.push(zlauder_engine::ManifestEntry {
                canonical_form: format!("v{i}"),
                token_handle: format!("[T_{i}]"),
                entity_kind: "X".to_string(),
                arrow_origin: zlauder_engine::Surface::UserMessage,
                exposed_at: None,
                broker: false,
                local: false,
            });
        }
        m.ingest_session_tokens(&man);
        assert_eq!(
            m.snapshot().session_tokens.len(),
            MAX_SESSION_TOKENS,
            "ledger is bounded at the cap after an over-cap ingest"
        );
    }

    #[test]
    fn session_token_eviction_drops_oldest_first() {
        let m = Monitor::new();
        // An OLD batch that nearly fills the cap, stamped at an earlier ms.
        let mut old = UnmaskManifest::new();
        for i in 0..(MAX_SESSION_TOKENS - 10) {
            old.push(zlauder_engine::ManifestEntry {
                canonical_form: format!("o{i}"),
                token_handle: format!("[OLD_{i}]"),
                entity_kind: "X".to_string(),
                arrow_origin: zlauder_engine::Surface::UserMessage,
                exposed_at: None,
                broker: false,
                local: false,
            });
        }
        m.ingest_session_tokens(&old);
        // Force the next batch to carry a strictly greater first_seen_ms.
        let t0 = now_ms();
        while now_ms() == t0 {
            std::hint::spin_loop();
        }
        // A NEW batch overshoots the cap (4990 + 50 = 5040, over = 40). The 40 victims
        // must be the OLDEST — so every NEW entry survives.
        let mut fresh = UnmaskManifest::new();
        for i in 0..50 {
            fresh.push(zlauder_engine::ManifestEntry {
                canonical_form: format!("n{i}"),
                token_handle: format!("[NEW_{i}]"),
                entity_kind: "X".to_string(),
                arrow_origin: zlauder_engine::Surface::UserMessage,
                exposed_at: None,
                broker: false,
                local: false,
            });
        }
        m.ingest_session_tokens(&fresh);
        let snap = m.snapshot();
        assert_eq!(snap.session_tokens.len(), MAX_SESSION_TOKENS);
        let new_present = snap
            .session_tokens
            .iter()
            .filter(|e| e.token.starts_with("[NEW_"))
            .count();
        assert_eq!(new_present, 50, "eviction dropped the oldest, never the newest");
    }

    fn manifest_kind(token: &str, value: &str, entity_kind: &str) -> UnmaskManifest {
        let mut m = UnmaskManifest::new();
        m.push(zlauder_engine::ManifestEntry {
            canonical_form: value.to_string(),
            token_handle: token.to_string(),
            entity_kind: entity_kind.to_string(),
            arrow_origin: zlauder_engine::Surface::UserMessage,
            exposed_at: None,
            broker: false,
            local: false,
        });
        m
    }

    /// C8 defense-in-depth: a CVV manifest entry (PCI SAD) is classified non-peekable
    /// so its plaintext is structurally withheld from the in-memory ledger snapshot even
    /// when it rode the reversible `Token` path (an overridden CVV operator). Ordinary
    /// PII (EMAIL_ADDRESS) stays AutoPii/peekable with its value present — unchanged.
    #[test]
    fn cvv_manifest_entry_is_non_peekable_and_value_withheld() {
        let m = Monitor::new();
        // entity_kind "CVV" matches zlauder_engine::ENTITY_CVV (the recognizer's stamp).
        m.ingest_session_tokens(&manifest_kind("[CVV_0001]", "123", "CVV"));
        m.ingest_session_tokens(&manifest_kind("[EMAIL_0002]", "alice@example.com", "EMAIL_ADDRESS"));
        let snap = m.snapshot();

        let cvv = snap
            .session_tokens
            .iter()
            .find(|e| e.token == "[CVV_0001]")
            .expect("CVV token interned into the ledger");
        assert!(!cvv.peekable, "CVV is SAD → non-peekable");
        assert_eq!(cvv.class, TokenClass::Sad, "CVV classifies as Sad");
        assert_eq!(cvv.value, "", "CVV plaintext withheld from the ledger snapshot");

        let email = snap
            .session_tokens
            .iter()
            .find(|e| e.token == "[EMAIL_0002]")
            .expect("EMAIL token interned into the ledger");
        assert!(email.peekable, "ordinary PII stays peekable");
        assert_eq!(email.class, TokenClass::AutoPii, "EMAIL classifies as AutoPii");
        assert_eq!(email.value, "alice@example.com", "EMAIL plaintext present (unchanged)");
    }

    #[test]
    fn session_token_reused_value_survives_eviction() {
        // Regression (B1): a value FIRST seen long ago but RE-MASKED right now must not
        // be evicted just for its age. Eviction keys on `last_seen_ms` (LRU), and a
        // repeat sighting refreshes it; under the old `first_seen_ms` eviction this
        // entry was the prime victim while still actively masking.
        let spin = || {
            let t = now_ms();
            while now_ms() == t {
                std::hint::spin_loop();
            }
        };
        let m = Monitor::new();
        // 1. An old, soon-to-be-reused secret.
        m.ingest_session_tokens(&manifest_with("[REUSED]", "s3cr3t"));
        spin();
        // 2. Fill exactly to the cap with distinct fresh tokens (no eviction yet).
        let mut fill = UnmaskManifest::new();
        for i in 0..(MAX_SESSION_TOKENS - 1) {
            fill.push(zlauder_engine::ManifestEntry {
                canonical_form: format!("f{i}"),
                token_handle: format!("[FILL_{i}]"),
                entity_kind: "X".to_string(),
                arrow_origin: zlauder_engine::Surface::UserMessage,
                exposed_at: None,
                broker: false,
                local: false,
            });
        }
        m.ingest_session_tokens(&fill);
        assert_eq!(m.snapshot().session_tokens.len(), MAX_SESSION_TOKENS);
        spin();
        // 3. Re-mask the OLD secret (refreshes its last_seen) AND add one new token,
        //    overshooting the cap by 1. The single victim must be a least-recently-seen
        //    FILL entry — never the just-reused secret.
        let mut reuse = UnmaskManifest::new();
        for (handle, value) in [("[REUSED]", "s3cr3t"), ("[FRESH]", "new")] {
            reuse.push(zlauder_engine::ManifestEntry {
                canonical_form: value.to_string(),
                token_handle: handle.to_string(),
                entity_kind: "X".to_string(),
                arrow_origin: zlauder_engine::Surface::UserMessage,
                exposed_at: None,
                broker: false,
                local: false,
            });
        }
        m.ingest_session_tokens(&reuse);
        let snap = m.snapshot();
        assert_eq!(snap.session_tokens.len(), MAX_SESSION_TOKENS);
        let reused = snap.session_tokens.iter().find(|e| e.token == "[REUSED]");
        assert!(
            reused.is_some(),
            "a value re-masked this turn must survive LRU eviction"
        );
        assert_eq!(reused.unwrap().count, 2, "repeat sighting bumped the count");
    }

    #[test]
    fn session_token_same_ms_tie_protects_current_manifest() {
        // Deterministic same-MILLISECOND tie (impossible via the public helper, which pins
        // now_ms() internally): drive `ingest_tokens_into` directly with a FIXED `now`.
        // Fill to cap at T, then a SECOND ingest at the SAME T re-masks one cap-resident
        // value and adds one new value (over = 1). The victim must be a NON-current entry;
        // the re-masked + new (current-manifest) values survive — which pure-`last_seen_ms`
        // eviction (unstable on the tie) could NOT guarantee. This is the B1 headline fix.
        let m = Monitor::new();
        let t: u128 = 1_000_000;
        let mut guard = m.inner.lock().expect("monitor mutex poisoned");
        let mut fill = UnmaskManifest::new();
        for i in 0..MAX_SESSION_TOKENS {
            fill.push(zlauder_engine::ManifestEntry {
                canonical_form: format!("f{i}"),
                token_handle: format!("[FILL_{i}]"),
                entity_kind: "X".to_string(),
                arrow_origin: zlauder_engine::Surface::UserMessage,
                exposed_at: None,
                broker: false,
                local: false,
            });
        }
        ingest_tokens_into(&mut guard, &fill, t, &HashMap::new());
        assert_eq!(guard.session_tokens.len(), MAX_SESSION_TOKENS);
        let mut reuse = UnmaskManifest::new();
        for (h, v) in [("[FILL_0]", "f0"), ("[NEW]", "new")] {
            reuse.push(zlauder_engine::ManifestEntry {
                canonical_form: v.to_string(),
                token_handle: h.to_string(),
                entity_kind: "X".to_string(),
                arrow_origin: zlauder_engine::Surface::UserMessage,
                exposed_at: None,
                broker: false,
                local: false,
            });
        }
        ingest_tokens_into(&mut guard, &reuse, t, &HashMap::new()); // SAME `now` → ties the whole ledger
        assert_eq!(guard.session_tokens.len(), MAX_SESSION_TOKENS);
        assert!(
            guard.session_tokens.contains_key("[FILL_0]"),
            "a value re-masked this turn survives the same-ms tie"
        );
        assert!(
            guard.session_tokens.contains_key("[NEW]"),
            "a value first masked this turn survives the same-ms tie"
        );
    }

    #[test]
    fn additive_serde_fields_default_on_old_snapshots() {
        // A Surface serialized before `provenance` existed deserializes to the safe,
        // fail-toward-showing default; a ledger entry without `last_seen_ms` -> 0.
        let s: Surface = serde_json::from_value(json!({
            "label": "m", "kind": "message", "runs": [], "block_hash": "h"
        }))
        .unwrap();
        assert_eq!(s.provenance, "user_input");
        let e: TokenLedgerEntry = serde_json::from_value(json!({
            "token": "[T]", "value": "v", "entity_kind": "X", "class": "auto_pii",
            "peekable": true, "first_seen_ms": 5, "count": 1
        }))
        .unwrap();
        assert_eq!(e.last_seen_ms, 0);
        assert_eq!(e.first_seen_ms, 5);
        // A ledger entry serialized before `provenance` existed → `None` (unclassified,
        // always shown), never a fabricated lane.
        assert_eq!(e.provenance, None);
    }

    fn find(m: &Monitor, id: &str) -> RequestRecord {
        m.snapshot()
            .records
            .into_iter()
            .find(|r| r.id == id)
            .unwrap()
    }
    fn convo_decision(m: &Monitor, id: &str) -> RequestDecision {
        find(m, id).decision
    }

    // ---- provenance-lane ledger grouping + human-turn bracketing (denoise chunk) ----

    fn manifest_entry(handle: &str, value: &str, kind: &str) -> zlauder_engine::ManifestEntry {
        zlauder_engine::ManifestEntry {
            canonical_form: value.to_string(),
            token_handle: handle.to_string(),
            entity_kind: kind.to_string(),
            arrow_origin: zlauder_engine::Surface::UserMessage,
            exposed_at: None,
            broker: false,
            local: false,
        }
    }

    fn record_with(m: &Monitor, b: &[u8], manifest: &UnmaskManifest) -> String {
        m.record_llm_request("/v1/messages", "POST", None, b, manifest, &PinnedMode::Normal)
            .id()
            .to_string()
    }

    fn human_turn_of(m: &Monitor, id: &str) -> u32 {
        find(m, id).human_turn_index
    }

    fn ledger_lane(m: &Monitor, handle: &str) -> Option<String> {
        m.snapshot()
            .session_tokens
            .into_iter()
            .find(|e| e.token == handle)
            .and_then(|e| e.provenance)
    }

    #[test]
    fn ledger_lane_is_attributed_from_the_surface_that_carried_the_value() {
        // The SAME entity kind from two surfaces lands in two lanes: a value in the system
        // prompt is harness scaffolding; the same-kind value in tool output is real egress.
        let m = Monitor::new();
        let b = serde_json::to_vec(&json!({
            "system": "contact [EMAIL_ADDRESS_sys] for help",
            "messages": [
                {"role": "user", "content": "run it"},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tu1", "content": "leaked [EMAIL_ADDRESS_tool]"}
                ]}
            ]
        }))
        .unwrap();
        let mut manifest = UnmaskManifest::new();
        manifest.push(manifest_entry("[EMAIL_ADDRESS_sys]", "a@sys.com", "EMAIL_ADDRESS"));
        manifest.push(manifest_entry("[EMAIL_ADDRESS_tool]", "b@tool.com", "EMAIL_ADDRESS"));
        record_with(&m, &b, &manifest);
        assert_eq!(ledger_lane(&m, "[EMAIL_ADDRESS_sys]").as_deref(), Some("harness_frame"));
        assert_eq!(ledger_lane(&m, "[EMAIL_ADDRESS_tool]").as_deref(), Some("tool_io"));
    }

    #[test]
    fn ledger_lane_upgrades_to_higher_signal_sighting_and_never_downgrades() {
        // "Any non-frame sighting disqualifies suppression": a value first folded in via
        // scaffolding must promote — and stay promoted — once it appears in a real lane.
        let m = Monitor::new();
        let handle = "[CRYPTO_x]";
        let mut man = UnmaskManifest::new();
        man.push(manifest_entry(handle, "wallet123", "CRYPTO"));

        let sys_body = serde_json::to_vec(&json!({
            "system": format!("example wallet {handle}"),
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .unwrap();
        record_with(&m, &sys_body, &man);
        assert_eq!(ledger_lane(&m, handle).as_deref(), Some("harness_frame"));

        let tool_body = serde_json::to_vec(&json!({
            "system": format!("example wallet {handle}"),
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t", "content": format!("found {handle}")}
                ]}
            ]
        }))
        .unwrap();
        record_with(&m, &tool_body, &man);
        assert_eq!(
            ledger_lane(&m, handle).as_deref(),
            Some("tool_io"),
            "a non-frame sighting promotes the lane out of foldable scaffolding"
        );

        // A later scaffolding-only resend must NOT pull it back into the foldable bucket.
        record_with(&m, &sys_body, &man);
        assert_eq!(
            ledger_lane(&m, handle).as_deref(),
            Some("tool_io"),
            "promotion is monotonic — a value seen in a real lane is never re-folded"
        );
    }

    #[test]
    fn count_tokens_only_value_stays_unclassified_until_a_surface_carries_it() {
        // The count_tokens path has no surfaces, so its values are ledgered with no lane
        // (always shown), then upgraded when a recorded request sights them in a surface.
        let m = Monitor::new();
        let mut man = UnmaskManifest::new();
        man.push(manifest_entry("[EMAIL_ADDRESS_q]", "q@x.com", "EMAIL_ADDRESS"));
        m.ingest_session_tokens(&man);
        assert_eq!(ledger_lane(&m, "[EMAIL_ADDRESS_q]"), None, "no surface ⇒ no lane (shown)");

        let b = serde_json::to_vec(&json!({
            "messages": [{"role": "user", "content": "mail [EMAIL_ADDRESS_q]"}]
        }))
        .unwrap();
        record_with(&m, &b, &man);
        assert_eq!(ledger_lane(&m, "[EMAIL_ADDRESS_q]").as_deref(), Some("user_input"));
    }

    #[test]
    fn human_turn_index_brackets_tool_cycle_under_one_prompt() {
        let m = Monitor::new();
        // Turn 1: the human prompt.
        let t1 = record(&m, &body(&[("user", json!("summarize the repo"))]));
        // Turn 2: a tool cycle — assistant tool_use + user tool_result, NO new human text.
        let t2 = record(
            &m,
            &body(&[
                ("user", json!("summarize the repo")),
                ("assistant", json!([{"type":"tool_use","id":"tu1","name":"Bash","input":{"command":"ls"}}])),
                ("user", json!([{"type":"tool_result","tool_use_id":"tu1","content":"src/ lib.rs"}])),
            ]),
        );
        // Turn 3: a genuine new human message.
        let t3 = record(
            &m,
            &body(&[
                ("user", json!("summarize the repo")),
                ("assistant", json!([{"type":"tool_use","id":"tu1","name":"Bash","input":{"command":"ls"}}])),
                ("user", json!([{"type":"tool_result","tool_use_id":"tu1","content":"src/ lib.rs"}])),
                ("assistant", json!("It has two files.")),
                ("user", json!("now write a test")),
            ]),
        );
        // Per-request turns are monotonic (egress granularity is preserved)...
        assert_eq!(turn_of(&m, &t1), 1);
        assert_eq!(turn_of(&m, &t2), 2);
        assert_eq!(turn_of(&m, &t3), 3);
        // ...but there are only TWO human turns: the tool cycle stays under prompt 1.
        assert_eq!(human_turn_of(&m, &t1), 1);
        assert_eq!(human_turn_of(&m, &t2), 1, "a tool-cycle continuation is not a new human turn");
        assert_eq!(human_turn_of(&m, &t3), 2, "a fresh user message opens human turn 2");
        // The sidebar reports human turns, not raw API requests.
        let convo = m.snapshot().conversations.into_iter().next().unwrap();
        assert_eq!(convo.turn_count, 2);
    }

    #[test]
    fn human_turn_index_counts_a_repeated_identical_prompt_as_a_new_turn() {
        // A byte-identical resent prompt is invisible to a hash-delta (same block_hash), but
        // the COUNT of user_input surfaces grows — so it still opens a new human turn (the
        // edge a hash-only delta would mis-group under the prior turn).
        let m = Monitor::new();
        let t1 = record(&m, &body(&[("user", json!("ping"))]));
        let t2 = record(
            &m,
            &body(&[
                ("user", json!("ping")),
                ("assistant", json!("pong")),
                ("user", json!("ping")),
            ]),
        );
        assert_eq!(convo_of(&m, &t1), convo_of(&m, &t2), "same conversation");
        assert_eq!(human_turn_of(&m, &t1), 1);
        assert_eq!(human_turn_of(&m, &t2), 2, "a repeated identical prompt is still a new human turn");
    }

    #[test]
    fn human_turn_index_defaults_on_old_records() {
        // A record serialized before `human_turn_index` existed deserializes to 0
        // (shown ungrouped), never a fabricated turn number.
        let m = Monitor::new();
        record(&m, &body(&[("user", json!("hi"))]));
        let rec = find(&m, "req-1");
        let mut v = serde_json::to_value(&rec).unwrap();
        v.as_object_mut().unwrap().remove("human_turn_index");
        let back: RequestRecord = serde_json::from_value(v).unwrap();
        assert_eq!(back.human_turn_index, 0);
    }
}

/// Build the conversation timeline from the current record set. Labels come from
/// the mint-time cache (`labels`); the endpoint+tail form is only a fallback for
/// a conversation whose cached label was evicted.
fn conversations_from_records(
    records: &VecDeque<RequestRecord>,
    labels: &HashMap<String, String>,
) -> Vec<ConversationMeta> {
    let mut metas: HashMap<String, ConversationMeta> = HashMap::new();
    for r in records {
        let pending = matches!(r.decision, RequestDecision::Pending);
        let m = metas
            .entry(r.conversation_id.clone())
            .or_insert_with(|| ConversationMeta {
                id: r.conversation_id.clone(),
                label: labels
                    .get(&r.conversation_id)
                    .cloned()
                    .unwrap_or_else(|| conversation_label(&r.endpoint, &r.conversation_id)),
                turn_count: 0,
                last_updated_ms: 0,
                pending_count: 0,
            });
        // Count HUMAN turns (what a person means by "turns"), not raw API requests: one
        // prompt that spawns N tool-cycle round-trips is ONE turn. Falls back to the
        // per-request index for pre-`human_turn_index` records (deserialized as 0).
        let human_turns = if r.human_turn_index > 0 {
            r.human_turn_index
        } else {
            r.turn_index
        };
        m.turn_count = m.turn_count.max(human_turns);
        m.last_updated_ms = m.last_updated_ms.max(r.updated_ms);
        if pending {
            m.pending_count += 1;
        }
    }
    let mut out: Vec<ConversationMeta> = metas.into_values().collect();
    // Most recently active first.
    out.sort_by(|a, b| b.last_updated_ms.cmp(&a.last_updated_ms));
    out
}
