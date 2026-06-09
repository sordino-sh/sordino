//! Monitor state: ring buffer, broadcast channel, approval waiters, and the
//! conversation/turn index. Holds all state-mutating methods.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, oneshot};
use zlauder_engine::UnmaskManifest;

use super::delta::{compute_delta, compute_delta_from_hashes};
use super::model::{
    ApprovalDecision, ConversationMeta, MonitorEvent, MonitorMode, MonitorSnapshot,
    RequestDecision, RequestRecord, Surface, TokenClass, TokenLedgerEntry, TurnDelta,
};
use super::spans::{now_ms, preview, spans_from_manifest, spans_from_values, token_previews};
use super::surfaces::{surfaces_from_body, surfaces_from_response_body};

const MAX_RECORDS: usize = 500;
const APPROVAL_TIMEOUT_SECS: u64 = 300;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(APPROVAL_TIMEOUT_SECS);
const DEFAULT_MAX_PENDING_APPROVALS: usize = 32;
/// Cap on the per-conversation cache of last-turn surface hashes. Keeps deltas
/// computable even after the prior turn's record is evicted from the global ring.
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
    /// Per-conversation cache of the most recent turn's `(turn_index, surface
    /// block_hashes)`. Lets the delta survive eviction of the prior turn's full
    /// record from the global ring, so a resent transcript is not mis-flagged as
    /// "first contact / all new". Bounded by [`MAX_TRACKED_CONVERSATIONS`].
    last_turn_hashes: HashMap<String, (u32, Vec<String>)>,
    /// Content-derived conversation anchors: auto-id → the conversation's current
    /// ordered sequence of non-system surface `block_hash`es. A new request with
    /// no explicit id is matched to the conversation whose anchor is a clean
    /// prefix of the request's surface sequence (longest wins); see
    /// [`resolve_content_conversation`]. Bounded by [`MAX_TRACKED_CONVERSATIONS`].
    conversation_anchors: HashMap<String, Vec<String>>,
    /// Per-conversation last-seen timestamp (ms), used as the LRU key when
    /// evicting `last_turn_hashes` / `conversation_anchors` / `labels`.
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
                last_turn_hashes: HashMap::new(),
                conversation_anchors: HashMap::new(),
                last_seen: HashMap::new(),
                labels: HashMap::new(),
                session_tokens: HashMap::new(),
            })),
            events,
        }
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
        ingest_tokens_into(&mut inner, manifest, now);
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
    ) -> ReviewTicket {
        // Compute everything that does NOT depend on shared state BEFORE taking the
        // lock. The masked body can be 100KB+ and `surfaces_from_body` parses it as
        // JSON and blake3-hashes every surface; doing that under the global mutex
        // would serialize the realtime hot path (every request blocks on every
        // other request's parse). Only the seq/turn/delta bookkeeping needs `inner`.
        let now = now_ms();
        let request_preview = preview(masked_body);
        let tokens = token_previews(manifest);
        let request_spans = spans_from_manifest(manifest, &request_preview);
        let request_surfaces = surfaces_from_body(masked_body, &tokens);
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

        let mut inner = self.inner.lock().expect("monitor mutex poisoned");
        // Fold this request's masked values into the durable ledger under the same
        // lock (a separate `ingest_session_tokens` call would deadlock the std mutex).
        ingest_tokens_into(&mut inner, manifest, now);
        let id = format!("req-{}", inner.next_seq);
        inner.next_seq += 1;

        // Resolve the conversation id. An explicit id (session URL / header) always
        // wins. Otherwise derive it from the transcript prefix; a body with no
        // anchorable surface (e.g. metadata-only) falls back to the shared
        // `"unknown"` bucket (no prefix matching — never mint from an empty head).
        let conversation_id = match conversation_id {
            Some(id) => id,
            None if anchor_seq.is_empty() => "unknown".to_string(),
            None => resolve_content_conversation(&mut inner.conversation_anchors, &anchor_seq),
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

        // Delta vs the most recent prior turn of this conversation.
        //
        // Prefer the prior turn's live record (full surface compare). If that
        // record has been evicted from the global ring, fall back to the cached
        // last-turn hashes so a resent transcript is not mislabeled. Only the
        // genuine first turn (turn_index == 1) is `is_first`; a non-first turn
        // with no prior data is `prev_unavailable`, not "all new".
        let delta = if let Some((pt, surfaces)) =
            previous_turn_surfaces(&inner.records, &conversation_id, turn_index)
        {
            compute_delta(&request_surfaces, Some((pt, &surfaces)))
        } else if let Some((pt, hashes)) = inner
            .last_turn_hashes
            .get(&conversation_id)
            .filter(|(pt, _)| *pt < turn_index)
        {
            compute_delta_from_hashes(&request_surfaces, *pt, hashes)
        } else if turn_index == 1 {
            TurnDelta::first()
        } else {
            TurnDelta::prev_unavailable(turn_index - 1)
        };

        // Cache this turn's surface hashes (computed before the lock) for future
        // delta computation after the full record is evicted from the ring; stamp
        // last-seen (the LRU eviction key); cache the conversation label once (from
        // the resent transcript's first user message — works on any turn).
        {
            // Reborrow through the guard so the field accesses are seen as
            // disjoint by the borrow checker.
            let inner = &mut *inner;
            inner
                .last_turn_hashes
                .insert(conversation_id.clone(), (turn_index, this_turn_hashes));
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

    pub fn record_response(&self, id: &str, status: u16, body: Option<&[u8]>) {
        self.update_record(id, |r| {
            // Terminal-idempotent: a late drain or a drop-guard firing after the
            // record already reached a terminal verdict must NOT resurrect
            // `Completed` over an error/abort or re-stamp the response surfaces.
            if r.decision.is_terminal() {
                return;
            }
            r.response_status = Some(status);
            r.response_preview = body.map(preview);
            r.response_spans = r
                .response_preview
                .as_deref()
                .map(|p| spans_from_values(&r.tokens, p))
                .unwrap_or_default();
            // The response body is UNMASKED here (walk::unmask_response has
            // already replaced every [ENTITY_xxxx] handle with its plaintext),
            // so segment by the canonical VALUE, not the handle.
            r.response_surfaces = body
                .map(|b| surfaces_from_response_body(b, &r.tokens))
                .unwrap_or_default();
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
}

impl CompletionGuard {
    pub fn new(monitor: Monitor, id: String, status: u16) -> Self {
        Self {
            monitor,
            id,
            status,
            armed: true,
        }
    }

    /// The stream drained normally: record `Completed` and disarm.
    pub fn complete(&mut self) {
        if std::mem::replace(&mut self.armed, false) {
            self.monitor.record_response(&self.id, self.status, None);
        }
    }

    /// The upstream stream errored mid-flight: record `UpstreamError` and disarm.
    pub fn upstream_error(&mut self, msg: &str) {
        if std::mem::replace(&mut self.armed, false) {
            self.monitor.record_upstream_error(&self.id, msg);
        }
    }
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        if self.armed {
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

/// Accumulate a manifest's entries into the durable session-token ledger held in
/// `inner`. New tokens are inserted with their first-seen timestamp; repeats bump
/// the count. Over [`MAX_SESSION_TOKENS`] the oldest entries are evicted (logged).
///
/// FORWARD-COMPAT SEAM (plan A): classification lives here, the single ingest point.
/// Today every manifest entry is detector/keyword PII → [`TokenClass::AutoPii`],
/// peekable. When the secrets engine tags manifest entries with a source, switch on
/// it here to set [`TokenClass::Guard`]/`Broker`; `is_peekable()` then suppresses
/// both the stored plaintext (`value` left empty) and UI peek — so a brokered secret
/// that interns into the manifest never reaches the snapshot in cleartext.
fn ingest_tokens_into(inner: &mut Inner, manifest: &UnmaskManifest, now: u128) {
    for e in &manifest.entries {
        if let Some(existing) = inner.session_tokens.get_mut(&e.token_handle) {
            existing.count = existing.count.saturating_add(1);
            continue;
        }
        let class = TokenClass::AutoPii;
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
                count: 1,
            },
        );
    }
    if inner.session_tokens.len() > MAX_SESSION_TOKENS {
        let over = inner.session_tokens.len() - MAX_SESSION_TOKENS;
        tracing::warn!(
            "session-token ledger over cap ({MAX_SESSION_TOKENS}); evicting {over} oldest entr{}",
            if over == 1 { "y" } else { "ies" }
        );
        // O(n) eviction: quickselect the `over` oldest into the prefix, then drop
        // them. Strictly cheaper than both the old min-scan-per-victim loop
        // (O(over * n)) and a full sort (O(n log n)) — and it runs under the global
        // monitor mutex, so the common one-over case must stay linear: a single large
        // request body can mint thousands of entries at once.
        let mut by_age: Vec<(u128, String)> = inner
            .session_tokens
            .values()
            .map(|e| (e.first_seen_ms, e.token.clone()))
            .collect();
        let over = over.min(by_age.len());
        if over > 0 {
            by_age.select_nth_unstable_by_key(over - 1, |(t, _)| *t);
            for (_, tok) in by_age.into_iter().take(over) {
                inner.session_tokens.remove(&tok);
            }
        }
    }
}

/// Find the most recent record in the same conversation with a smaller turn
/// index, returning its turn index and a clone of its request surfaces.
///
/// `records` is newest-first, so the first match older than `turn_index` is the
/// immediately-previous turn.
fn previous_turn_surfaces(
    records: &VecDeque<RequestRecord>,
    conversation_id: &str,
    turn_index: u32,
) -> Option<(u32, Vec<Surface>)> {
    records
        .iter()
        .filter(|r| r.conversation_id == conversation_id && r.turn_index < turn_index)
        .max_by_key(|r| r.turn_index)
        .map(|r| (r.turn_index, r.request_surfaces.clone()))
}

/// Bound every per-conversation map by evicting the least-recently-seen
/// conversations until back under cap. All five maps (`turn_counts`,
/// `last_seen`, `last_turn_hashes`, `conversation_anchors`, `labels`) are evicted
/// as a SET for the same victim, so they never disagree. Choosing the victim by
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
        inner.last_turn_hashes.remove(&victim);
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

/// A human conversation label: a short snippet of the first user message
/// (masked — safe to show), falling back to the endpoint + id tail. Computed
/// from `request_surfaces`, which on every turn carry the full resent transcript,
/// so the first message is present even on a mid-conversation cold start.
fn first_message_label(surfaces: &[Surface], endpoint: &str, conversation_id: &str) -> String {
    let snippet = surfaces
        .iter()
        .find(|s| s.kind == "message" && s.role.as_deref() == Some("user"))
        .or_else(|| surfaces.iter().find(|s| s.kind == "message"))
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
        m.record_llm_request("/v1/messages", "POST", None, b, &manifest)
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
            .record_llm_request("/v1/messages", "POST", None, &b, &manifest)
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
        m.record_response(&id, 200, None);
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
        m.record_response(&id, 200, None);
        assert!(matches!(find(&m, &id).decision, RequestDecision::Aborted));
        // Upstream error stays terminal under a stray completion too.
        let id2 = record(&m, &body(&[("user", json!("go2"))]));
        m.record_dispatched(&id2);
        m.record_upstream_error(&id2, "boom");
        m.record_response(&id2, 200, None);
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
        let mut g = CompletionGuard::new(m.clone(), id.clone(), 200);
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
            let _g = CompletionGuard::new(m.clone(), id.clone(), 200);
        }
        assert!(matches!(find(&m, &id).decision, RequestDecision::Aborted));
    }

    #[test]
    fn completion_guard_upstream_error_is_terminal() {
        let m = Monitor::new();
        let id = record(&m, &body(&[("user", json!("go"))]));
        m.record_dispatched(&id);
        let mut g = CompletionGuard::new(m.clone(), id.clone(), 200);
        g.upstream_error("boom");
        drop(g); // disarmed → stays UpstreamError, not Aborted
        assert!(matches!(
            find(&m, &id).decision,
            RequestDecision::UpstreamError
        ));
    }

    fn manifest_with(token: &str, value: &str) -> UnmaskManifest {
        let mut m = UnmaskManifest::new();
        m.push(zlauder_engine::ManifestEntry {
            canonical_form: value.to_string(),
            token_handle: token.to_string(),
            entity_kind: "EMAIL_ADDRESS".to_string(),
            arrow_origin: zlauder_engine::Surface::UserMessage,
            exposed_at: None,
        });
        m
    }

    #[test]
    fn session_token_survives_record_ring_eviction() {
        let m = Monitor::new();
        // A request masking a distinct value seeds the ledger.
        let early = manifest_with("[EMAIL_0001]", "alice@example.com");
        m.record_llm_request("/v1/messages", "POST", None, &body(&[("user", json!("hi"))]), &early);

        // Flood the 500-record ring so the seeding record is evicted.
        for i in 0..(MAX_RECORDS + 5) {
            let b = body(&[("user", json!(format!("turn {i}")))]);
            m.record_llm_request("/v1/messages", "POST", Some(format!("c{i}")), &b, &UnmaskManifest::new());
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
        m.turn_count = m.turn_count.max(r.turn_index);
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
