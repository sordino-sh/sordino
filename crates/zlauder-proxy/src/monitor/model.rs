//! Serde data types for the monitor data contract.
//!
//! Every type here is serialized as `snake_case` JSON over
//! `/zlauder/monitor/snapshot` and the SSE `/events` stream. Integration tests
//! assert on the field names of [`RequestRecord`], so existing fields must never
//! be renamed or removed; additive fields are safe.

use serde::{Deserialize, Serialize};
use zlauder_engine::{ENTITY_CVV, ManifestEntry};

/// Monitor operating mode. Decides whether requests are held for approval.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorMode {
    /// Observe only; never hold a request.
    Off,
    /// Hold every LLM request for manual approval.
    ManualAllLlm,
    /// Hold only requests where masking detected at least one token.
    ManualOnDetection,
}

/// Internal approval verdict produced by the UI or the timeout path.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub(crate) enum ApprovalDecision {
    Approve,
    Reject { reason: String },
}

/// The lifecycle state of a recorded request, as shown to the operator.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestDecision {
    AutoAccepted,
    Pending,
    Approved,
    /// Released upstream; awaiting (or streaming) the response. Set by
    /// `record_dispatched` just before the upstream call and cleared to
    /// `Completed` when the response body / SSE stream finishes.
    InFlight,
    Rejected,
    BackpressureRejected,
    TimedOut,
    UpstreamError,
    /// The downstream client disconnected before the response completed (the
    /// streamed body was dropped mid-flight). Terminal.
    Aborted,
    Completed,
}

impl RequestDecision {
    /// A terminal verdict that later lifecycle writes must not overwrite. Keeps
    /// a stream drop-guard / late drain from resurrecting `Completed` over an
    /// error or abort, or double-stamping a finished record.
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(
            self,
            RequestDecision::Rejected
                | RequestDecision::BackpressureRejected
                | RequestDecision::TimedOut
                | RequestDecision::UpstreamError
                | RequestDecision::Aborted
                | RequestDecision::Completed
        )
    }
}

/// One masked token occurrence, with its hidden plaintext (local UI only).
///
/// Carries the same `class` / `peekable` redaction seam as [`TokenLedgerEntry`]:
/// this is the OTHER value-bearing surface (it rides every `RequestRecord` and the
/// per-record SSE frame, and the UI's live ledger augmentation reads it), so it must
/// honor the same gate or a future secret-class value would leak here even though the
/// ledger withholds it. Today all tokens are [`TokenClass::AutoPii`] ⇒ peekable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenPreview {
    pub token: String,
    /// Canonical plaintext, or empty when `!peekable`.
    pub value: String,
    pub entity_kind: String,
    pub surface: String,
    pub request_start: Option<usize>,
    pub request_end: Option<usize>,
    #[serde(default = "default_token_class")]
    pub class: TokenClass,
    #[serde(default = "default_peekable")]
    pub peekable: bool,
}

fn default_token_class() -> TokenClass {
    TokenClass::AutoPii
}
fn default_peekable() -> bool {
    true
}
/// Fail-toward-showing default for [`Surface::provenance`]: an entry whose lane is
/// unknown is treated as genuine user content (shown), never as collapsible scaffolding.
fn default_provenance() -> String {
    "user_input".to_string()
}

/// A legacy byte-offset span over a preview string, used only for the raw
/// "Full Masked Request" / response previews. New UI rendering uses
/// pre-segmented [`Surface`]/[`Run`] instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviewSpan {
    pub start: usize,
    pub end: usize,
    pub token: String,
    pub entity_kind: String,
    pub surface: String,
}

/// A reference from a masked-token run back to the plaintext it hides.
///
/// `surface` is the arrow origin (e.g. `UserMessage`) recorded by the engine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRef {
    /// The `[ENTITY_xxxx]` handle that appears in the masked text.
    pub token: String,
    /// The canonical plaintext that was hidden behind the handle.
    pub value: String,
    pub entity_kind: String,
    /// Arrow origin string (`UserMessage`, `SystemPrompt`, ...).
    pub surface: String,
}

/// A contiguous run of a surface's masked text.
///
/// `token == None` => plain text. `token == Some` => a masked-token occurrence.
/// Concatenating every `run.text` of a surface reproduces that surface's masked
/// text exactly (byte-for-byte), so the client renders with zero offset math.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenRef>,
}

/// A single reviewable text surface extracted from a request/response body
/// (a system prompt, an instructions field, one message, one tool result, ...).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Surface {
    /// Human label, e.g. `messages[2] - user`.
    pub label: String,
    /// Role, when the source carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Coarse classification: `system|instructions|message|tool_result|other`.
    pub kind: String,
    /// Provenance lane (server-derived HINT): one of `harness_meta | harness_frame |
    /// userctx | user_input | tool_io | assistant`. Drives labels / ledger grouping /
    /// de-noise (plan §1A/§1B). A hint only — unrecognized content falls through to
    /// `user_input` (shown), and provenance NEVER gates detection. Additive;
    /// deserializes to `user_input` (the fail-toward-showing default) when absent.
    #[serde(default = "default_provenance")]
    pub provenance: String,
    /// Pre-segmented runs; concatenating `run.text` reproduces the surface text.
    pub runs: Vec<Run>,
    /// Short blake3 hex of the surface masked text (delta / dedupe key).
    pub block_hash: String,
}

/// Per-request delta vs the previous turn of the same conversation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TurnDelta {
    /// 1-based turn index of the previous turn, if any.
    pub prev_turn: Option<u32>,
    /// True only for the genuine first turn of its conversation.
    pub is_first: bool,
    /// True when this is NOT the first turn but the previous turn's surfaces are
    /// no longer available (evicted from the ring and no cached hashes), so the
    /// delta could not be computed. Distinct from `is_first`: the UI must tell
    /// the operator to audit the full request rather than claim "all new".
    #[serde(default)]
    pub prev_unavailable: bool,
    /// `block_hash`es present this turn but absent in the previous turn.
    pub added_surface_hashes: Vec<String>,
}

impl TurnDelta {
    /// Delta for the genuine first turn of a conversation: everything is new.
    pub fn first() -> Self {
        Self {
            prev_turn: None,
            is_first: true,
            prev_unavailable: false,
            added_surface_hashes: Vec::new(),
        }
    }

    /// Delta for a non-first turn whose previous turn is unavailable (evicted).
    /// The delta cannot be computed, so no surfaces are flagged new; the UI
    /// directs the operator to audit the full request.
    pub fn prev_unavailable(prev_turn: u32) -> Self {
        Self {
            prev_turn: Some(prev_turn),
            is_first: false,
            prev_unavailable: true,
            added_surface_hashes: Vec::new(),
        }
    }
}

/// One recorded request and its evolving response/decision state.
///
/// PRESERVED FIELDS (asserted by integration tests): `id`, `conversation_id`,
/// `endpoint`, `method`, `started_ms`, `updated_ms`, `decision`,
/// `request_preview`, `request_spans`, `response_preview`, `response_spans`,
/// `response_status`, `tokens`, `tags`, `rejection_reason`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestRecord {
    pub id: String,
    pub conversation_id: String,
    pub endpoint: String,
    pub method: String,
    pub started_ms: u128,
    pub updated_ms: u128,
    pub decision: RequestDecision,
    pub request_preview: String,
    pub request_spans: Vec<PreviewSpan>,
    pub response_preview: Option<String>,
    pub response_spans: Vec<PreviewSpan>,
    pub response_status: Option<u16>,
    pub tokens: Vec<TokenPreview>,
    pub tags: Vec<String>,
    pub rejection_reason: Option<String>,
    // --- additive fields (overhaul) ---
    /// 1-based position of this request within its conversation, by start order.
    pub turn_index: u32,
    /// When the request was released upstream (`record_dispatched`). Drives the
    /// live "streaming" elapsed timer in the UI. `None` until dispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_ms: Option<u128>,
    /// Pre-segmented reviewable surfaces of the masked request body.
    pub request_surfaces: Vec<Surface>,
    /// Pre-segmented reviewable surfaces of the response body (best effort).
    pub response_surfaces: Vec<Surface>,
    /// What is new this turn vs the previous turn of the same conversation.
    pub delta: TurnDelta,
    /// 1-based index of the HUMAN turn this request belongs to within its conversation
    /// — the user message that began this tool-cycle, NOT the per-request `turn_index`.
    /// One human prompt that spawns N tool round-trips shares ONE `human_turn_index`
    /// across all N requests, so the UI nests the tool-cycle under its human turn. A new
    /// human turn is detected when this request carries MORE `user_input` surfaces than the
    /// prior turn of the same conversation (the whole transcript is resent every turn, so
    /// presence alone is not enough; counting also catches a repeated byte-identical prompt
    /// that a hash-delta would miss, and survives record-ring eviction of the prior turn).
    /// `0` means no human turn observed yet (pre-prompt / old snapshot) → shown ungrouped
    /// (fail toward showing). Presentation grouping only. Additive; deserializes to `0`.
    #[serde(default)]
    pub human_turn_index: u32,
}

/// Provenance class of a masked value, carried on every [`TokenLedgerEntry`].
///
/// FORWARD-COMPAT SEAM (plan A ↔ plan B): the secrets engine will introduce
/// guard/broker secret values that flow through the masking manifest. Those MUST
/// NOT be peekable in the operator UI and their plaintext MUST be redacted out of
/// the snapshot server-side (a guard/broker value in the monitor is a leak). The
/// `class` + [`TokenLedgerEntry::peekable`] pair is that gate, present from day one
/// so the ledger never has to be re-founded: the secrets engine sets the reserved
/// variants below and `is_peekable()` returns `false`, suppressing both peek and
/// value transport. Today every masked token is detector/keyword PII, all peekable.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    /// A presidio/regex auto-detected PII token. Plaintext peekable locally.
    AutoPii,
    /// A user-defined custom keyphrase mask. Plaintext peekable locally.
    Custom,
    /// RESERVED (secrets engine): a guarded secret the model never sees and that is
    /// never revealable. Not produced yet; peek + value transport are suppressed.
    Guard,
    /// RESERVED (secrets engine): a brokered secret resolved at the tool boundary
    /// (interned, so it WOULD appear in the manifest). Not produced yet; tool-only,
    /// peek + value transport suppressed.
    Broker,
    /// PCI Sensitive Authentication Data (CVV/CVC) that nonetheless rode the reversible
    /// `Token` path — only reachable if a deployment overrode the built-in CVV→`Redact`
    /// default back to a reversible operator. SAD must never be stored, so even when a
    /// reversible token mints a manifest entry, its plaintext is withheld from the ledger
    /// (non-peekable). Defense-in-depth backstop to the C8 `Redact` default (cvv-plan.md
    /// Part 3 C8); the primary protection is that CVV redacts out of the box.
    Sad,
}

impl TokenClass {
    /// Whether a value of this class may have its plaintext shown (peek) and carried
    /// in the snapshot. Secret classes (guard/broker) and PCI SAD ([`TokenClass::Sad`])
    /// are never peekable.
    pub fn is_peekable(self) -> bool {
        matches!(self, TokenClass::AutoPii | TokenClass::Custom)
    }

    /// THE single classification point for both value-bearing surfaces — the durable
    /// ledger ([`TokenLedgerEntry`]) and per-record token previews ([`TokenPreview`]).
    /// Detector/keyword PII is [`TokenClass::AutoPii`] (peekable). Two structural
    /// exceptions are withheld from peek + plaintext transport via [`is_peekable`]:
    ///
    /// - CVV: PCI Sensitive Authentication Data that must never be stored. CVV defaults
    ///   to the irreversible `Redact` operator (which mints NO manifest entry, so it
    ///   never reaches here) — but a deployment may override CVV back to a reversible
    ///   `Token`, at which point it WOULD intern into the manifest. We classify it
    ///   [`TokenClass::Sad`] (non-peekable) as a defense-in-depth backstop to the C8
    ///   `Redact` default (cvv-plan.md Part 3 C8).
    /// - Brokered secrets: a broker `ManifestEntry` carries the value in
    ///   `canonical_form`; classify it [`TokenClass::Broker`] (non-peekable). (Guard/
    ///   `hash` secrets are colon-form, never interned, so they never reach a manifest
    ///   entry — there is no `Guard` manifest path to switch on here.)
    ///
    /// [`is_peekable`]: TokenClass::is_peekable
    pub fn for_manifest_entry(e: &ManifestEntry) -> TokenClass {
        if e.entity_kind == ENTITY_CVV {
            TokenClass::Sad
        } else if e.broker {
            TokenClass::Broker
        } else {
            TokenClass::AutoPii
        }
    }
}

/// One distinct masked value observed this proxy session, accumulated durably
/// (independent of the 500-entry record ring) so the ledger is genuinely
/// session-scoped. `value` is empty when `!peekable` (a secret class) — redaction
/// is structural, not a UI courtesy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenLedgerEntry {
    /// The `[ENTITY_xxxx]` handle that appears in masked text.
    pub token: String,
    /// Canonical plaintext, or empty when `!peekable`.
    pub value: String,
    pub entity_kind: String,
    pub class: TokenClass,
    /// May the UI peek the plaintext? `false` for secret classes (and then `value`
    /// is empty). The UI gates per-row peek on this flag alone — it never needs to
    /// know the class taxonomy.
    pub peekable: bool,
    /// First time this token was seen this session (ms since epoch); the ledger
    /// sort key. (Eviction keys on `last_seen_ms`, not this — a value first seen
    /// long ago but still actively masked must not be evicted.)
    pub first_seen_ms: u128,
    /// Most recent time this token was masked this session (ms since epoch); the
    /// eviction key (least-recently-seen evicted first), so a frequently-reused
    /// secret is not dropped while still active. Additive; deserializes to `0` when
    /// absent (an old snapshot then treats the entry as eviction-eligible-first,
    /// which is harmless for display-only historical data).
    #[serde(default)]
    pub last_seen_ms: u128,
    /// How many times the value has been masked this session.
    pub count: u64,
    /// Highest-signal provenance lane this value has been seen in this session
    /// (presentation hint for ledger grouping; plan §1A): `userctx | tool_io |
    /// user_input | assistant | harness_frame | harness_meta`. A value EVER seen in a
    /// non-scaffolding lane is recorded as that lane, so it is never folded as
    /// scaffolding ("any non-frame sighting disqualifies suppression"). `None` when no
    /// classified surface carried it (e.g. a `count_tokens`-only sighting) → rendered
    /// "unclassified" (always shown). Presentation only — NEVER gates detection,
    /// masking, or eviction. Additive; deserializes to `None` on old snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

/// A conversation grouping shown in the sidebar/timeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationMeta {
    pub id: String,
    pub label: String,
    pub turn_count: u32,
    pub last_updated_ms: u128,
    pub pending_count: u32,
}

/// Full monitor state returned by `/snapshot` and the initial SSE frame.
///
/// PRESERVED FIELDS: `mode`, `pending_count`, `max_pending_approvals`,
/// `records`. Additive: `conversations`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorSnapshot {
    pub mode: MonitorMode,
    pub pending_count: usize,
    pub max_pending_approvals: usize,
    pub records: Vec<RequestRecord>,
    pub conversations: Vec<ConversationMeta>,
    /// Server-side hold timeout in seconds. A pending request silently becomes a
    /// reject after this elapses; the UI drives a live countdown from this value.
    /// Additive field; deserializes to the historical default when absent.
    #[serde(default = "default_approval_timeout_secs")]
    pub approval_timeout_secs: u64,
    /// Durable, session-scoped ledger of every distinct value masked this proxy
    /// session (sorted by `first_seen_ms`). Survives 500-record ring eviction so the
    /// secrets ledger is genuinely session-complete. Additive; only rides full
    /// snapshots (not per-record SSE frames). Deserializes empty when absent.
    #[serde(default)]
    pub session_tokens: Vec<TokenLedgerEntry>,
}

fn default_approval_timeout_secs() -> u64 {
    300
}

/// A live, in-flight update of a STREAMED response, carried on its own lightweight
/// SSE frame rather than the whole [`RequestRecord`].
///
/// The three SSE relay paths unmask the upstream reply frame-by-frame and forward it
/// downstream; this frame mirrors the same unmasked text onto the monitor as it streams,
/// so the operator watches the model's reply paint in on the SAME turn — instead of only
/// seeing it once the NEXT request resends it as transcript. Kept separate from the
/// `Record` frame on purpose: re-broadcasting the entire (often 100KB+) request body on
/// every text chunk would be wasteful, so only the growing response rides here. The UI
/// merges these onto the matching record by `id`. The terminal `Completed` state still
/// arrives on a full `Record` frame when the stream drains.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseProgress {
    pub id: String,
    pub status: u16,
    pub response_preview: String,
    pub response_surfaces: Vec<Surface>,
}

/// SSE event envelope: `{ "event": ..., "data": ... }`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "event", content = "data")]
pub(crate) enum MonitorEvent {
    Snapshot(Box<MonitorSnapshot>),
    Record(Box<RequestRecord>),
    /// The live masking policy changed. Payload is the same JSON shape as
    /// `GET /zlauder/config` (`{ config, ml, … }`). Pushed by every control-plane
    /// writer (UI PUT, `/zlauder:privacy` CLI, profile, ml toggle, reload) so any
    /// open policy panel re-syncs the instant the policy moves — the panel is then
    /// a faithful live mirror, never a stale snapshot from when it was opened.
    Policy(Box<serde_json::Value>),
    /// A streamed response grew. Lightweight live update of one record's `response_*`
    /// fields (see [`ResponseProgress`]); emitted by the SSE relay as the model replies.
    ResponseProgress(Box<ResponseProgress>),
}

// --- request DTOs (HTTP input bodies) ---

#[derive(Deserialize)]
pub struct ModeRequest {
    pub(crate) mode: MonitorMode,
    #[serde(default)]
    pub(crate) max_pending_approvals: Option<usize>,
}

#[derive(Deserialize)]
pub struct RejectRequest {
    #[serde(default)]
    pub(crate) reason: String,
}

#[derive(Deserialize)]
pub struct TagsRequest {
    #[serde(default)]
    pub(crate) tags: Vec<String>,
}

#[derive(Deserialize)]
pub struct CustomMaskRequest {
    pub(crate) pattern: String,
    #[serde(default)]
    pub(crate) entity_type: Option<String>,
    #[serde(default = "default_true")]
    pub(crate) case_sensitive: bool,
}

/// Remove one custom-mask rule (matched by `pattern` + `entity_type`), both live
/// and from the persisted `zlauder.local.toml`.
#[derive(Deserialize)]
pub struct CustomMaskRemoveRequest {
    pub(crate) pattern: String,
    #[serde(default)]
    pub(crate) entity_type: Option<String>,
}

/// Reveal a value to the model: allow-list it (so future requests egress it
/// plaintext) and, if it was backed by a custom rule, drop that rule too. Durable.
#[derive(Deserialize)]
pub struct RevealRequest {
    /// The plaintext value to start passing through unmasked.
    pub(crate) value: String,
    /// When the value is a custom keyphrase, its rule `pattern` (so we also remove
    /// the backing `CustomReplacement`). Optional — auto-detected values have none.
    #[serde(default)]
    pub(crate) pattern: Option<String>,
    /// `entity_type` of the backing custom rule (defaults to `CUSTOM_KEYWORD`).
    #[serde(default)]
    pub(crate) entity_type: Option<String>,
}

/// Re-mask a previously-revealed value: lift its allow-list suppression so
/// detection resumes. Does NOT recreate a removed custom rule.
#[derive(Deserialize)]
pub struct RemaskRequest {
    pub(crate) value: String,
}

fn default_true() -> bool {
    true
}
