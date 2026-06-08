//! Serde data types for the monitor data contract.
//!
//! Every type here is serialized as `snake_case` JSON over
//! `/zlauder/monitor/snapshot` and the SSE `/events` stream. Integration tests
//! assert on the field names of [`RequestRecord`], so existing fields must never
//! be renamed or removed; additive fields are safe.

use serde::{Deserialize, Serialize};

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
    Rejected,
    BackpressureRejected,
    TimedOut,
    UpstreamError,
    Completed,
}

/// One masked token occurrence, with its hidden plaintext (local UI only).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenPreview {
    pub token: String,
    pub value: String,
    pub entity_kind: String,
    pub surface: String,
    pub request_start: Option<usize>,
    pub request_end: Option<usize>,
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
    /// Pre-segmented reviewable surfaces of the masked request body.
    pub request_surfaces: Vec<Surface>,
    /// Pre-segmented reviewable surfaces of the response body (best effort).
    pub response_surfaces: Vec<Surface>,
    /// What is new this turn vs the previous turn of the same conversation.
    pub delta: TurnDelta,
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
}

fn default_approval_timeout_secs() -> u64 {
    300
}

/// SSE event envelope: `{ "event": ..., "data": ... }`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "event", content = "data")]
pub(crate) enum MonitorEvent {
    Snapshot(Box<MonitorSnapshot>),
    Record(Box<RequestRecord>),
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

fn default_true() -> bool {
    true
}
