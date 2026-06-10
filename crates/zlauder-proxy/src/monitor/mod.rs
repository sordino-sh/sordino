//! Local realtime request monitor and optional approval gate.
//!
//! Decomposed into focused submodules:
//!   * [`model`]    — serde data contract (records, surfaces, runs, deltas).
//!   * [`store`]    — [`Monitor`] state, ring buffer, turn/conversation index.
//!   * [`surfaces`] — server-side message parsing + byte-correct run segmentation.
//!   * [`delta`]    — per-turn context delta (what is new this turn).
//!   * [`spans`]    — legacy byte-offset spans for the raw preview views.
//!   * [`http`]     — axum handlers (snapshot/mode/approve/reject/tags/mask/events).
//!   * [`ui`]       — compile-time assembled UI served at `/zlauder/ui`.
//!
//! The public API below is re-exported at exactly these paths so
//! `routes.rs` / `main.rs` / `openai_chat.rs` / `openai_responses.rs` / `lib.rs`
//! compile with no path changes.

mod capture;
mod delta;
mod http;
mod model;
mod persist;
mod spans;
mod store;
mod surfaces;
mod ui;

// --- preserved public API surface ---

pub use capture::CapKind;
pub use http::{
    approve, custom_mask, custom_masks_list, custom_masks_remove, events, maybe_approve,
    reject, remask_keyphrase, reveal_keyphrase, set_mode, snapshot, tags,
};
pub use model::{
    ConversationMeta, CustomMaskRequest, ModeRequest, MonitorMode, MonitorSnapshot, PreviewSpan,
    RejectRequest, RequestDecision, RequestRecord, ResponseProgress, Run, Surface, TagsRequest,
    TokenClass, TokenLedgerEntry, TokenPreview, TokenRef, TurnDelta,
};
pub use store::{CompletionGuard, Monitor, ReviewTicket};
pub use ui::ui;

use ::http::HeaderMap;
use uuid::Uuid;

/// Conversation id from the `x-zlauder-conversation` header fallback.
pub fn conversation_from_headers(hdrs: &HeaderMap) -> Option<String> {
    hdrs.get("x-zlauder-conversation")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// A fresh random conversation id (used when no session id is supplied).
pub fn random_conversation_id() -> String {
    Uuid::new_v4().to_string()
}
