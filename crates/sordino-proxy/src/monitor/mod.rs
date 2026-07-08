//! Local realtime request monitor and optional approval gate.
//!
//! Decomposed into focused submodules:
//!   * [`model`]    — serde data contract (records, surfaces, runs, deltas).
//!   * [`store`]    — [`Monitor`] state, ring buffer, turn/conversation index.
//!   * [`surfaces`] — server-side message parsing + byte-correct run segmentation.
//!   * [`delta`]    — per-turn context delta (what is new this turn).
//!   * [`spans`]    — legacy byte-offset spans for the raw preview views.
//!   * [`http`]     — axum handlers (snapshot/mode/approve/reject/tags/mask/events).
//!   * [`ui`]       — compile-time assembled UI served at `/sordino/ui`.
//!
//! The public API below is re-exported at exactly these paths so
//! `routes.rs` / `main.rs` / `openai_chat.rs` / `openai_responses.rs` / `lib.rs`
//! compile with no path changes.

mod capture;
mod delta;
mod http;
mod ledger;
mod model;
mod persist;
mod spans;
mod store;
mod surfaces;
mod ui;

// --- preserved public API surface ---

pub use capture::CapKind;
pub use ledger::{Ledger, LedgerEvent};
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
pub(crate) use store::ROUTED_RECENTLY_WINDOW_MS;
pub use ui::ui;

use ::http::HeaderMap;
use uuid::Uuid;

/// Conversation id from the request headers.
///
/// Precedence:
///   1. `x-sordino-conversation` — the Claude/`sordino` path (UserPromptSubmit hook).
///   2. `session-id` — Codex's per-session header (it never sends
///      `x-sordino-conversation`); A0-verified to carry the same id the
///      UserPromptSubmit hook reports as `session_id`.
///   3. `thread-id` — Codex's fallback, byte-identical to `session-id`.
///
/// Without the Codex `session-id`/`thread-id` fallback every Codex inbound would key
/// as missing in the monitor's `last_seen`, leaving the per-session inbound
/// observability endpoint unable to ever attribute Codex traffic to a session.
pub fn conversation_from_headers(hdrs: &HeaderMap) -> Option<String> {
    for name in ["x-sordino-conversation", "session-id", "thread-id"] {
        if let Some(id) = hdrs
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
        {
            return Some(id);
        }
    }
    None
}

/// A fresh random conversation id (used when no session id is supplied).
pub fn random_conversation_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::http::HeaderValue;

    #[test]
    fn conversation_from_headers_precedence_and_codex_fallback() {
        // x-sordino-conversation wins when present (even if Codex headers also set).
        let mut h = HeaderMap::new();
        h.insert("x-sordino-conversation", HeaderValue::from_static("zl-conv"));
        h.insert("session-id", HeaderValue::from_static("codex-sess"));
        h.insert("thread-id", HeaderValue::from_static("codex-thread"));
        assert_eq!(conversation_from_headers(&h).as_deref(), Some("zl-conv"));

        // Codex request (no x-sordino-conversation): keys by `session-id`.
        let mut h = HeaderMap::new();
        h.insert(
            "session-id",
            HeaderValue::from_static("019f0504-a6af-7253-8f6e-b6a41e31d7c4"),
        );
        h.insert(
            "thread-id",
            HeaderValue::from_static("019f0504-a6af-7253-8f6e-b6a41e31d7c4"),
        );
        assert_eq!(
            conversation_from_headers(&h).as_deref(),
            Some("019f0504-a6af-7253-8f6e-b6a41e31d7c4")
        );

        // session-id absent → falls back to thread-id.
        let mut h = HeaderMap::new();
        h.insert("thread-id", HeaderValue::from_static("only-thread"));
        assert_eq!(conversation_from_headers(&h).as_deref(), Some("only-thread"));

        // An empty / whitespace x-sordino-conversation is rejected, then falls through.
        let mut h = HeaderMap::new();
        h.insert("x-sordino-conversation", HeaderValue::from_static("   "));
        h.insert("session-id", HeaderValue::from_static("codex-sess"));
        assert_eq!(conversation_from_headers(&h).as_deref(), Some("codex-sess"));

        // Absent-all → None.
        let h = HeaderMap::new();
        assert_eq!(conversation_from_headers(&h), None);
    }
}
