//! Shared proxy state.

use std::sync::Arc;
use zlauder_engine::MaskEngine;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<MaskEngine>,
    pub http: reqwest::Client,
    pub upstream_base: Arc<String>,
    /// Hex of the session key; required (via `x-zlauder-key`) to call the audit
    /// reveal endpoint, so it is not a trivial deanon oracle for a tool `curl`.
    pub admin_key: Arc<String>,
}

impl AppState {
    /// Host portion of the upstream base URL (for the rewritten `Host` header).
    pub fn upstream_host(&self) -> &str {
        self.upstream_base
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("api.anthropic.com")
    }
}
