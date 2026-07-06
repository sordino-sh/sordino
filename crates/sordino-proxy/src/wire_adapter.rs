//! The egress seam: turn a (already-masked) request body into the concrete
//! upstream `(url, headers, body)`.
//!
//! This is a **net-new** trait introduced by the ZDR foundation. Today `send_upstream`
//! is a flat function that prepends `upstream_base` and forwards verbatim headers;
//! the foundation routes that dispatch through [`WireAdapter`] instead, so a future
//! non-Anthropic wire (Bedrock SigV4 over the canonicalized body, vLLM OpenAI-wire
//! translation) becomes a new *impl* rather than a second rewrite of dispatch.
//!
//! The foundation ships exactly one impl, [`AnthropicNative`], with two routing
//! modes selected by [`PinnedMode`]:
//!   - **Normal** — byte-identical to pre-ZDR behaviour: `upstream_base` + verbatim
//!     client headers (minus hop-by-hop), `Host` rewritten.
//!   - **ZDR** — the target's `base_url`, with the client's **subscription
//!     credential stripped** and the env-sourced ZDR credential injected. The
//!     subscription token MUST NOT reach a third-party endpoint (ToS + leak).

use std::sync::Arc;

use http::HeaderMap;

use crate::headers;
use crate::zdr::{PinnedMode, ZdrTarget};

/// The concrete upstream request an adapter produces from a masked body.
pub struct WireRequest {
    pub url: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// The egress seam. One method: dress a masked body for the wire.
pub trait WireAdapter {
    /// Build the upstream request. `incoming` is the client's header map; `path` is
    /// the upstream path (incl. any query for the verbatim relay).
    fn build(&self, incoming: &HeaderMap, path: &str, masked_body: Vec<u8>) -> WireRequest;
}

/// The Anthropic Messages wire — the only adapter in the foundation. Carries either
/// the default upstream (ZDR `None`) or a resolved ZDR target.
pub struct AnthropicNative {
    base_url: String,
    host: String,
    /// `None` ⇒ default upstream (verbatim client creds); `Some` ⇒ ZDR routing
    /// (strip client creds, inject the target's env-sourced credential).
    zdr: Option<Arc<ZdrTarget>>,
}

impl AnthropicNative {
    /// Build the adapter for a request's pinned trust posture. `default_base` /
    /// `default_host` are the proxy's normal upstream (used when not ZDR-routed).
    pub fn for_mode(default_base: &str, default_host: &str, pinned: &PinnedMode) -> Self {
        match pinned {
            PinnedMode::Normal => Self {
                base_url: default_base.to_string(),
                host: default_host.to_string(),
                zdr: None,
            },
            PinnedMode::Zdr(t) => Self {
                base_url: t.base_url.clone(),
                host: t.host.clone(),
                zdr: Some(t.clone()),
            },
        }
    }
}

impl WireAdapter for AnthropicNative {
    fn build(&self, incoming: &HeaderMap, path: &str, masked_body: Vec<u8>) -> WireRequest {
        let url = format!("{}{}", self.base_url, path);
        let headers = match &self.zdr {
            // Byte-identical to pre-ZDR egress.
            None => headers::upstream_request_headers(incoming, &self.host),
            // Strip client creds; inject the ZDR credential + extra headers.
            Some(t) => headers::upstream_request_headers_zdr(incoming, &self.host, t),
        };
        WireRequest {
            url,
            headers,
            body: masked_body,
        }
    }
}
