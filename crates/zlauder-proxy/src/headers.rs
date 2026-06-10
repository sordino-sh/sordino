//! Verbatim header passthrough with hop-by-hop filtering.

use http::header::{ACCEPT_ENCODING, HOST, HeaderMap, HeaderName, HeaderValue};

use crate::zdr::ZdrTarget;

const HOP_BY_HOP: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "accept-encoding",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.contains(&name)
}

/// Headers to send upstream: everything from the client (incl. `x-api-key`,
/// `anthropic-version`, `anthropic-beta`, `authorization`) minus hop-by-hop,
/// with `host` rewritten and compression disabled so we can scan plaintext.
pub fn upstream_request_headers(incoming: &HeaderMap, upstream_host: &str) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in incoming.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    if let Ok(h) = HeaderValue::from_str(upstream_host) {
        out.insert(HOST, h);
    }
    out.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    out
}

/// Headers to send to a **ZDR** target. Like [`upstream_request_headers`] but it
/// **strips the client's credentials** (the subscription `authorization` bearer and
/// any `x-api-key`) — that token must NEVER reach a third-party endpoint (ToS +
/// leak) — and injects the target's env-sourced ZDR credential as `x-api-key`,
/// then the target's (config-validated, non-secret) extra headers, then the
/// rewritten `Host`. An empty credential means a no-auth endpoint (nothing injected).
pub fn upstream_request_headers_zdr(
    incoming: &HeaderMap,
    upstream_host: &str,
    target: &ZdrTarget,
) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in incoming.iter() {
        let n = name.as_str();
        if is_hop_by_hop(n) {
            continue;
        }
        // Strip the CLIENT's credentials — never forward the subscription token to a
        // ZDR target. ZDR auth is injected below from the env-sourced credential.
        if n.eq_ignore_ascii_case("authorization") || n.eq_ignore_ascii_case("x-api-key") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    // Inject the ZDR credential (env-sourced, in-process only). Empty ⇒ no-auth.
    let key = target.key();
    if !key.is_empty()
        && let Ok(v) = HeaderValue::from_str(key.as_str())
    {
        out.insert("x-api-key", v);
    }
    // Target-specific extra headers (non-secret; auth-bearing names are rejected at
    // config load). These OVERRIDE any forwarded value of the same name.
    for (k, v) in &target.extra_headers {
        if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v))
        {
            out.insert(name, val);
        }
    }
    if let Ok(h) = HeaderValue::from_str(upstream_host) {
        out.insert(HOST, h);
    }
    out.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    out
}

/// Headers to return to the client. When the body was rewritten (JSON unmask or
/// SSE re-emission) we drop `content-length` / `content-encoding` since the
/// length changes and the stream is chunked.
pub fn downstream_response_headers(upstream: &HeaderMap, body_rewritten: bool) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream.iter() {
        let n = name.as_str();
        if is_hop_by_hop(n) {
            continue;
        }
        if body_rewritten && (n == "content-length" || n == "content-encoding") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}
