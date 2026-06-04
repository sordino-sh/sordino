//! Verbatim header passthrough with hop-by-hop filtering.

use http::header::{ACCEPT_ENCODING, HOST, HeaderMap, HeaderValue};

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
