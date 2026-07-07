//! Registered-secret tripwire (A2b, GAP-CLOSURE G1/L20).
//!
//! A2a gave the engine a scan-only primitive
//! ([`MaskEngine::registered_secret_hit`]) that returns the NAME (never the value)
//! of the first registered secret whose exact value appears in a string. A2b is the
//! PROXY half: when a registered secret's value turns up inside a subtree the walkers
//! NEVER rewrite — `tool.input_schema`, an OpenAI contract-key subtree, or an
//! Anthropic `extra` flatten sink — forwarding it verbatim would leak the secret in
//! plaintext. This module walks such a subtree and, on a hit, hands the caller the
//! secret name so it can REFUSE (409) instead. It is detect-then-refuse, not mask: the
//! subtree is still never rewritten (the no-mask-schema invariant is untouched).
//!
//! Both scanners inspect object KEYS as well as values — a registered secret used as a
//! JSON object key (`properties.<SECRET>`) is just as much a leak as one used as a
//! value.

use serde_json::{Map, Value};
use sordino_engine::MaskEngine;

/// Bound on recursion into an attacker-shaped subtree. serde_json itself rejects a body
/// nested deeper than 128 before any walker runs, so this cap only ever engages on a body
/// that already parsed; it is a belt for the (already-closed) deep-nesting hole, never the
/// primary defense.
const MAX_SCAN_DEPTH: u32 = 256;

/// Recursively scan a JSON value for a registered-secret hit, returning the NAME of the
/// first secret found (never its value). Scans object KEYS as well as their values.
/// Returns `None` past [`MAX_SCAN_DEPTH`].
pub fn scan_value(engine: &MaskEngine, v: &Value, depth: u32) -> Option<String> {
    if depth > MAX_SCAN_DEPTH {
        return None;
    }
    match v {
        Value::String(s) => engine.registered_secret_hit(s),
        Value::Array(a) => a.iter().find_map(|x| scan_value(engine, x, depth + 1)),
        Value::Object(o) => o.iter().find_map(|(k, x)| {
            engine
                .registered_secret_hit(k)
                .or_else(|| scan_value(engine, x, depth + 1))
        }),
        _ => None,
    }
}

/// Scan an object map (a flatten `extra` sink) for a registered-secret hit, returning the
/// NAME of the first secret found. Scans KEYS as well as values.
pub fn scan_map(engine: &MaskEngine, m: &Map<String, Value>) -> Option<String> {
    m.iter().find_map(|(k, v)| {
        engine
            .registered_secret_hit(k)
            .or_else(|| scan_value(engine, v, 0))
    })
}
