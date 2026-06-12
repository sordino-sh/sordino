//! HTTP ML recognizer: token-classification over a remote endpoint instead of
//! the in-process Candle backend (`backend = "http"` in `[engine.ml]`).
//!
//! Speaks the HF token-classification schema, so HF-hosted and self-hosted
//! endpoints can share the same client.
//!
//! This module adapts remote responses to engine semantics: codepoint offsets
//! become byte offsets, missing scores become 1.0 before thresholding, and raw
//! model labels map to the same `EntityType`s as the local backend.
//!
//! Endpoint failures return `Err`, so the engine refuses the request instead of
//! falling back to regex-only scanning. Load-time strictness is controlled by
//! `[engine.ml] required`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use presidio_core::{EntityType, RecognizerResult};
use serde::Deserialize;

use crate::config::{ENTITY_PRIVATE_DATE, MlConfig};
use crate::error::EngineError;
use crate::ml_api::MlRecognizer;

/// Total attempts per request (1 initial + 2 retries). 503 (HF cold load) waits
/// longer between attempts than transport errors do.
const ATTEMPTS: u32 = 3;
const PROBE_TEXT: &str = "Probe contact: Sarah Probe <sarah.probe@example.com>";
const PROBE_EMAIL: &str = "sarah.probe@example.com";

/// A failed HTTP exchange. `msg` is log-safe and never includes a response body;
/// `body_snippet` is only for the synthetic probe, where echoed input cannot
/// contain user text.
#[derive(Debug)]
struct HttpError {
    status: Option<u16>,
    msg: String,
    /// Truncated response body, intentionally ignored by analyze/detect paths.
    body_snippet: Option<String>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl HttpError {
    /// Worth retrying? Transport hiccups and cold-load/overload statuses are;
    /// a 401/404/422 will not improve by retrying.
    fn retryable(&self) -> bool {
        matches!(
            self.status,
            None | Some(502) | Some(503) | Some(504) | Some(429)
        )
    }

    /// Statuses commonly used when a single-input endpoint rejects `inputs: [...]`.
    fn rejects_request_shape(&self) -> bool {
        matches!(
            self.status,
            Some(400) | Some(404) | Some(405) | Some(413) | Some(415) | Some(422)
        )
    }

    /// Wrap as the fail-closed engine error surfaced in logs/status.
    fn fail_closed(&self) -> EngineError {
        EngineError::Ml(format!(
            "http ML endpoint unavailable (failing CLOSED — request refused, not \
             passed through unmasked): {}",
            self.msg
        ))
    }
}

/// One span as it appears on the wire (HF token-classification schema). Unknown
/// fields (`word`, `placeholder`, …) are ignored.
#[derive(Debug, Deserialize)]
struct WireEntity {
    /// Aggregated label (`aggregation_strategy != "none"`), e.g. `private_person`.
    #[serde(default)]
    entity_group: Option<String>,
    /// Raw per-token tag (`aggregation_strategy = "none"`), e.g. `B-private_person`.
    /// Fallback only — used when a server ignores the aggregation parameter.
    #[serde(default)]
    entity: Option<String>,
    /// Confidence; servers without one (the official `opf` runtime) send null.
    #[serde(default)]
    score: Option<f32>,
    /// Codepoint offsets into the input text (Python-string semantics).
    start: usize,
    end: usize,
}

/// The two response shapes seen in the wild: one entity array per input
/// (batch semantics, also used by some servers for a single input) or a flat
/// array for a single input. `[]` parses as `Nested(vec![])` — fine for both
/// call sites (no entities either way).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WireResponse {
    Nested(Vec<Vec<WireEntity>>),
    Flat(Vec<WireEntity>),
}

/// How a span's label arrived: an aggregated `entity_group` (`Bare`) or a raw
/// BIOES tag. Only raw tags participate in client-side stitching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    /// Aggregated by the server — NEVER merged client-side (two adjacent
    /// distinct entities must stay distinct).
    Bare,
    /// Begin — starts a new span.
    B,
    /// Inside — continues the open span (orphan ⇒ starts one).
    I,
    /// End — continues then CLOSES the open span.
    E,
    /// Single — a complete one-token span (starts AND closes).
    S,
}

/// `analyze`-internal span after label resolution, still in codepoint offsets.
struct ResolvedSpan {
    label: String,
    tag: Tag,
    score: f32,
    start_cp: usize,
    end_cp: usize,
}

/// Map a raw model label to the engine's `EntityType`, matching the local
/// backend. Unknown labels become custom entities instead of being dropped.
fn label_to_entity(label: &str) -> EntityType {
    match label {
        "private_person" => EntityType::Person,
        "private_address" => EntityType::Location,
        "private_email" => EntityType::EmailAddress,
        "private_phone" => EntityType::PhoneNumber,
        "private_url" => EntityType::Url,
        "account_number" => EntityType::UsBankAccount,
        "secret" => EntityType::ApiKey,
        ENTITY_PRIVATE_DATE_LABEL => EntityType::Custom(ENTITY_PRIVATE_DATE.into()),
        other => EntityType::Custom(other.to_ascii_uppercase()),
    }
}

/// The model's native label for any private date (same constant as `ml.rs`).
const ENTITY_PRIVATE_DATE_LABEL: &str = "private_date";

pub struct HttpRecognizer {
    agent: ureq::Agent,
    endpoint: String,
    /// Pre-rendered `Bearer <token>` from `auth_token_env`; the token stays out
    /// of config.
    auth_header: Option<String>,
    /// Score floor (spec default 0.5 when unset, matching the local backend).
    min_score: f32,
    /// Set after a rejected/non-batch response so future batches go per-text.
    batch_unsupported: AtomicBool,
}

impl std::fmt::Debug for HttpRecognizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRecognizer")
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth_header.is_some())
            .field("min_score", &self.min_score)
            .finish()
    }
}

impl HttpRecognizer {
    /// Validate config and resolve the auth token at load time.
    pub fn from_config(cfg: &MlConfig) -> Result<Self, EngineError> {
        let endpoint = cfg.endpoint.clone().ok_or_else(|| {
            EngineError::Ml(
                "[engine.ml] backend = \"http\" requires `endpoint` (the URL of an \
                 HF-token-classification-compatible server)"
                    .into(),
            )
        })?;
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(EngineError::Ml(format!(
                "[engine.ml] endpoint must be http:// or https://, got '{endpoint}'"
            )));
        }
        let auth_header = match &cfg.auth_token_env {
            Some(var) => {
                let token = std::env::var(var).unwrap_or_default();
                if token.is_empty() {
                    return Err(EngineError::Ml(format!(
                        "[engine.ml] auth_token_env names '{var}' but that environment \
                         variable is unset or empty"
                    )));
                }
                Some(format!("Bearer {token}"))
            }
            None => None,
        };
        let timeout = Duration::from_secs(cfg.http_timeout_secs.max(1));
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .user_agent(concat!("zlauder/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Self {
            agent,
            endpoint,
            auth_header,
            min_score: cfg.min_score.unwrap_or(0.5),
            batch_unsupported: AtomicBool::new(false),
        })
    }

    /// POST `body`, retrying what can plausibly recover: transport errors back
    /// off briefly; 502/503/504/429 (HF cold load / overload) wait longer.
    /// Other HTTP statuses fail immediately (a 401/404/422 will not improve).
    fn post(&self, body: &serde_json::Value) -> Result<serde_json::Value, HttpError> {
        let payload = body.to_string();
        let mut last = HttpError {
            status: None,
            msg: "no attempt made".into(),
            body_snippet: None,
        };
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                let wait = if last.status.is_some() {
                    Duration::from_secs(2 * attempt as u64)
                } else {
                    Duration::from_millis(250 * (1 << attempt))
                };
                std::thread::sleep(wait);
            }
            let mut req = self
                .agent
                .post(&self.endpoint)
                .set("Content-Type", "application/json");
            if let Some(auth) = &self.auth_header {
                req = req.set("Authorization", auth);
            }
            match req.send_string(&payload) {
                Ok(resp) => {
                    // io error reading the body carries no response content — safe.
                    let text = resp.into_string().map_err(|e| HttpError {
                        status: None,
                        msg: format!("reading response body from {}: {e}", self.endpoint),
                        body_snippet: None,
                    })?;
                    // serde parse errors are positional only (offset/line), not
                    // the input text — safe to embed.
                    return serde_json::from_str(&text).map_err(|e| HttpError {
                        status: None,
                        msg: format!("response from {} is not valid JSON: {e}", self.endpoint),
                        body_snippet: None,
                    });
                }
                Err(ureq::Error::Status(code, resp)) => {
                    // The body MAY echo the rejected input (PII). Keep it out of
                    // `msg` (which flows to logs/status); stash the truncated copy
                    // in `body_snippet`, which only `probe()` is allowed to read.
                    let body = resp.into_string().unwrap_or_default();
                    let snippet: String = body.chars().take(200).collect();
                    last = HttpError {
                        status: Some(code),
                        msg: format!("HTTP {code} from {}", self.endpoint),
                        body_snippet: (!snippet.is_empty()).then_some(snippet),
                    };
                    if !last.retryable() {
                        return Err(last);
                    }
                }
                Err(e) => {
                    last = HttpError {
                        status: None,
                        msg: format!("request to {} failed: {e}", self.endpoint),
                        body_snippet: None,
                    };
                }
            }
        }
        last.msg = format!("{} (after {ATTEMPTS} attempts)", last.msg);
        Err(last)
    }

    /// One-shot connectivity probe used at load and by `--download-model`.
    pub fn probe(&self) -> Result<(), EngineError> {
        let body = serde_json::json!({
            "inputs": PROBE_TEXT,
            "parameters": {"aggregation_strategy": "simple"},
        });
        // Probe may surface the response body because it sends fixed synthetic
        // text, never user input.
        let v = self.post(&body).map_err(|e| {
            let detail = match &e.body_snippet {
                Some(s) => format!("{}: {s}", e.msg),
                None => e.msg.clone(),
            };
            EngineError::Ml(detail)
        })?;
        let entities = match serde_json::from_value::<WireResponse>(v.clone()) {
            Ok(wire) => self.single_input_entities(wire).map_err(|msg| {
                EngineError::Ml(format!("endpoint {} answered, but {msg}", self.endpoint))
            })?,
            Err(_) => {
                return Err(EngineError::Ml(format!(
                    "endpoint {} answered, but not with a token-classification array \
                 (got: {})",
                    self.endpoint,
                    truncate_for_log(&v.to_string()),
                )));
            }
        };
        let spans = self.convert(PROBE_TEXT, entities);
        let saw_email = spans.iter().any(|r| {
            r.entity_type == EntityType::EmailAddress
                && PROBE_TEXT.get(r.start..r.end) == Some(PROBE_EMAIL)
        });
        if saw_email {
            Ok(())
        } else {
            Err(EngineError::Ml(format!(
                "endpoint {} answered, but the probe did not return the expected \
                 EMAIL_ADDRESS span",
                self.endpoint
            )))
        }
    }

    fn single_input_entities(&self, response: WireResponse) -> Result<Vec<WireEntity>, String> {
        match response {
            WireResponse::Nested(mut nested) => {
                if nested.is_empty() {
                    Ok(Vec::new())
                } else if nested.len() == 1 {
                    Ok(nested.swap_remove(0))
                } else {
                    Err(format!(
                        "ambiguous nested response with {} outer arrays for a single input",
                        nested.len()
                    ))
                }
            }
            WireResponse::Flat(flat) => Ok(flat),
        }
    }

    /// Wire spans → engine results: resolve labels (BIOES stitching for raw
    /// tags), default missing scores to 1.0, apply the score floor, convert
    /// codepoint offsets to byte offsets.
    fn convert(&self, text: &str, entities: Vec<WireEntity>) -> Vec<RecognizerResult> {
        // Codepoint index → byte offset table (one pass; index == char count at
        // the end gives `text.len()` for an end-of-string span).
        let byte_of: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
        let n_chars = byte_of.len();
        let to_byte = |cp: usize| -> usize {
            if cp >= n_chars {
                text.len()
            } else {
                byte_of[cp]
            }
        };

        // Resolve labels. Prefer the aggregated `entity_group`; fall back to the
        // raw BIOES `entity` tag (server ignored the aggregation parameter).
        let mut resolved: Vec<ResolvedSpan> = Vec::with_capacity(entities.len());
        for w in entities {
            let (label, tag) = match (&w.entity_group, &w.entity) {
                (Some(g), _) if !g.is_empty() => (g.clone(), Tag::Bare),
                (_, Some(raw)) if !raw.is_empty() => {
                    let (tag, stripped) = match raw.split_once('-') {
                        Some(("B", rest)) => (Tag::B, rest),
                        Some(("I", rest)) => (Tag::I, rest),
                        Some(("E", rest)) => (Tag::E, rest),
                        Some(("S", rest)) => (Tag::S, rest),
                        // Unknown scheme prefix or unprefixed label: treat as a
                        // complete span (never merged into a neighbor).
                        _ => (Tag::Bare, raw.as_str()),
                    };
                    if stripped == "O" || raw == "O" {
                        continue;
                    }
                    (stripped.to_string(), tag)
                }
                _ => continue,
            };
            if w.end <= w.start {
                continue;
            }
            resolved.push(ResolvedSpan {
                label,
                tag,
                score: w.score.unwrap_or(1.0),
                start_cp: w.start,
                end_cp: w.end,
            });
        }

        // Stitch raw BIOES token spans back into entity spans, TAG-driven (the
        // per-token shape splits one entity across many wordpieces):
        //   B / S  → always START a new span (S also closes it);
        //   I / E  → CONTINUE the open same-label span (E closes it); an orphan
        //            I/E (no open span, label mismatch, or non-contiguous)
        //            starts a new span rather than being dropped;
        //   Bare   → its own span, never merged (the server already aggregated;
        //            two adjacent distinct entities must stay distinct).
        // Contiguity (≤1 codepoint gap) is kept as a sanity bound so a stray
        // far-away I-tag can't fuse across unrelated text.
        resolved.sort_by_key(|s| (s.start_cp, s.end_cp));
        let mut merged: Vec<ResolvedSpan> = Vec::with_capacity(resolved.len());
        let mut open = false; // is merged.last() an open (B/I, not yet E/S-closed) span?
        for span in resolved {
            let continues = matches!(span.tag, Tag::I | Tag::E)
                && open
                && merged.last().is_some_and(|prev| {
                    prev.label == span.label && span.start_cp <= prev.end_cp.saturating_add(1)
                });
            if continues {
                let prev = merged.last_mut().expect("checked above");
                prev.end_cp = prev.end_cp.max(span.end_cp);
                prev.score = prev.score.max(span.score);
                open = span.tag == Tag::I; // E closes the span
            } else {
                open = matches!(span.tag, Tag::B | Tag::I); // S/E/Bare are closed
                merged.push(span);
            }
        }

        merged
            .into_iter()
            .filter(|s| s.score >= self.min_score)
            .filter_map(|s| {
                let start = to_byte(s.start_cp);
                let end = to_byte(s.end_cp);
                if end <= start || start >= text.len() {
                    return None;
                }
                Some(RecognizerResult::new(
                    label_to_entity(&s.label),
                    start,
                    end.min(text.len()),
                    s.score,
                ))
            })
            .collect()
    }

    /// Detection for one text. `Err` = the endpoint could not be consulted —
    /// fail closed; `Ok(vec![])` = a genuine "no PII".
    fn detect(&self, text: &str) -> Result<Vec<RecognizerResult>, EngineError> {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let body = serde_json::json!({
            "inputs": text,
            "parameters": {"aggregation_strategy": "simple"},
        });
        let v = self.post(&body).map_err(|e| e.fail_closed())?;
        let entities = match serde_json::from_value::<WireResponse>(v) {
            Ok(wire) => self.single_input_entities(wire).map_err(|msg| {
                EngineError::Ml(format!(
                    "http ML endpoint unavailable (failing CLOSED — request \
                     refused, not passed through unmasked): {msg} from {}",
                    self.endpoint
                ))
            })?,
            Err(e) => {
                return Err(EngineError::Ml(format!(
                    "unexpected response shape from {}: {e}",
                    self.endpoint
                )));
            }
        };
        Ok(self.convert(text, entities))
    }

    /// Batched detection. Single-input endpoints are remembered and handled by
    /// the per-text path; other endpoint failures propagate fail-closed.
    fn detect_batch(&self, texts: &[&str]) -> Result<Vec<Vec<RecognizerResult>>, EngineError> {
        if self.batch_unsupported.load(Ordering::Relaxed) {
            return texts.iter().map(|t| self.detect(t)).collect();
        }
        let body = serde_json::json!({
            "inputs": texts,
            "parameters": {"aggregation_strategy": "simple"},
        });
        let v = match self.post(&body) {
            Ok(v) => v,
            Err(e) if e.rejects_request_shape() => {
                // Single-input endpoint: remember and go per-text from now on.
                self.batch_unsupported.store(true, Ordering::Relaxed);
                return texts.iter().map(|t| self.detect(t)).collect();
            }
            Err(e) => return Err(e.fail_closed()),
        };
        match serde_json::from_value::<WireResponse>(v) {
            Ok(WireResponse::Nested(nested)) if nested.len() == texts.len() => Ok(nested
                .into_iter()
                .zip(texts)
                .map(|(ents, text)| self.convert(text, ents))
                .collect()),
            // Parsed, but not one-array-per-input: this server doesn't batch.
            _ => {
                self.batch_unsupported.store(true, Ordering::Relaxed);
                texts.iter().map(|t| self.detect(t)).collect()
            }
        }
    }
}

impl MlRecognizer for HttpRecognizer {
    /// Endpoint failures are real errors; empty `Ok` means "no PII found".
    fn analyze(&self, text: &str) -> Result<Vec<RecognizerResult>, EngineError> {
        self.detect(text)
    }

    fn analyze_batch(&self, texts: &[&str]) -> Result<Vec<Vec<RecognizerResult>>, EngineError> {
        self.detect_batch(texts)
    }
}

fn truncate_for_log(s: &str) -> String {
    s.chars().take(200).collect()
}

/// Build the HTTP recognizer and probe the endpoint at load time.
pub fn build_recognizer(cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    let rec = HttpRecognizer::from_config(cfg)?;
    rec.probe()?;
    Ok(Arc::new(rec))
}

/// `--download-model` for the http backend: nothing to download — validate the
/// config and probe the endpoint instead.
pub fn probe(cfg: &MlConfig) -> Result<(), EngineError> {
    HttpRecognizer::from_config(cfg)?.probe()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Minimal one-shot HTTP responder: accepts `n` connections sequentially,
    /// answers each with the corresponding canned body (200 unless the body
    /// starts with "STATUS:<code>:"), then exits. Good enough for ureq's
    /// one-request-per-connection usage under `Connection: close`.
    fn serve(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                // Read the request until the end of headers, then the body per
                // Content-Length (ureq always sends one for send_string).
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                let (mut header_end, mut content_len) = (0usize, 0usize);
                loop {
                    let n = match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if header_end == 0 {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos + 4;
                            let headers = String::from_utf8_lossy(&buf[..pos]);
                            for line in headers.lines() {
                                if let Some(v) = line
                                    .to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(str::trim)
                                    .and_then(|v| v.parse::<usize>().ok())
                                {
                                    content_len = v;
                                }
                            }
                        }
                    }
                    if header_end > 0 && buf.len() >= header_end + content_len {
                        break;
                    }
                }
                let (status, payload) = match body.strip_prefix("STATUS:") {
                    Some(rest) => {
                        let (code, p) = rest.split_once(':').expect("STATUS:<code>:<body>");
                        (code.parse::<u16>().expect("status code"), p.to_string())
                    }
                    None => (200, body),
                };
                let reason = if status == 200 { "OK" } else { "ERR" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len(),
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}/detect")
    }

    fn cfg_for(endpoint: &str) -> MlConfig {
        MlConfig {
            enabled: true,
            backend: crate::config::MlBackend::Http,
            endpoint: Some(endpoint.to_string()),
            ..Default::default()
        }
    }

    fn rec_for(endpoint: &str) -> HttpRecognizer {
        HttpRecognizer::from_config(&cfg_for(endpoint)).expect("config valid")
    }

    /// Offsets on the wire are CODEPOINT indices (Python-string semantics);
    /// the engine consumes BYTES. A 4-byte emoji before the span forces the
    /// conversion to actually shift.
    #[test]
    fn codepoint_offsets_convert_to_bytes() {
        let text = "📧 mail sarah@example.com now";
        let cp_start = text.chars().take_while(|c| *c != 's').count();
        let cp_end = cp_start + "sarah@example.com".chars().count();
        let url = serve(vec![format!(
            r#"[{{"entity_group":"private_email","score":0.99,"word":"sarah@example.com","start":{cp_start},"end":{cp_end}}}]"#
        )]);
        let rec = rec_for(&url);
        let out = rec.detect(text).expect("detect");
        assert_eq!(out.len(), 1, "one span expected: {out:?}");
        let (start, end) = (out[0].start, out[0].end);
        assert_eq!(&text[start..end], "sarah@example.com");
        assert_eq!(out[0].entity_type, EntityType::EmailAddress);
    }

    /// `score: null` (servers without confidence, e.g. the official opf
    /// runtime) means "trust the server's own thresholding" — treated as 1.0,
    /// which always clears the floor. Real scores below `min_score` drop.
    #[test]
    fn null_score_passes_low_score_drops() {
        let url = serve(vec![
            r#"[{"entity_group":"private_person","score":null,"start":0,"end":4},
                {"entity_group":"private_person","score":0.10,"start":5,"end":9}]"#
                .to_string(),
        ]);
        let rec = rec_for(&url); // min_score defaults to 0.5
        let out = rec.detect("John Paul").expect("detect");
        assert_eq!(out.len(), 1, "null-score kept, 0.10 dropped: {out:?}");
        assert_eq!((out[0].start, out[0].end), (0, 4));
        assert_eq!(out[0].score, 1.0);
    }

    /// Label mapping mirrors the local backend's `privacy_filter_mapping`:
    /// `private_date` routes to `Custom("PRIVATE_DATE")` (never `DateTime` /
    /// `DATE_OF_BIRTH` — see `ml.rs`), unknown labels surface as
    /// `Custom(UPPERCASE)` instead of being silently dropped.
    #[test]
    fn label_mapping_matches_local_backend() {
        assert_eq!(
            label_to_entity("private_date"),
            EntityType::Custom(ENTITY_PRIVATE_DATE.into())
        );
        assert_eq!(label_to_entity("private_person"), EntityType::Person);
        assert_eq!(label_to_entity("private_address"), EntityType::Location);
        assert_eq!(label_to_entity("private_email"), EntityType::EmailAddress);
        assert_eq!(label_to_entity("private_phone"), EntityType::PhoneNumber);
        assert_eq!(label_to_entity("private_url"), EntityType::Url);
        assert_eq!(label_to_entity("account_number"), EntityType::UsBankAccount);
        assert_eq!(label_to_entity("secret"), EntityType::ApiKey);
        assert_eq!(
            label_to_entity("medical_record"),
            EntityType::Custom("MEDICAL_RECORD".into())
        );
    }

    /// A server that ignores `aggregation_strategy` answers with raw per-token
    /// BIOES tags (`entity`, `entity_group: null`). Those must stitch back into
    /// one span per entity — and `O` tags must vanish.
    #[test]
    fn bioes_fallback_stitches_tokens() {
        let text = "My name is Sarah Jessica Parker ok";
        let url = serve(vec![
            r#"[{"entity":"B-private_person","entity_group":null,"score":0.99,"start":11,"end":16},
                {"entity":"I-private_person","entity_group":null,"score":0.98,"start":17,"end":24},
                {"entity":"E-private_person","entity_group":null,"score":0.97,"start":25,"end":31},
                {"entity":"O","entity_group":null,"score":0.99,"start":32,"end":34}]"#
                .to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect(text).expect("detect");
        assert_eq!(out.len(), 1, "B/I/E tokens must stitch: {out:?}");
        assert_eq!(&text[out[0].start..out[0].end], "Sarah Jessica Parker");
    }

    /// BIOES boundaries are authoritative: an `E-` (closed) followed by an
    /// adjacent `B-`/`S-` of the SAME label is TWO entities, not one — the
    /// stitcher must not proximity-merge across a B/S boundary.
    #[test]
    fn bioes_boundaries_keep_adjacent_entities_distinct() {
        let text = "Anna Bert";
        let url = serve(vec![
            r#"[{"entity":"S-private_person","entity_group":null,"score":0.9,"start":0,"end":4},
                {"entity":"S-private_person","entity_group":null,"score":0.9,"start":5,"end":9}]"#
                .to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect(text).expect("detect");
        assert_eq!(out.len(), 2, "S/S adjacent spans stay distinct: {out:?}");
        assert_eq!(&text[out[0].start..out[0].end], "Anna");
        assert_eq!(&text[out[1].start..out[1].end], "Bert");
    }

    /// An orphan `I-` (no open span — e.g. after an `E-` closed it) starts a
    /// new span instead of being dropped or fused backwards.
    #[test]
    fn bioes_orphan_inside_starts_new_span() {
        let text = "Anna Bert";
        let url = serve(vec![
            r#"[{"entity":"E-private_person","entity_group":null,"score":0.9,"start":0,"end":4},
                {"entity":"I-private_person","entity_group":null,"score":0.9,"start":5,"end":9}]"#
                .to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect(text).expect("detect");
        assert_eq!(
            out.len(),
            2,
            "orphan I- must not fuse into a closed span: {out:?}"
        );
    }

    /// Aggregated (`entity_group`) spans are the server's grouping — two
    /// adjacent same-label entities must NOT be re-merged client-side.
    #[test]
    fn aggregated_spans_are_not_merged() {
        let url = serve(vec![
            r#"[{"entity_group":"private_person","score":0.9,"start":0,"end":4},
                {"entity_group":"private_person","score":0.9,"start":5,"end":9}]"#
                .to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect("Anna Bert").expect("detect");
        assert_eq!(
            out.len(),
            2,
            "server-aggregated spans stay distinct: {out:?}"
        );
    }

    /// Batched detection: one POST, nested response, index-aligned results.
    #[test]
    fn batch_nested_response_maps_per_text() {
        let url = serve(vec![
            r#"[[{"entity_group":"private_person","score":0.9,"start":0,"end":4}],[]]"#.to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect_batch(&["Anna x", "no pii"]).expect("batch");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), 1);
        assert!(out[1].is_empty());
    }

    /// A server that answers a batch with a FLAT array doesn't batch; the
    /// recognizer must fall back to per-text requests (and remember).
    #[test]
    fn batch_flat_response_falls_back_per_text() {
        let url = serve(vec![
            // 1: the batched attempt comes back flat (wrong shape)
            r#"[{"entity_group":"private_person","score":0.9,"start":0,"end":4}]"#.to_string(),
            // 2+3: the per-text fallback
            r#"[{"entity_group":"private_person","score":0.9,"start":0,"end":4}]"#.to_string(),
            r#"[]"#.to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect_batch(&["Anna x", "no pii"]).expect("batch");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), 1);
        assert!(out[1].is_empty());
        assert!(rec.batch_unsupported.load(Ordering::Relaxed));
    }

    /// A server that REJECTS `inputs: [...]` outright (the single-input-only
    /// shape, e.g. a 422) must also flip the fallback — not surface an error.
    #[test]
    fn batch_4xx_rejection_falls_back_per_text() {
        let url = serve(vec![
            r#"STATUS:422:{"error":"inputs must be a string"}"#.to_string(),
            // the per-text fallback
            r#"[{"entity_group":"private_person","score":0.9,"start":0,"end":4}]"#.to_string(),
            r#"[]"#.to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect_batch(&["Anna x", "no pii"]).expect("batch");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), 1);
        assert!(rec.batch_unsupported.load(Ordering::Relaxed));
    }

    /// 503 (HF cold load) is retried; the next attempt's success is returned.
    #[test]
    fn retries_after_503() {
        let url = serve(vec![
            r#"STATUS:503:{"error":"Model openai/privacy-filter is currently loading"}"#
                .to_string(),
            r#"[{"entity_group":"private_email","score":0.9,"start":0,"end":7}]"#.to_string(),
        ]);
        let rec = rec_for(&url);
        let out = rec.detect("a@b.com").expect("503 then success");
        assert_eq!(out.len(), 1);
    }

    /// FAIL-CLOSED: an unreachable endpoint must surface as a real `Err` from
    /// `analyze` (the detection layer refuses the request) — NEVER as an empty
    /// "no PII" success.
    #[test]
    fn unreachable_endpoint_fails_closed() {
        // Port 9 (discard) on localhost: nothing listens; connect refuses fast.
        let rec = rec_for("http://127.0.0.1:9/detect");
        let err = rec
            .analyze("private text with sarah@example.com")
            .expect_err("must be Err, never an empty Ok");
        assert!(err.to_string().contains("failing CLOSED"), "got: {err}");
    }

    /// Config validation fails fast at construction (visible at load), not at
    /// the first masked request.
    #[test]
    fn config_validation_fails_fast() {
        // endpoint required
        let mut cfg = cfg_for("http://127.0.0.1:9/detect");
        cfg.endpoint = None;
        assert!(HttpRecognizer::from_config(&cfg).is_err());
        // http(s) only
        let cfg = cfg_for("ftp://example.com/detect");
        assert!(HttpRecognizer::from_config(&cfg).is_err());
        // a named auth env var must exist and be non-empty
        let mut cfg = cfg_for("http://127.0.0.1:9/detect");
        cfg.auth_token_env = Some("ZLAUDER_TEST_UNSET_TOKEN_VAR".into());
        assert!(HttpRecognizer::from_config(&cfg).is_err());
    }

    /// A status-error response body must NOT leak into the error surface: many
    /// endpoints echo the rejected input, which would copy PII into logs/status.
    /// 500 is non-retryable, so one canned response is consumed. The error must
    /// name the status (`HTTP 500`) but never the echoed marker.
    #[test]
    fn status_error_does_not_leak_response_body() {
        let marker = "SSN 123-45-6789 echoed back";
        let url = serve(vec![format!("STATUS:500:{marker}")]);
        let rec = rec_for(&url);
        let err = rec
            .analyze("my ssn is 123-45-6789")
            .expect_err("500 must fail closed");
        let s = err.to_string();
        assert!(s.contains("HTTP 500"), "want status code in: {s}");
        assert!(!s.contains(marker), "response body leaked PII: {s}");
    }

    /// Probe errors may surface the body because probe sends fixed synthetic text.
    #[test]
    fn probe_error_may_include_body() {
        let marker = "currently loading details here";
        let url = serve(vec![format!("STATUS:500:{marker}")]);
        let rec = rec_for(&url);
        let err = rec.probe().expect_err("500 must fail the probe");
        let s = err.to_string();
        assert!(s.contains("HTTP 500"), "want status code in: {s}");
        assert!(
            s.contains(marker),
            "probe should surface its (safe) body: {s}"
        );
    }

    /// A single-input response with >1 outer array is ambiguous: the old
    /// `swap_remove(0)` would silently take the (empty) first array and report
    /// "no PII" — FAIL OPEN. It must instead fail CLOSED.
    #[test]
    fn nested_multi_array_single_input_fails_closed() {
        let url = serve(vec![
            r#"[[],[{"entity_group":"private_person","score":0.9,"start":0,"end":4}]]"#.to_string(),
        ]);
        let rec = rec_for(&url);
        let err = rec
            .analyze("Anna is here")
            .expect_err("ambiguous nested shape must fail closed, never empty Ok");
        assert!(err.to_string().contains("failing CLOSED"), "got: {err}");
    }

    /// `probe()` requires a real expected detection, not just array-shaped JSON.
    #[test]
    fn probe_requires_expected_email_span() {
        let bad = serve(vec![r#"[1,2,3]"#.to_string()]);
        let rec = rec_for(&bad);
        assert!(
            rec.probe().is_err(),
            "[1,2,3] is an array but not a WireResponse — probe must reject"
        );

        let empty = serve(vec![r#"[[]]"#.to_string()]);
        let rec = rec_for(&empty);
        assert!(
            rec.probe().is_err(),
            "empty token-classification shape proves JSON compatibility, not detection"
        );

        let ok = serve(vec![
            r#"[{"entity_group":"private_email","score":0.99,"start":29,"end":52}]"#.to_string(),
        ]);
        let rec = rec_for(&ok);
        rec.probe()
            .expect("synthetic email span proves token-classification detection");
    }

    /// Live conformance against the real HF Inference Providers router. Ignored
    /// by default (network + a token with the `inference.serverless` permission);
    /// run with:
    ///   HF_TOKEN=hf_… cargo test -p zlauder-engine hf_router_live -- --ignored
    #[test]
    #[ignore = "live network test against router.huggingface.co (needs HF_TOKEN)"]
    fn hf_router_live_conformance() {
        if std::env::var("HF_TOKEN").unwrap_or_default().is_empty() {
            eprintln!("HF_TOKEN unset; skipping");
            return;
        }
        let mut cfg =
            cfg_for("https://router.huggingface.co/hf-inference/models/openai/privacy-filter");
        cfg.auth_token_env = Some("HF_TOKEN".into());
        let rec = HttpRecognizer::from_config(&cfg).expect("config");
        rec.probe()
            .expect("probe (rides out a 503 cold load via retries)");
        let text = "My name is Sarah Jessica Parker, email sjp@example.com";
        let out = rec.detect(text).expect("detect");
        assert!(
            out.iter().any(|r| r.entity_type == EntityType::Person),
            "expected a PERSON span: {out:?}"
        );
        assert!(
            out.iter()
                .any(|r| r.entity_type == EntityType::EmailAddress),
            "expected an EMAIL_ADDRESS span: {out:?}"
        );
        for r in &out {
            assert!(text.is_char_boundary(r.start) && text.is_char_boundary(r.end));
        }
    }
}
