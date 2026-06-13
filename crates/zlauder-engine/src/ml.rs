//! ML recognizer construction. `[engine.ml] backend` selects local Candle
//! inference (`ml`) or a remote token-classification endpoint (`ml-http`).
//! Missing backend features fail explicitly instead of falling through.
//!
//! Both backends build the SAME `presidio_classifier::TokenClassifierRecognizer`
//! through one helper ([`build_token_recognizer`]); they differ ONLY in the
//! `InferenceBackend` passed in. The spec, chunker, label-map override, and
//! score floor are set once, in that helper, so local and http can never drift
//! into different detections for the same model output (the #1 silent-corruption
//! trap of a hand-rolled second path).
//!
//! Fail-closed by construction: the engine slot stores the recognizer as a
//! [`MlRecognizer`], whose impl drives the recognizer's inherent fail-CLOSED
//! `try_analyze` (a backend error becomes `Err`, which the caller turns into a
//! request refusal — never an empty "no PII" that would leak). `try_analyze`
//! covers the `Result` half only; a backend can still PANIC (candle OOM /
//! tensor-shape), so the impl keeps `catch_unwind` around the call. Backend
//! errors are rendered via [`BackendError::redacted`] before they reach any log
//! or status line — the raw `Display` can echo the analyzed text (PII).
//!
//! Entry points are synchronous; the proxy calls them from `spawn_blocking`.

use std::sync::Arc;

use crate::config::{MlBackend, MlConfig};
use crate::error::EngineError;
use crate::ml_api::MlRecognizer;

#[cfg(any(feature = "ml", feature = "ml-http"))]
use presidio_classifier::{
    Chunker, InferenceBackend, LabelMap, OPENAI_PRIVACY_FILTER, TokenClassifierRecognizer,
};
#[cfg(any(feature = "ml", feature = "ml-http"))]
use presidio_core::{EntityType, RecognizerResult};

#[cfg(any(feature = "ml", feature = "ml-http"))]
use crate::config::ENTITY_PRIVATE_DATE;
#[cfg(any(feature = "ml", feature = "ml-http"))]
use crate::ml_api::catch_recognizer_panic;

#[cfg(feature = "ml")]
use presidio_classifier::backends::{
    CandleBackend, CandleConfig, CpuPrecision, DeviceHint, PrecisionHint, Quant,
};
#[cfg(feature = "ml")]
use crate::config::{ComputePrecision, Quantization};

#[cfg(feature = "ml-http")]
use presidio_classifier::backends::{HttpAuth, HttpBackend, HttpConfig, HttpSchema, RetryPolicy};

/// The `openai/privacy-filter` model's native label for any private date.
#[cfg(any(feature = "ml", feature = "ml-http"))]
const ML_LABEL_PRIVATE_DATE: &str = "private_date";

/// Build the label map for the privacy-filter recognizer, remapping the model's
/// generic `private_date` label to `Custom("PRIVATE_DATE")` rather than letting
/// it fall through to the spec default (`DateTime`).
///
/// The model emits `private_date` for ALL private dates, not just dates of
/// birth, and the `entity_kind` string surfaces verbatim in the manifest, the
/// monitor ledger, and the UI. Relabeling it `DATE_OF_BIRTH` would assert a
/// birth where the model only saw a date — an audit-trail lie. `DATE_OF_BIRTH`
/// is reserved for the hard-context regex recognizer; the ML signal routes to
/// the neutral `PRIVATE_DATE` (an Identity-category entity). Every other label
/// keeps its spec default.
///
/// This is the SINGLE source of truth for label translation, shared by both
/// backends via [`build_token_recognizer`]: the http backend returns the same
/// native model labels (`private_date`, `private_email`, …) and routes them
/// through this exact map, so a date can never resolve to a different entity
/// type local-vs-http.
#[cfg(any(feature = "ml", feature = "ml-http"))]
fn privacy_filter_mapping() -> LabelMap {
    LabelMap::from_spec(&OPENAI_PRIVACY_FILTER).with_overrides([(
        ML_LABEL_PRIVATE_DATE.into(),
        EntityType::Custom(ENTITY_PRIVATE_DATE.into()),
    )])
}

/// Construct the privacy-filter recognizer over `backend`. Spec, chunker,
/// label-map override, and score floor are set HERE and only here, so every
/// backend produces a span-comparable recognizer (see the module-level note on
/// drift). Returns the concrete type so callers can reach the recognizer's
/// inherent `try_analyze` / `healthcheck`.
#[cfg(any(feature = "ml", feature = "ml-http"))]
fn build_token_recognizer(
    backend: Arc<dyn InferenceBackend>,
    cfg: &MlConfig,
) -> Arc<TokenClassifierRecognizer> {
    let mut builder = TokenClassifierRecognizer::builder()
        .with_spec(&OPENAI_PRIVACY_FILTER)
        .with_backend(backend)
        // Sentence-like chunker so oversize fields are split, not rejected.
        .with_chunker(Chunker::for_openai_privacy_filter())
        // Remap the generic `private_date` label to a neutral `PRIVATE_DATE`
        // (NOT `DATE_OF_BIRTH`); see `privacy_filter_mapping`.
        .with_mapping(privacy_filter_mapping());
    if let Some(s) = cfg.min_score {
        builder = builder.with_min_score(s);
    }
    Arc::new(builder.build())
}

/// Drive the recognizer's inherent fail-CLOSED seam onto the engine's fallible
/// ML slot. Both backends are the same concrete type, so this one impl serves
/// local AND http.
#[cfg(any(feature = "ml", feature = "ml-http"))]
impl MlRecognizer for TokenClassifierRecognizer {
    fn analyze(&self, text: &str) -> Result<Vec<RecognizerResult>, EngineError> {
        // `try_analyze` is fail-CLOSED (Err on backend failure); the engine maps
        // that to a refusal. `catch_unwind` covers the half `try_analyze` does
        // NOT — a backend panic (candle OOM/tensor-shape). `redacted()` keeps a
        // leaked `HttpStatus.body` / decode detail (which can echo the analyzed
        // text = PII) out of the error that flows to logs/status.
        catch_recognizer_panic(|| self.try_analyze(text, None))?
            .map_err(|e| EngineError::Ml(e.redacted().to_string()))
    }

    fn analyze_batch(&self, texts: &[&str]) -> Result<Vec<Vec<RecognizerResult>>, EngineError> {
        catch_recognizer_panic(|| self.try_analyze_batch(texts, None))?
            .map_err(|e| EngineError::Ml(e.redacted().to_string()))
    }
}

/// Map the engine-facing precision selector onto the backend's CPU-precision
/// enum. Default `F32` is recall-neutral; `F16` is the recall-risk opt-in and
/// only takes effect on CPU (CUDA/Metal ignore it and use BF16).
#[cfg(feature = "ml")]
fn cpu_precision(p: ComputePrecision) -> CpuPrecision {
    match p {
        ComputePrecision::F32 => CpuPrecision::F32,
        ComputePrecision::F16 => CpuPrecision::F16,
    }
}

/// Map the engine-facing quantization selector onto the backend's `Quant` enum.
/// `Bf16` (the default) is recall-neutral and CPU-only; `None` is the historical
/// F32 path; `Q8_0` and `Bf16Vnni` are recall-risk opt-ins. `Bf16`/`Bf16Vnni` are
/// CPU-only levers (a no-op on GPU, which already computes in bf16).
#[cfg(feature = "ml")]
fn quant(q: Quantization) -> Quant {
    match q {
        Quantization::None => Quant::None,
        Quantization::Q8_0 => Quant::Q8_0,
        Quantization::Bf16 => Quant::Bf16,
        Quantization::Bf16Vnni => Quant::Bf16Vnni,
    }
}

/// Translate an `MlConfig` into the Candle backend's config. `prefer_gpu` only
/// matters if the crate was built with `cuda`/`metal`; otherwise it falls through
/// to CPU regardless (see `select_device`).
#[cfg(feature = "ml")]
fn candle_config(cfg: &MlConfig) -> CandleConfig {
    CandleConfig {
        repo_id: cfg.model.clone(),
        revision: cfg.revision.clone(),
        // presidio-classifier's GPU foundation replaced `prefer_gpu: bool` with a
        // `device: DeviceHint` + `gpu_precision: PrecisionHint` pair. Preserve the
        // prior engine-facing semantics exactly: `prefer_gpu` => `Auto` (try cuda >
        // metal > cpu), otherwise pin to `Cpu`. `PrecisionHint::Auto` resolves to
        // BF16 on sm80+/Metal and degrades to F16 below (router/experts/score-head
        // stay F32). `MlConfig.prefer_gpu` stays the knob; richer device selection
        // is a future MlConfig extension.
        device: if cfg.prefer_gpu {
            DeviceHint::Auto
        } else {
            DeviceHint::Cpu
        },
        gpu_precision: PrecisionHint::Auto,
        cpu_precision: cpu_precision(cfg.compute_precision),
        quant: quant(cfg.quant),
        banded_attention: cfg.banded_attention,
    }
}

/// Refuse to fetch or load model repos outside the authorized allowlist.
/// Runs before any network or loader work. Local-only: the http backend pulls
/// no weights, so there is no checkpoint supply-chain surface to gate.
#[cfg(feature = "ml")]
fn ensure_authorized(cfg: &MlConfig) -> Result<(), EngineError> {
    if !crate::config::is_authorized_model(&cfg.model) {
        return Err(EngineError::Ml(format!(
            "ML model '{}' is not authorized; ZlauDeR only fetches/loads: {}",
            cfg.model,
            crate::config::AUTHORIZED_ML_MODELS.join(", ")
        )));
    }
    Ok(())
}

/// Build the configured recognizer. Heavy + blocking: the local backend
/// downloads + loads the model (cached under the standard `hf-hub` location);
/// the http backend validates config, connectivity-probes, and runs a synthetic
/// PII positive control against the endpoint.
pub fn build_recognizer(cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    match cfg.backend {
        MlBackend::Local => build_local(cfg),
        MlBackend::Http => build_http(cfg),
    }
}

/// `--download-model` pre-warm: local caches weights; http probes the endpoint.
pub fn download(cfg: &MlConfig) -> Result<(), EngineError> {
    match cfg.backend {
        MlBackend::Local => download_local(cfg),
        MlBackend::Http => probe_http(cfg),
    }
}

#[cfg(feature = "ml")]
fn build_local(cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    ensure_authorized(cfg)?;
    let backend =
        CandleBackend::new(candle_config(cfg)).map_err(|e| EngineError::Ml(e.to_string()))?;
    let rec: Arc<dyn MlRecognizer> = build_token_recognizer(Arc::new(backend), cfg);
    Ok(rec)
}

#[cfg(feature = "ml")]
fn download_local(cfg: &MlConfig) -> Result<(), EngineError> {
    ensure_authorized(cfg)?;
    CandleBackend::new(candle_config(cfg)).map_err(|e| EngineError::Ml(e.to_string()))?;
    Ok(())
}

/// Synthetic text whose round-trip through a privacy-filter endpoint must yield
/// an `EMAIL_ADDRESS` span. Fixed and PII-free (`example.com`), so it can be
/// sent to an unproven endpoint and may safely appear in error surfaces.
#[cfg(feature = "ml-http")]
const PROBE_TEXT: &str = "Probe contact: Sarah Probe <sarah.probe@example.com>";
#[cfg(feature = "ml-http")]
const PROBE_EMAIL: &str = "sarah.probe@example.com";

/// Translate the engine's http config knobs into the upstream `HttpConfig`.
#[cfg(feature = "ml-http")]
fn http_config(cfg: &MlConfig) -> Result<HttpConfig, EngineError> {
    let endpoint = cfg.endpoint.as_deref().ok_or_else(|| {
        EngineError::Ml(
            "[engine.ml] backend = \"http\" requires `endpoint` (the URL of an \
             HF-token-classification-compatible server)"
                .into(),
        )
    })?;
    let base_url = url::Url::parse(endpoint).map_err(|e| {
        EngineError::Ml(format!(
            "[engine.ml] endpoint '{endpoint}' is not a valid URL: {e}"
        ))
    })?;
    if !matches!(base_url.scheme(), "http" | "https") {
        return Err(EngineError::Ml(format!(
            "[engine.ml] endpoint must be http:// or https://, got '{endpoint}'"
        )));
    }
    // Resolve the bearer token from the named env var at load time and wrap it
    // in a `SecretString` (zeroized, never Debug-printed). The token never lives
    // in config files; a named-but-empty var fails closed.
    let auth = match &cfg.auth_token_env {
        Some(var) => {
            let token = std::env::var(var).unwrap_or_default();
            if token.is_empty() {
                return Err(EngineError::Ml(format!(
                    "[engine.ml] auth_token_env names '{var}' but that environment \
                     variable is unset or empty"
                )));
            }
            Some(HttpAuth::Bearer(secrecy::SecretString::from(token)))
        }
        None => None,
    };
    Ok(HttpConfig {
        base_url,
        // HF `transformers serve` / Inference-Providers shape: POST the endpoint
        // directly with `{"inputs": text}`. (TEI/custom remain a future knob.)
        schema: HttpSchema::HfTransformers,
        auth,
        call_timeout: std::time::Duration::from_secs(cfg.http_timeout_secs.max(1)),
        retry: RetryPolicy::default(),
        // Remote by definition; we make no localhost-trust claim here.
        require_local: false,
    })
}

/// Build the http recognizer and run both load-time checks. A failure here is a
/// load failure (status `failed`): hot-load semantics keep masking regex-only
/// unless `[engine.ml] required = true`.
#[cfg(feature = "ml-http")]
fn build_http_checked(cfg: &MlConfig) -> Result<Arc<TokenClassifierRecognizer>, EngineError> {
    let backend = HttpBackend::new(http_config(cfg)?)
        .map_err(|e| EngineError::Ml(format!("http ML backend init failed: {}", e.redacted())))?;
    let rec = build_token_recognizer(Arc::new(backend), cfg);
    // Check 1: connectivity — the endpoint answers a 2xx (upstream `healthcheck`
    // posts a synthetic `warmup` input and asserts success).
    rec.healthcheck().map_err(|e| {
        EngineError::Ml(format!("http ML endpoint healthcheck failed: {}", e.redacted()))
    })?;
    // Check 2: positive control — synthetic PII actually round-trips to an
    // EMAIL_ADDRESS span. A bare 2xx proves reachability, not that this is a
    // privacy-filter token-classifier; upstream deliberately bakes no PII
    // fixture / expected label into the library, so this assertion is zlauder's.
    positive_control(rec.as_ref())?;
    Ok(rec)
}

/// Send [`PROBE_TEXT`] through the recognizer and assert the expected email span
/// comes back. Fail-closed via `try_analyze`: a backend error surfaces (redacted)
/// rather than an empty result that would falsely pass the control.
#[cfg(feature = "ml-http")]
fn positive_control(rec: &TokenClassifierRecognizer) -> Result<(), EngineError> {
    let spans = rec.try_analyze(PROBE_TEXT, None).map_err(|e| {
        EngineError::Ml(format!("http ML endpoint probe failed: {}", e.redacted()))
    })?;
    let saw_email = spans.iter().any(|r| {
        r.entity_type == EntityType::EmailAddress
            && PROBE_TEXT.get(r.start..r.end) == Some(PROBE_EMAIL)
    });
    if saw_email {
        Ok(())
    } else {
        Err(EngineError::Ml(
            "http ML endpoint answered, but the synthetic-PII probe did not return \
             the expected EMAIL_ADDRESS span (is it an openai/privacy-filter \
             token-classification endpoint?)"
                .into(),
        ))
    }
}

#[cfg(feature = "ml-http")]
fn build_http(cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    let rec: Arc<dyn MlRecognizer> = build_http_checked(cfg)?;
    Ok(rec)
}

#[cfg(feature = "ml-http")]
fn probe_http(cfg: &MlConfig) -> Result<(), EngineError> {
    build_http_checked(cfg).map(|_| ())
}

// A build can carry one backend without the other; selecting the missing one is
// an explicit, actionable error — never a silent fall-through.
#[cfg(not(feature = "ml"))]
fn build_local(_cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    Err(no_local_backend())
}
#[cfg(not(feature = "ml"))]
fn download_local(_cfg: &MlConfig) -> Result<(), EngineError> {
    Err(no_local_backend())
}
#[cfg(not(feature = "ml"))]
fn no_local_backend() -> EngineError {
    EngineError::Ml(
        "this build lacks the local (Candle) ML backend; rebuild with the `ml` \
         feature or set [engine.ml] backend = \"http\""
            .into(),
    )
}
#[cfg(not(feature = "ml-http"))]
fn build_http(_cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    Err(no_http_backend())
}
#[cfg(not(feature = "ml-http"))]
fn probe_http(_cfg: &MlConfig) -> Result<(), EngineError> {
    Err(no_http_backend())
}
#[cfg(not(feature = "ml-http"))]
fn no_http_backend() -> EngineError {
    EngineError::Ml(
        "this build lacks the http ML backend; rebuild with the `ml-http` feature \
         or set [engine.ml] backend = \"local\""
            .into(),
    )
}

// Gated on `ml` (not just test): these exercise the Candle-path helpers
// (`ensure_authorized`), which don't exist in an `ml-http`-only build. The
// pure-mapping tests would compile under either backend, but `ensure_authorized`
// pins them to `ml`.
#[cfg(all(test, feature = "ml"))]
mod tests {
    use super::*;

    /// Unauthorized model ids are refused before network or loader work.
    #[test]
    fn unauthorized_model_is_refused_without_loading() {
        let mut cfg = MlConfig {
            model: "attacker/evil-weights".to_string(),
            ..Default::default()
        };
        let err = download(&cfg).expect_err("an unlisted repo must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("not authorized"), "got: {msg}");
        assert!(msg.contains("openai/privacy-filter"), "got: {msg}");
        // The default (allowlisted) model passes the gate (does not return the auth
        // error). We check the guard directly to avoid a real network fetch.
        cfg.model = crate::config::AUTHORIZED_ML_MODELS[0].to_string();
        assert!(ensure_authorized(&cfg).is_ok());
    }

    /// C5: the `private_date` override routes to `Custom("PRIVATE_DATE")` — NOT
    /// `DateTime` (the spec default) and NOT `DATE_OF_BIRTH`. Exercises only the
    /// pure `LabelMap` builder; no backend/model is loaded. Both backends share
    /// this map (see `build_token_recognizer`), so this guards http too.
    #[test]
    fn private_date_remaps_to_private_date_custom() {
        let map = privacy_filter_mapping();
        assert_eq!(
            map.translate(ML_LABEL_PRIVATE_DATE),
            Some(EntityType::Custom(ENTITY_PRIVATE_DATE.into())),
            "private_date must remap to Custom(\"PRIVATE_DATE\")"
        );
        // Guard against the rejected v1 design (private_date -> DATE_OF_BIRTH)
        // and against the spec default (DateTime) leaking through.
        assert_ne!(
            map.translate(ML_LABEL_PRIVATE_DATE),
            Some(EntityType::Custom("DATE_OF_BIRTH".into())),
            "private_date must NOT be relabeled DATE_OF_BIRTH (audit-trail lie)"
        );
        assert_ne!(
            map.translate(ML_LABEL_PRIVATE_DATE),
            Some(EntityType::DateTime),
            "private_date must override the spec default of DateTime"
        );
    }

    /// The override must touch ONLY `private_date`; every other privacy-filter
    /// label keeps its spec-default `EntityType`.
    #[test]
    fn other_labels_keep_spec_defaults() {
        let map = privacy_filter_mapping();
        assert_eq!(
            map.translate("private_email"),
            Some(EntityType::EmailAddress)
        );
        assert_eq!(map.translate("private_phone"), Some(EntityType::PhoneNumber));
        assert_eq!(map.translate("private_url"), Some(EntityType::Url));
        assert_eq!(map.translate("private_address"), Some(EntityType::Location));
        assert_eq!(map.translate("private_person"), Some(EntityType::Person));
        assert_eq!(
            map.translate("account_number"),
            Some(EntityType::UsBankAccount)
        );
        assert_eq!(map.translate("secret"), Some(EntityType::ApiKey));
    }
}

// The genuinely-zlauder HTTP seam: config translation, the two load-time checks
// (connectivity + synthetic-PII positive control), and the redaction the engine
// applies when surfacing a backend error. The wire decode / BIOES / offset /
// retry behavior is upstream's (presidio_classifier::backends::http) and tested
// there; these drive the REAL `HttpBackend` against a local mock server.
#[cfg(all(test, feature = "ml-http"))]
mod http_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Minimal one-shot HTTP responder: answers `responses.len()` sequential
    /// connections, each with the matching canned body (`200` unless the body is
    /// `STATUS:<code>:<body>`), then exits. The backend's `reqwest::blocking`
    /// client sends one request per connection under `Connection: close`.
    fn serve(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                let (mut header_end, mut content_len) = (0usize, 0usize);
                loop {
                    let n = match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if header_end == 0
                        && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                    {
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
            backend: MlBackend::Http,
            endpoint: Some(endpoint.to_string()),
            ..Default::default()
        }
    }

    /// Both load-time checks pass against a privacy-filter-shaped endpoint:
    /// connectivity (the warmup 2xx) then the synthetic-PII positive control
    /// (an EMAIL_ADDRESS span at the probe's offsets). Proves the config →
    /// `HttpConfig` translation and the shared label map are wired end to end.
    #[test]
    fn good_endpoint_passes_both_load_checks() {
        let url = serve(vec![
            // 1: healthcheck/warmup
            "[]".to_string(),
            // 2: positive control — email span at PROBE_EMAIL's offsets (28..51)
            r#"[{"entity_group":"private_email","score":0.99,"start":28,"end":51}]"#.to_string(),
        ]);
        super::build_http_checked(&cfg_for(&url))
            .expect("a privacy-filter endpoint must pass connectivity + positive control");
    }

    /// A reachable endpoint that returns NO email for the synthetic probe fails
    /// the positive control — a bare 2xx is not proof it's a privacy filter.
    #[test]
    fn positive_control_rejects_non_email_endpoint() {
        let url = serve(vec![
            "[]".to_string(),
            // a PERSON span, no email — wrong/again-not-a-privacy-filter endpoint
            r#"[{"entity_group":"private_person","score":0.99,"start":15,"end":26}]"#.to_string(),
        ]);
        let err = super::build_http_checked(&cfg_for(&url))
            .expect_err("no EMAIL_ADDRESS span must fail the positive control");
        assert!(err.to_string().contains("EMAIL_ADDRESS"), "got: {err}");
    }

    /// FAIL-CLOSED + REDACTED: a 4xx whose body echoes the rejected input (HF/TEI
    /// endpoints commonly do) must surface as an `Err` from `analyze` — never an
    /// empty "no PII" — and the PII in the body must NOT reach the error string
    /// (the engine renders `BackendError::redacted()`).
    #[test]
    fn status_error_fails_closed_without_leaking_body() {
        let sentinel = "SSN 123-45-6789 echoed back";
        // 400 is non-retryable → exactly one canned response is consumed.
        let url = serve(vec![format!("STATUS:400:{sentinel}")]);
        let backend = HttpBackend::new(http_config(&cfg_for(&url)).unwrap()).unwrap();
        let rec = build_token_recognizer(Arc::new(backend), &cfg_for(&url));
        let err = rec
            .analyze("my ssn is 123-45-6789")
            .expect_err("a 4xx must fail closed, never an empty Ok");
        let s = err.to_string();
        assert!(s.contains("400"), "want the status code in: {s}");
        assert!(!s.contains(sentinel), "response body leaked PII into error: {s}");
    }

    /// An unreachable endpoint surfaces as a real `Err` (fail closed), never an
    /// empty result that would ride upstream with PII unscanned.
    #[test]
    fn unreachable_endpoint_fails_closed() {
        // Port 9 (discard): nothing listens; connect refuses.
        let cfg = cfg_for("http://127.0.0.1:9/detect");
        let backend = HttpBackend::new(http_config(&cfg).unwrap()).unwrap();
        let rec = build_token_recognizer(Arc::new(backend), &cfg);
        assert!(
            rec.analyze("private text with sarah@example.com").is_err(),
            "an unreachable endpoint must be Err, never an empty Ok"
        );
    }

    /// Config validation fails fast at translation time (load), not the first
    /// masked request.
    #[test]
    fn config_validation_fails_fast() {
        // endpoint is required
        let mut c = cfg_for("http://127.0.0.1:9/detect");
        c.endpoint = None;
        assert!(http_config(&c).is_err(), "missing endpoint must error");
        // http(s) only
        assert!(
            http_config(&cfg_for("ftp://example.com/detect")).is_err(),
            "non-http scheme must error"
        );
        // a named auth env var must exist and be non-empty
        let mut c = cfg_for("http://127.0.0.1:9/detect");
        c.auth_token_env = Some("ZLAUDER_TEST_DEFINITELY_UNSET_TOKEN_VAR".into());
        assert!(
            http_config(&c).is_err(),
            "auth_token_env naming an unset var must fail closed"
        );
    }
}
