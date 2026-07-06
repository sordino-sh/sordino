//! ML recognizer construction. `[engine.ml] backend` selects local Candle
//! inference (`ml`), a remote token-classification endpoint (`ml-http`), or an
//! out-of-process burn-wgpu GPU sidecar child (`ml-sidecar`). Missing backend
//! features fail explicitly instead of falling through.
//!
//! All three backends build the SAME `presidio_classifier::TokenClassifierRecognizer`
//! through one helper ([`build_token_recognizer`]); they differ ONLY in the
//! `InferenceBackend` passed in. The spec, chunker, label-map override, and
//! score floor are set once, in that helper, so local/http/sidecar can never drift
//! into different detections for the same model output (the #1 silent-corruption
//! trap of a hand-rolled second path). The http and sidecar paths additionally
//! share the two load-time checks (connectivity + synthetic-PII positive control)
//! via [`validate_opaque_backend`], because both wrap an opaque backend whose
//! liveness and identity must be proven at load (candle is trusted by in-process
//! construction).
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

#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
use presidio_classifier::{
    Chunker, InferenceBackend, LabelMap, OPENAI_PRIVACY_FILTER, TokenClassifierRecognizer,
};
#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
use presidio_core::{EntityType, RecognizerResult};

#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
use crate::config::ENTITY_PRIVATE_DATE;
#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
use crate::ml_api::catch_recognizer_panic;

#[cfg(feature = "ml")]
use presidio_classifier::backends::{
    select, BackendChoice, CandleConfig, CpuPrecision, DeviceHint, PrecisionHint, Quant,
};
#[cfg(feature = "ml")]
use crate::config::{ComputePrecision, Quantization};

#[cfg(feature = "ml-http")]
use presidio_classifier::backends::{HttpAuth, HttpBackend, HttpConfig, HttpSchema, RetryPolicy};

#[cfg(feature = "ml-sidecar")]
use std::ffi::OsString;
#[cfg(feature = "ml-sidecar")]
use std::path::PathBuf;
#[cfg(feature = "ml-sidecar")]
use std::time::Duration;
#[cfg(feature = "ml-sidecar")]
use presidio_classifier::BackendCapabilities;
#[cfg(feature = "ml-sidecar")]
use presidio_classifier::backends::{
    SidecarRestartPolicy, SubprocessConfig, SubprocessSidecarBackend,
};

/// The `openai/privacy-filter` model's native label for any private date.
#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
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
#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
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
#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
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
#[cfg(any(feature = "ml", feature = "ml-http", feature = "ml-sidecar"))]
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

/// Translate an `MlConfig` into a [`CandleConfig`]. `prefer_gpu` => `DeviceHint::Auto`
/// (candle resolves cuda > metal > cpu — all freely re-buildable, so this survives
/// sordino's ML reload lifecycle), else pin `Cpu`. `PrecisionHint::Auto` resolves
/// per device: BF16 on CUDA sm80+ (degrading to F16 below), F16 on Metal, F32 on CPU;
/// router/experts/score-head stay F32. The CPU-F32 and CUDA-BF16 paths are the ones
/// the recall gate proved; F16-on-Metal (reachable on the Apple-Silicon build when
/// `prefer_gpu` is set) is not yet separately gated — a tracked follow-up. When
/// `force_cpu` is set (cache pre-warm), the device is pinned `Cpu` regardless of
/// `prefer_gpu`. `MlConfig.prefer_gpu` stays the engine-facing knob; richer device
/// selection is a future `MlConfig` extension.
#[cfg(feature = "ml")]
fn candle_config(cfg: &MlConfig, force_cpu: bool) -> CandleConfig {
    CandleConfig {
        repo_id: cfg.model.clone(),
        revision: cfg.revision.clone(),
        device: if cfg.prefer_gpu && !force_cpu {
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

/// The [`BackendChoice`] for an `MlConfig` — the candle substrate via the `Candle`
/// trapdoor. Deliberately NOT `BackendChoice::Auto` (which would add the burn-wgpu
/// rung): cubecl's single-wgpu-init-per-process collides with sordino's drop+rebuild
/// reload lifecycle, so the burn rung is deferred until a backend-reuse path exists.
#[cfg(feature = "ml")]
fn backend_choice(cfg: &MlConfig) -> BackendChoice {
    BackendChoice::Candle(candle_config(cfg, false))
}

/// Refuse to fetch or load any model repo that is not on the authorized allowlist
/// ([`crate::config::AUTHORIZED_ML_MODELS`]). This is the SINGLE chokepoint covering
/// every override source — `--download-model --model <repo>`, `model on --model
/// <repo> --scope <file>`, and a raw `[engine.ml] model = "…"` edit all resolve here
/// before any network/loader work, so an arbitrary (model-supplied, injected, or
/// typo'd) checkpoint can never be pulled. Applies to the weight-fetching backends
/// — local Candle AND the burn-wgpu sidecar child (which fetches its own weights
/// from the model id we forward as argv). The http backend pulls no weights, so it
/// has no checkpoint supply-chain surface and does not gate here.
#[cfg(any(feature = "ml", feature = "ml-sidecar"))]
fn ensure_authorized(cfg: &MlConfig) -> Result<(), EngineError> {
    if !crate::config::is_authorized_model(&cfg.model) {
        return Err(EngineError::Ml(format!(
            "ML model '{}' is not authorized; Sordino only fetches/loads: {}",
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
        MlBackend::Sidecar => build_sidecar(cfg),
    }
}

/// `--download-model` pre-warm: local caches weights; http probes the endpoint;
/// sidecar spawns the burn child (which fetches weights + inits the GPU) and runs
/// the same load-time checks — a strictly stronger pre-warm that also proves the
/// GPU path works before the operator relies on it.
pub fn download(cfg: &MlConfig) -> Result<(), EngineError> {
    match cfg.backend {
        MlBackend::Local => download_local(cfg),
        MlBackend::Http => probe_http(cfg),
        MlBackend::Sidecar => probe_sidecar(cfg),
    }
}

#[cfg(feature = "ml")]
fn build_local(cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    ensure_authorized(cfg)?;
    // Build via presidio-classifier's `select()` API, pinned to the candle substrate
    // (cuda > metal > cpu under `prefer_gpu`, else CPU). candle is re-buildable, so
    // this survives ML reload; the burn-wgpu rung is deferred (see `backend_choice`).
    // `select()` returns a ready (warmed) `Arc<dyn InferenceBackend>`; route it through
    // the shared `build_token_recognizer` so the local path can never drift from http.
    let backend = select(backend_choice(cfg)).map_err(|e| EngineError::Ml(e.to_string()))?;
    let rec: Arc<dyn MlRecognizer> = build_token_recognizer(backend, cfg);
    Ok(rec)
}

#[cfg(feature = "ml")]
fn download_local(cfg: &MlConfig) -> Result<(), EngineError> {
    ensure_authorized(cfg)?;
    // Device-irrelevant for a cache pre-warm: force candle CPU so a `--download-model`
    // never spins up a GPU just to populate the hf-hub cache.
    select(BackendChoice::Candle(candle_config(cfg, true)))
        .map_err(|e| EngineError::Ml(e.to_string()))?;
    Ok(())
}

/// Synthetic text whose round-trip through a privacy-filter backend must yield an
/// `EMAIL_ADDRESS` span. Fixed and PII-free (`example.com`), so it can be sent to
/// an unproven endpoint/child and may safely appear in error surfaces. Shared by
/// the http and sidecar load-time positive control.
#[cfg(any(feature = "ml-http", feature = "ml-sidecar"))]
const PROBE_TEXT: &str = "Probe contact: Sarah Probe <sarah.probe@example.com>";
#[cfg(any(feature = "ml-http", feature = "ml-sidecar"))]
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

/// Run the two load-time checks shared by every opaque (out-of-process / remote)
/// backend — http and sidecar. `what` names the backend in error messages
/// ("http ML endpoint" / "burn sidecar"). A failure here is a load failure
/// (status `failed`): hot-load semantics keep masking regex-only unless
/// `[engine.ml] required = true`. Candle does NOT use this — an in-process build
/// is trusted by construction.
#[cfg(any(feature = "ml-http", feature = "ml-sidecar"))]
fn validate_opaque_backend(rec: &TokenClassifierRecognizer, what: &str) -> Result<(), EngineError> {
    // Check 1: connectivity / liveness — the backend answers warmup (upstream
    // `healthcheck` posts a synthetic `warmup` and asserts success; for the
    // sidecar this is also what waits out the child's eager GPU build).
    rec.healthcheck()
        .map_err(|e| EngineError::Ml(format!("{what} healthcheck failed: {}", e.redacted())))?;
    // Check 2: positive control — synthetic PII actually round-trips to an
    // EMAIL_ADDRESS span. A bare liveness reply proves reachability, not that this
    // is a privacy-filter token-classifier; upstream deliberately bakes no PII
    // fixture / expected label into the library, so this assertion is sordino's.
    positive_control(rec, what)
}

/// Build the http recognizer and run both load-time checks.
#[cfg(feature = "ml-http")]
fn build_http_checked(cfg: &MlConfig) -> Result<Arc<TokenClassifierRecognizer>, EngineError> {
    let backend = HttpBackend::new(http_config(cfg)?)
        .map_err(|e| EngineError::Ml(format!("http ML backend init failed: {}", e.redacted())))?;
    let rec = build_token_recognizer(Arc::new(backend), cfg);
    validate_opaque_backend(rec.as_ref(), "http ML endpoint")?;
    Ok(rec)
}

/// Send [`PROBE_TEXT`] through the recognizer and assert the expected email span
/// comes back. Fail-closed via `try_analyze`: a backend error surfaces (redacted)
/// rather than an empty result that would falsely pass the control.
#[cfg(any(feature = "ml-http", feature = "ml-sidecar"))]
fn positive_control(rec: &TokenClassifierRecognizer, what: &str) -> Result<(), EngineError> {
    let spans = rec
        .try_analyze(PROBE_TEXT, None)
        .map_err(|e| EngineError::Ml(format!("{what} probe failed: {}", e.redacted())))?;
    let saw_email = spans.iter().any(|r| {
        r.entity_type == EntityType::EmailAddress
            && PROBE_TEXT.get(r.start..r.end) == Some(PROBE_EMAIL)
    });
    if saw_email {
        Ok(())
    } else {
        Err(EngineError::Ml(format!(
            "{what} answered, but the synthetic-PII probe did not return the expected \
             EMAIL_ADDRESS span (is it an openai/privacy-filter token-classifier?)"
        )))
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

/// Default basename of the burn-wgpu sidecar child binary (shipped as a separate
/// release asset; located by path at spawn time).
#[cfg(feature = "ml-sidecar")]
const BURN_SERVER_BIN: &str = "presidio-classifier-burn-server";

/// Resolve the burn-server child binary. Order: explicit `[engine.ml] sidecar_path`,
/// then the `SORDINO_BURN_SERVER` env override, then a binary co-located with the
/// running proxy executable (where packaging puts it). The explicit path / env are
/// validated to exist (a clear load error, not an opaque spawn failure); if none
/// resolve, loading fails closed with an actionable message.
///
/// There is intentionally NO bare-name `$PATH` fallback: the child is spawned with
/// UNMASKED leaf text on its stdin, so resolving it through an ambient/writable
/// `PATH` entry would be a PII-exfil / code-exec hijack surface. The binary must be
/// named explicitly, via the env override, or co-located with the proxy.
#[cfg(feature = "ml-sidecar")]
fn resolve_sidecar_program(cfg: &MlConfig) -> Result<PathBuf, EngineError> {
    if let Some(p) = cfg.sidecar_path.as_deref() {
        return require_executable(PathBuf::from(p), "[engine.ml] sidecar_path");
    }
    if let Some(p) = std::env::var_os("SORDINO_BURN_SERVER") {
        return require_executable(PathBuf::from(p), "SORDINO_BURN_SERVER");
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(BURN_SERVER_BIN);
        if candidate.is_file() {
            return require_executable(candidate, "the proxy executable directory");
        }
    }
    Err(EngineError::Ml(format!(
        "could not locate the burn-wgpu sidecar binary '{BURN_SERVER_BIN}': set \
         [engine.ml] sidecar_path to an absolute path, set $SORDINO_BURN_SERVER, or \
         co-locate it next to the proxy executable. (No $PATH lookup is performed — \
         the child receives unmasked text, so an ambient PATH entry would be a hijack \
         surface.)"
    )))
}

/// Resolve `path` to an existing, CANONICAL absolute file, with an actionable build
/// hint. `source` names where the path came from (config key / env var / co-located).
///
/// An ABSOLUTE input is load-bearing security, not cosmetics, so it is enforced
/// explicitly BEFORE canonicalize: `Path::canonicalize` resolves a *relative* input
/// against the proxy's CWD (a bare `"presidio-classifier-burn-server"` becomes
/// `$CWD/presidio-classifier-burn-server`), which would silently accept a binary from
/// an ambient, possibly-writable working directory — a code-exec / PII-exfil hijack
/// for a child that receives UNMASKED text. Rejecting non-absolute paths up front also
/// forecloses the upstream `Command::new` ambient-`$PATH` fallback (which only consults
/// `$PATH` for bare names). Canonicalize then merely resolves symlinks and confirms
/// existence; `is_file` rejects a dir / symlink-to-dir.
#[cfg(feature = "ml-sidecar")]
fn require_executable(path: PathBuf, source: &str) -> Result<PathBuf, EngineError> {
    // Absolute-path invariant (see fn doc): reject a relative input before canonicalize,
    // which would otherwise silently re-anchor it on the proxy's CWD.
    if !path.is_absolute() {
        return Err(EngineError::Ml(format!(
            "{source} points at '{}', which is not an absolute path; the burn-wgpu \
             sidecar binary must be named by ABSOLUTE path (a relative path resolves \
             against the proxy's working directory — a hijack surface for a child that \
             receives unmasked text). build it (cargo build -p presidio-classifier \
             --no-default-features --features backend-burn --bin {BURN_SERVER_BIN}) and \
             point at the absolute path to the resulting binary",
            path.display()
        )));
    }
    let resolved = path.canonicalize().map_err(|e| {
        EngineError::Ml(format!(
            "{source} points at '{}', which could not be resolved to an existing file \
             ({e}); build the burn-wgpu sidecar (cargo build -p presidio-classifier \
             --no-default-features --features backend-burn --bin {BURN_SERVER_BIN}) and \
             point at an absolute path to the resulting binary",
            path.display()
        ))
    })?;
    if resolved.is_file() {
        Ok(resolved)
    } else {
        Err(EngineError::Ml(format!(
            "{source} resolves to '{}', which is not a file",
            resolved.display()
        )))
    }
}

/// Capabilities the burn sidecar reports via `InferenceBackend::capabilities`.
/// Mirrors the model's native label set; `local = true` (same-host private pipe),
/// `deterministic = false` (GPU float reductions are not bit-reproducible across
/// drivers). Informational — detection routing uses the spec's [`LabelMap`], not
/// these caps.
#[cfg(feature = "ml-sidecar")]
fn sidecar_caps(cfg: &MlConfig) -> BackendCapabilities {
    BackendCapabilities {
        model_id: cfg.model.as_str().into(),
        supported_labels: [
            "account_number",
            "private_address",
            "private_date",
            "private_email",
            "private_person",
            "private_phone",
            "private_url",
            "secret",
        ]
        .iter()
        .map(|s| (*s).into())
        .collect(),
        max_input_chars: 8192,
        languages: vec!["en".into()],
        local: true,
        deterministic: false,
    }
}

/// Construct the supervised burn-wgpu sidecar backend and run the load-time checks.
///
/// The backend is lazy-spawn (upstream): the first call — our `healthcheck` warmup
/// — spawns the child, which eagerly builds the wgpu device and loads the model,
/// then answers. `spawn_timeout` therefore covers the full cold start (cubecl init
/// and model fetch/load); `call_timeout` covers a single classify. Reload safety
/// rides sordino's EXISTING drop+rebuild path: dropping this recognizer drops the
/// backend, whose `Drop` shuts the child down (then `kill`s it), and a rebuild
/// spawns a fresh child with a fresh, uncontended cubecl global — the whole reason
/// the GPU path lives out-of-process.
#[cfg(feature = "ml-sidecar")]
fn build_sidecar_checked(cfg: &MlConfig) -> Result<Arc<TokenClassifierRecognizer>, EngineError> {
    // The child fetches its own weights from the model id we forward; gate the
    // allowlist here, before any spawn/network, exactly as the local loader does.
    ensure_authorized(cfg)?;
    let program = resolve_sidecar_program(cfg)?;

    // Forward only the knobs the child honors: model id, optional revision, and
    // banded-attention. `min_score` is applied at the recognizer level (the shared
    // `build_token_recognizer`), not as argv; device/dtype are not wireable through
    // the child (always wgpu-auto at its built-in precision).
    let mut args: Vec<OsString> = Vec::new();
    args.push("--model-id".into());
    args.push(cfg.model.as_str().into());
    if let Some(rev) = &cfg.revision {
        args.push("--model-revision".into());
        args.push(rev.as_str().into());
    }
    args.push("--banded-attention".into());
    args.push(if cfg.banded_attention { "true" } else { "false" }.into());

    let sub = SubprocessConfig {
        program,
        args,
        envs: Vec::new(),
        path_prepend: None,
        id: format!("{}@sidecar:burn-wgpu", cfg.model),
        caps: sidecar_caps(cfg),
        // Forward child stderr to ours: the child writes ALL diagnostics there by
        // discipline (stdout is JSON-RPC frames only), so this is the only window
        // into a failing GPU init.
        log_to_stderr: true,
        // Cold start can be slow: a first-ever model download happens inside the
        // child during the eager build, and the warmup reply waits on it. Generous
        // so a legitimate cold download is not mistaken for a hang — this gates only
        // load-time/pre-warm, never the steady-state request path. Pre-warm with
        // `--download-model` to keep steady-state spawns fast (warm hf-hub cache).
        spawn_timeout: Duration::from_secs(600),
        // One classify on the GPU; generous for a large document. Fail-closed on
        // timeout (the recognizer turns a Timeout into a refusal, never an empty Ok).
        call_timeout: Duration::from_secs(120),
        // Keep the GPU child warm; sordino's reload owns the lifecycle, not idle.
        idle_shutdown: None,
        restart_policy: SidecarRestartPolicy::default(),
    };

    let backend = SubprocessSidecarBackend::new(sub)
        .map_err(|e| EngineError::Ml(format!("burn sidecar init failed: {}", e.redacted())))?;
    let rec = build_token_recognizer(Arc::new(backend), cfg);
    validate_opaque_backend(rec.as_ref(), "burn sidecar")?;
    Ok(rec)
}

#[cfg(feature = "ml-sidecar")]
fn build_sidecar(cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    let rec: Arc<dyn MlRecognizer> = build_sidecar_checked(cfg)?;
    Ok(rec)
}

#[cfg(feature = "ml-sidecar")]
fn probe_sidecar(cfg: &MlConfig) -> Result<(), EngineError> {
    build_sidecar_checked(cfg).map(|_| ())
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
#[cfg(not(feature = "ml-sidecar"))]
fn build_sidecar(_cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    Err(no_sidecar_backend())
}
#[cfg(not(feature = "ml-sidecar"))]
fn probe_sidecar(_cfg: &MlConfig) -> Result<(), EngineError> {
    Err(no_sidecar_backend())
}
#[cfg(not(feature = "ml-sidecar"))]
fn no_sidecar_backend() -> EngineError {
    EngineError::Ml(
        "this build lacks the burn-wgpu sidecar ML backend; rebuild with the \
         `ml-sidecar` feature or set [engine.ml] backend = \"local\""
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

// The genuinely-sordino HTTP seam: config translation, the two load-time checks
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
        c.auth_token_env = Some("SORDINO_TEST_DEFINITELY_UNSET_TOKEN_VAR".into());
        assert!(
            http_config(&c).is_err(),
            "auth_token_env naming an unset var must fail closed"
        );
    }
}

// The genuinely-sordino sidecar seam: the model allowlist must gate the burn
// child (which fetches its own weights), and it must fire BEFORE any binary
// resolution / spawn. The supervision, protocol, and GPU work are upstream's
// (presidio_classifier::backends::sidecar + the burn-server child) and tested
// there; this guards sordino's wiring of the security gate.
#[cfg(all(test, feature = "ml-sidecar"))]
mod sidecar_tests {
    use super::*;

    /// The model allowlist gates the sidecar path too: an unauthorized model id is
    /// refused at `ensure_authorized`, BEFORE the child binary is resolved or
    /// spawned. Otherwise a model-supplied / injected / typo'd repo id would be
    /// handed to the burn child, which fetches arbitrary weights from HF (a
    /// supply-chain vector). `download` routes sidecar → `probe_sidecar` →
    /// `build_sidecar_checked`, whose first action is the allowlist check.
    #[test]
    fn unauthorized_model_refused_before_spawn() {
        let cfg = MlConfig {
            backend: MlBackend::Sidecar,
            model: "attacker/evil-weights".to_string(),
            // A path that would error loudly at resolution ("could not be resolved")
            // IF reached; the allowlist must short-circuit before that.
            sidecar_path: Some("/nonexistent/zzz-burn-server".into()),
            ..Default::default()
        };
        let err = download(&cfg).expect_err("an unlisted repo must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("not authorized"), "got: {msg}");
        assert!(
            !msg.contains("could not be resolved"),
            "must refuse on the allowlist BEFORE resolving the binary path: {msg}"
        );
        // The authorized default passes the gate (checked directly to avoid a real
        // spawn + GPU init + model fetch).
        let ok = MlConfig {
            model: crate::config::AUTHORIZED_ML_MODELS[0].to_string(),
            ..cfg
        };
        assert!(ensure_authorized(&ok).is_ok());
    }

    /// Fail-closed resolution: an AUTHORIZED model with a non-existent (or
    /// bare/relative) `sidecar_path` must error at canonicalization — never spawn,
    /// never let the upstream `Command::new` fall back to a `$PATH` lookup of a bare
    /// program name (a hijack surface, since the child receives unmasked text). This
    /// gets PAST `ensure_authorized` into `resolve_sidecar_program`.
    #[test]
    fn missing_or_relative_sidecar_binary_fails_closed_at_resolution() {
        let cfg = MlConfig {
            backend: MlBackend::Sidecar,
            model: crate::config::AUTHORIZED_ML_MODELS[0].to_string(),
            sidecar_path: Some("/nonexistent/zzz-burn-server".into()),
            ..Default::default()
        };
        let err = probe_sidecar(&cfg).expect_err("a missing binary must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("could not be resolved"),
            "expected a fail-closed resolution error, got: {msg}"
        );
        // A RELATIVE sidecar_path must be rejected as non-absolute BEFORE canonicalize
        // (which would otherwise re-anchor it on the proxy's CWD — the hijack the
        // absolute-path invariant forecloses). Distinct error from the missing case.
        let rel = MlConfig {
            backend: MlBackend::Sidecar,
            model: crate::config::AUTHORIZED_ML_MODELS[0].to_string(),
            sidecar_path: Some("zzz-burn-server".into()),
            ..Default::default()
        };
        let rel_err = probe_sidecar(&rel).expect_err("a relative sidecar_path must fail closed");
        assert!(
            rel_err.to_string().contains("not an absolute path"),
            "a relative sidecar_path must be rejected as non-absolute, got: {rel_err}"
        );
        // resolve_sidecar_program returns a CANONICAL absolute path for a real file,
        // so `Command::new` never consults $PATH. Sanity-check canonicalization on a
        // path we know exists (this test binary itself).
        let me = std::env::current_exe().expect("current_exe");
        let resolved = require_executable(me.clone(), "test")
            .expect("an existing file must resolve");
        assert!(
            resolved.is_absolute(),
            "resolved program must be absolute (no $PATH fallback at spawn): {}",
            resolved.display()
        );
    }
}
