//! ML recognizer construction. `[engine.ml] backend` selects local Candle
//! inference (`ml`) or a remote token-classification endpoint (`ml-http`).
//! Missing backend features fail explicitly instead of falling through.
//!
//! Entry points are synchronous; the proxy calls them from `spawn_blocking`.

use std::sync::Arc;

#[cfg(feature = "ml")]
use presidio_classifier::backends::{CandleBackend, CandleConfig, CpuPrecision, Quant};
#[cfg(feature = "ml")]
use presidio_classifier::{Chunker, LabelMap, OPENAI_PRIVACY_FILTER, TokenClassifierRecognizer};
#[cfg(feature = "ml")]
use presidio_core::EntityType;

#[cfg(feature = "ml")]
use crate::config::{ComputePrecision, ENTITY_PRIVATE_DATE, Quantization};
use crate::config::{MlBackend, MlConfig};
use crate::error::EngineError;
#[cfg(feature = "ml")]
use crate::ml_api::InfallibleMl;
use crate::ml_api::MlRecognizer;

/// The `openai/privacy-filter` model's native label for any private date.
#[cfg(feature = "ml")]
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
#[cfg(feature = "ml")]
fn privacy_filter_mapping() -> LabelMap {
    LabelMap::from_spec(&OPENAI_PRIVACY_FILTER).with_overrides([(
        ML_LABEL_PRIVATE_DATE.into(),
        EntityType::Custom(ENTITY_PRIVATE_DATE.into()),
    )])
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
        prefer_gpu: cfg.prefer_gpu,
        cpu_precision: cpu_precision(cfg.compute_precision),
        quant: quant(cfg.quant),
        banded_attention: cfg.banded_attention,
    }
}

/// Refuse to fetch or load model repos outside the authorized allowlist.
/// Runs before any network or loader work.
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
/// the http backend validates config and probes the endpoint.
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
    let mut builder = TokenClassifierRecognizer::builder()
        .with_spec(&OPENAI_PRIVACY_FILTER)
        .with_backend(Arc::new(backend))
        // Sentence-like chunker so oversize fields are split, not rejected.
        .with_chunker(Chunker::for_openai_privacy_filter())
        // Remap the generic `private_date` label to a neutral `PRIVATE_DATE`
        // (NOT `DATE_OF_BIRTH`); see `privacy_filter_mapping`.
        .with_mapping(privacy_filter_mapping());
    if let Some(s) = cfg.min_score {
        builder = builder.with_min_score(s);
    }
    // Adapt the infallible local recognizer onto the engine's fallible ML slot.
    Ok(Arc::new(InfallibleMl(Arc::new(builder.build()))))
}

#[cfg(feature = "ml")]
fn download_local(cfg: &MlConfig) -> Result<(), EngineError> {
    ensure_authorized(cfg)?;
    CandleBackend::new(candle_config(cfg)).map_err(|e| EngineError::Ml(e.to_string()))?;
    Ok(())
}

#[cfg(feature = "ml-http")]
fn build_http(cfg: &MlConfig) -> Result<Arc<dyn MlRecognizer>, EngineError> {
    crate::ml_http::build_recognizer(cfg)
}

#[cfg(feature = "ml-http")]
fn probe_http(cfg: &MlConfig) -> Result<(), EngineError> {
    crate::ml_http::probe(cfg)
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
// (`privacy_filter_mapping`, `ensure_authorized`), which don't exist in an
// `ml-http`-only build.
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
    /// pure `LabelMap` builder; the candle backend/model is never loaded.
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
        assert_eq!(
            map.translate("private_phone"),
            Some(EntityType::PhoneNumber)
        );
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
