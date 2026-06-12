//! ML recognizer construction (`openai/privacy-filter` on a native-Rust Candle
//! CPU backend). This is the ONLY module that touches `presidio-classifier` /
//! Candle, so it is gated behind the `ml` feature; the rest of the engine wires
//! the recognizer in purely as an `Arc<dyn presidio_core::Recognizer>`.
//!
//! Both entry points are synchronous and heavy (model download + load). The
//! proxy calls them from a `spawn_blocking` task so the request executor is never
//! blocked, and `CandleBackend`'s loader drives `hf-hub` on its own scoped-thread
//! runtime, so it is safe to call from inside a Tokio context.

use std::sync::Arc;

use presidio_classifier::backends::{
    CandleBackend, CandleConfig, CpuPrecision, DeviceHint, PrecisionHint, Quant,
};
use presidio_classifier::{Chunker, LabelMap, OPENAI_PRIVACY_FILTER, TokenClassifierRecognizer};
use presidio_core::{EntityType, Recognizer};

use crate::config::{ComputePrecision, ENTITY_PRIVATE_DATE, MlConfig, Quantization};
use crate::error::EngineError;

/// The `openai/privacy-filter` model's native label for any private date.
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
fn privacy_filter_mapping() -> LabelMap {
    LabelMap::from_spec(&OPENAI_PRIVACY_FILTER).with_overrides([(
        ML_LABEL_PRIVATE_DATE.into(),
        EntityType::Custom(ENTITY_PRIVATE_DATE.into()),
    )])
}

/// Map the engine-facing precision selector onto the backend's CPU-precision
/// enum. Default `F32` is recall-neutral; `F16` is the recall-risk opt-in and
/// only takes effect on CPU (CUDA/Metal ignore it and use BF16).
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
fn candle_config(cfg: &MlConfig) -> CandleConfig {
    CandleConfig {
        repo_id: cfg.model.clone(),
        revision: cfg.revision.clone(),
        // presidio-classifier's GPU foundation replaced `prefer_gpu: bool` with a
        // `device: DeviceHint` + `gpu_precision: PrecisionHint` pair. Preserve the
        // prior semantics exactly: `prefer_gpu` => `Auto` (try cuda > metal > cpu),
        // otherwise pin to `Cpu`. `PrecisionHint::Auto` resolves to BF16 on
        // sm80+/Metal and degrades to F16 below (both gate-proven recall-safe;
        // router/experts/score-head stay F32). `MlConfig.prefer_gpu` stays the
        // engine-facing knob; richer device selection (index/explicit Cuda/Metal)
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

/// Refuse to fetch or load any model repo that is not on the authorized allowlist
/// ([`crate::config::AUTHORIZED_ML_MODELS`]). This is the SINGLE chokepoint covering
/// every override source — `--download-model --model <repo>`, `model on --model
/// <repo> --scope <file>`, and a raw `[engine.ml] model = "…"` edit all resolve here
/// before any network/loader work, so an arbitrary (model-supplied, injected, or
/// typo'd) checkpoint can never be pulled. Runs FIRST, before `CandleBackend::new`.
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

/// Build the token-classification recognizer, downloading + loading the model
/// (cached under the standard `hf-hub` location). Heavy + blocking.
pub fn build_recognizer(cfg: &MlConfig) -> Result<Arc<dyn Recognizer>, EngineError> {
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
    Ok(Arc::new(builder.build()))
}

/// Download + cache the model's weights/tokenizer/config without keeping it
/// loaded (constructs the backend, then drops it). Used by the explicit
/// `zlauder-proxy --download-model` pre-warm so a later `enable` is fast.
pub fn download(cfg: &MlConfig) -> Result<(), EngineError> {
    ensure_authorized(cfg)?;
    CandleBackend::new(candle_config(cfg)).map_err(|e| EngineError::Ml(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unauthorized model id is refused by `download`/`build_recognizer` BEFORE
    /// any network or loader work — `ensure_authorized` short-circuits, so this test
    /// needs no model files and asserts the supply-chain gate, not the backend.
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
