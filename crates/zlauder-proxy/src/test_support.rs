//! Test-only helpers shared by the walker test modules.
//!
//! The walkers' Phase-1 prewarm path only runs when a model is `Ready`
//! (`engine.ml_active()`), so to exercise it without downloading the ~2.8 GB
//! openai/privacy-filter model we install a deterministic MOCK recognizer via the
//! engine's public `ml_begin_load` / `ml_set_ready` slot API. The mock flags every
//! occurrence of a fixed marker as an `EmailAddress` (whose default operator is
//! `Token`, so it round-trips); the marker is a shape the regex analyzer never
//! detects, so on it the ONLY detection is the mock's — isolating the ML path that
//! prewarm batches.

use std::sync::Arc;

use presidio_core::{EntityType, NlpArtifacts, Recognizer, RecognizerResult};
use zlauder_engine::{EngineConfig, InfallibleMl, MaskEngine, MlConfig};

/// A deterministic stand-in for the ML recognizer. `analyze_batch` is left at the
/// trait default (loops `analyze`), exactly what the per-leaf `mask` path calls, so
/// the walker test pins the COLLECT→prewarm→mask wiring rather than the real
/// batched-forward parity (that is gated by the ignored real-model test).
#[derive(Debug)]
pub struct MarkerRecognizer {
    entities: Vec<EntityType>,
    marker: &'static str,
}

impl MarkerRecognizer {
    pub fn new(marker: &'static str) -> Self {
        Self {
            entities: vec![EntityType::EmailAddress],
            marker,
        }
    }
}

impl Recognizer for MarkerRecognizer {
    fn name(&self) -> &str {
        "marker-mock"
    }
    fn supported_entities(&self) -> &[EntityType] {
        &self.entities
    }
    fn supported_languages(&self) -> &[&str] {
        &["en"]
    }
    fn analyze(
        &self,
        text: &str,
        _entities: Option<&[EntityType]>,
        _nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(i) = text[from..].find(self.marker) {
            let start = from + i;
            let end = start + self.marker.len();
            out.push(RecognizerResult::new(
                EntityType::EmailAddress,
                start,
                end,
                0.99,
            ));
            from = end;
        }
        out
    }
}

/// An engine whose ML slot is `Ready` with a [`MarkerRecognizer`], so the walkers'
/// `engine.ml_active()`-gated prewarm phase actually runs. Fixed session bytes ⇒
/// deterministic token minting.
pub fn engine_with_mock_ml(marker: &'static str) -> MaskEngine {
    let engine = MaskEngine::with_session(EngineConfig::default(), [3u8; 32], [5u8; 16])
        .expect("engine init");
    let generation = engine.ml_begin_load(MlConfig::default());
    engine.ml_set_ready(
        generation,
        Arc::new(InfallibleMl(Arc::new(MarkerRecognizer::new(marker)))),
    );
    assert!(engine.ml_active(), "mock ML should be Ready");
    engine
}
