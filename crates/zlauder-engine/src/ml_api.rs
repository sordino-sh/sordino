//! The engine-internal ML recognizer abstraction.
//!
//! The presidio `Recognizer` trait is infallible, but remote backends can fail.
//! The engine stores this fallible trait so failures refuse the request instead
//! of looking like "no PII found". Local recognizers are wrapped by
//! [`InfallibleMl`], which also converts panics into ML errors.
//!
//! Always compiled (no feature gate): the ML slot exists even in a regex-only
//! build; only the backends behind it are feature-gated.

use std::sync::Arc;

use presidio_core::RecognizerResult;

use crate::error::EngineError;

/// A fallible "text in -> PII spans out" backend for the engine's ML slot.
/// `Err` means the backend could not be consulted; `Ok(vec![])` means no PII.
pub trait MlRecognizer: Send + Sync {
    fn analyze(&self, text: &str) -> Result<Vec<RecognizerResult>, EngineError>;

    /// Batched sibling; one result vector per input, index-aligned. All-or-nothing:
    /// any failure aborts the whole batch. Default loops `analyze`.
    fn analyze_batch(&self, texts: &[&str]) -> Result<Vec<Vec<RecognizerResult>>, EngineError> {
        texts.iter().map(|t| self.analyze(t)).collect()
    }
}

/// Adapter from an infallible presidio recognizer onto the fallible ML slot.
/// Panics become [`EngineError::Ml`] so the request is refused.
pub struct InfallibleMl(pub Arc<dyn presidio_core::Recognizer>);

impl MlRecognizer for InfallibleMl {
    fn analyze(&self, text: &str) -> Result<Vec<RecognizerResult>, EngineError> {
        catch_recognizer_panic(|| self.0.analyze(text, None, None))
    }

    fn analyze_batch(&self, texts: &[&str]) -> Result<Vec<Vec<RecognizerResult>>, EngineError> {
        catch_recognizer_panic(|| self.0.analyze_batch(texts, None, None))
    }
}

/// Run a recognizer call with panic containment.
fn catch_recognizer_panic<T>(f: impl FnOnce() -> T) -> Result<T, EngineError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        // Do not surface panic payloads. They are arbitrary strings from backend
        // code and could include text being analyzed.
        EngineError::Ml("local ML recognizer panicked".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_payload_is_not_surfaced() {
        let err = catch_recognizer_panic(|| panic!("secret@example.com")).unwrap_err();
        match err {
            EngineError::Ml(msg) => {
                assert_eq!(msg, "local ML recognizer panicked");
                assert!(!msg.contains("secret@example.com"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
