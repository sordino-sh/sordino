//! The engine-internal ML recognizer abstraction.
//!
//! The presidio `Recognizer` trait is infallible (`analyze -> Vec<_>`), which is
//! the wrong boundary for backends that can FAIL — most obviously the http
//! backend, where "endpoint unreachable" must refuse the request (fail-closed),
//! never return an empty "no PII" result (fail-open). So the ML slot stores this
//! fallible trait instead, and each backend adapts to it:
//!   - the http backend ([`crate::ml_http::HttpRecognizer`]) implements it
//!     directly, returning real errors;
//!   - the local Candle backend (and the test mocks) are wrapped in
//!     [`InfallibleMl`], whose `catch_unwind` also contains any unexpected panic
//!     inside the model code and surfaces it as an error instead of letting it
//!     tear through the proxy's request task.
//!
//! Always compiled (no feature gate): the ML slot exists even in a regex-only
//! build; only the backends behind it are feature-gated.

use std::sync::Arc;

use presidio_core::RecognizerResult;

use crate::error::EngineError;

/// A fallible "text in → PII spans out" backend for the engine's ML slot.
/// `Err` means the backend could not be consulted — the detection layer treats
/// that as a detection failure, which the engine fail-safes into refusing the
/// request. `Ok(vec![])` is a genuine "no PII found".
pub trait MlRecognizer: Send + Sync {
    fn analyze(&self, text: &str) -> Result<Vec<RecognizerResult>, EngineError>;

    /// Batched sibling; one result vector per input, index-aligned. All-or-nothing:
    /// any failure aborts the whole batch. Default loops `analyze`.
    fn analyze_batch(&self, texts: &[&str]) -> Result<Vec<Vec<RecognizerResult>>, EngineError> {
        texts.iter().map(|t| self.analyze(t)).collect()
    }
}

/// Adapter from an infallible presidio [`presidio_core::Recognizer`] (the local
/// Candle recognizer, test mocks) onto the fallible [`MlRecognizer`] slot. The
/// `catch_unwind` is deliberate hardening: a panic inside model code becomes an
/// [`EngineError::Ml`] (request refused) instead of unwinding through the proxy.
pub struct InfallibleMl(pub Arc<dyn presidio_core::Recognizer>);

impl MlRecognizer for InfallibleMl {
    fn analyze(&self, text: &str) -> Result<Vec<RecognizerResult>, EngineError> {
        catch_recognizer_panic(|| self.0.analyze(text, None, None))
    }

    fn analyze_batch(&self, texts: &[&str]) -> Result<Vec<Vec<RecognizerResult>>, EngineError> {
        catch_recognizer_panic(|| self.0.analyze_batch(texts, None, None))
    }
}

/// Run a recognizer call with panic containment, mapping an unwind to
/// [`EngineError::Ml`] so the caller's existing fail-safe (refuse the request)
/// takes over instead of the panic tearing through the proxy's request task.
fn catch_recognizer_panic<T>(f: impl FnOnce() -> T) -> Result<T, EngineError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("recognizer panicked (non-string payload)");
        EngineError::Ml(msg.to_string())
    })
}
