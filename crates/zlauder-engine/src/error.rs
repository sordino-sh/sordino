use crate::surface::Surface;

#[derive(thiserror::Error, Debug)]
pub enum EngineError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("mask() called with an unmask surface {0:?}")]
    WrongDirection(Surface),
    #[error("detection failed: {0}")]
    DetectionFailed(String),
    #[error("invalid custom regex {pattern:?}: {source}")]
    BadCustomRegex {
        pattern: String,
        source: regex::Error,
    },
    #[error("ml model: {0}")]
    Ml(String),
    #[error("invalid secret rule: {0}")]
    InvalidSecret(String),
}
