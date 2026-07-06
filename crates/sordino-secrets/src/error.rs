/// Errors from resolving/listing a secret through a provider. Never carries a secret
/// value (only paths/schemes/stderr, which themselves must not be logged at info+).
#[derive(thiserror::Error, Debug)]
pub enum ProviderError {
    #[error("secret not found")]
    NotFound,
    #[error("backend binary not found: {0}")]
    BinaryMissing(String),
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("authentication / decryption failed: {0}")]
    Auth(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("invalid secret ref: {0}")]
    BadRef(String),
}
