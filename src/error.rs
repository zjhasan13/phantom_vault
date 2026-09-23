use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum VaultError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Generator invalid parameters: {0}")]
    GeneratorInvalidParams(String),
    #[error("Biometric error: {0}")]
    Biometric(String),
    #[error("Sync error: {0}")]
    Sync(String),
    #[error("Auto-Type error: {0}")]
    AutoType(String),
    #[error("Security violation: {0}")]
    Security(String),
}
