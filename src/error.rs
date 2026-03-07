//! Error types for dotenvage operations.

use thiserror::Error;

/// A specialized `Result` type for dotenvage operations.
pub type SecretsResult<T> = Result<T, SecretsError>;

/// Errors that can occur when working with encrypted secrets and environment
/// files.
#[derive(Debug, Error)]
pub enum SecretsError {
    /// Failed to load encryption key from file or environment variable.
    #[error("key load failed: {0}")]
    KeyLoadFailed(String),

    /// Failed to save encryption key to file.
    #[error("key save failed: {0}")]
    KeySaveFailed(String),

    /// Failed to encrypt a value.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Failed to decrypt a value (e.g., wrong key, corrupted data).
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Failed to read an environment file.
    #[error("env file read failed for {path}: {reason}")]
    EnvFileReadFailed {
        /// The path to the file that couldn't be read.
        path: String,
        /// The reason for the failure.
        reason: String,
    },

    /// Failed to parse an environment file.
    #[error("env file parse failed for {path}: {reason}")]
    EnvFileParseFailed {
        /// The path to the file that couldn't be parsed.
        path: String,
        /// The reason for the failure.
        reason: String,
    },

    /// Environment variable not found in the process environment.
    #[error("env var not found: {key}")]
    EnvVarNotFound {
        /// The name of the variable that wasn't found.
        key: String,
    },

    /// Failed to write output.
    #[error("write failed: {0}")]
    WriteFailed(String),

    /// Key already exists and `force` was not set.
    #[error("key already exists: {0}")]
    KeyAlreadyExists(String),

    /// Required elevated privileges (sudo/admin).
    #[error("insufficient privileges: {0}")]
    InsufficientPrivileges(String),
}
