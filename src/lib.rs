#![warn(missing_docs)]
#![warn(clippy::missing_errors_doc)]
#![warn(clippy::missing_panics_doc)]
#![warn(clippy::missing_safety_doc)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod loader;
pub mod manager;
pub mod patterns;

pub use crate::error::{
    SecretsError,
    SecretsResult,
};
pub use crate::loader::{
    Arch,
    AutoDetectPatterns,
    EnvLoader,
    Os,
};
pub use crate::manager::{
    KeyGenOptions,
    KeyGenResult,
    KeyLocation,
    KeyStoreTarget,
    SecretManager,
};
