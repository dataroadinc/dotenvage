//! Node.js bindings for dotenvage using NAPI-RS

use std::path::Path;

use dotenvage::{
    AutoDetectPatterns,
    EnvLoader,
    SecretManager,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Wrapper for SecretManager in Node.js
#[napi]
pub struct JsSecretManager {
    inner: SecretManager,
}

#[napi]
impl JsSecretManager {
    /// Creates a new SecretManager by loading the key from standard locations
    #[napi]
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: SecretManager::new()
                .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?,
        })
    }

    /// Generates a new random identity
    #[napi(factory)]
    pub fn generate() -> Result<Self> {
        Ok(Self {
            inner: SecretManager::generate()
                .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?,
        })
    }

    /// Gets the public key as a string in age format (starts with `age1`)
    #[napi]
    pub fn public_key_string(&self) -> String {
        self.inner.public_key_string()
    }

    /// Encrypts a plaintext value and wraps it in the format `ENC[AGE:b64:...]`
    #[napi]
    pub fn encrypt_value(&self, plaintext: String) -> Result<String> {
        self.inner
            .encrypt_value(&plaintext)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))
    }

    /// Decrypts a value if it's encrypted; otherwise returns it unchanged
    #[napi]
    pub fn decrypt_value(&self, value: String) -> Result<String> {
        self.inner
            .decrypt_value(&value)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))
    }

    /// Checks if a value is in a recognized encrypted format
    #[napi]
    pub fn is_encrypted(&self, value: String) -> bool {
        SecretManager::is_encrypted(&value)
    }

    /// Returns the raw identity string (`AGE-SECRET-KEY-1...`)
    #[napi]
    pub fn identity_string(&self) -> String {
        self.inner.identity_string()
    }

    /// Creates a SecretManager from an existing identity string
    #[napi(factory)]
    pub fn from_identity_string(identity: String) -> Result<Self> {
        use age::x25519;

        // Parse the identity string directly (age format)
        let parsed_identity = identity
            .parse::<x25519::Identity>()
            .map_err(|e| Error::new(Status::GenericFailure, format!("Invalid identity: {}", e)))?;

        Ok(Self {
            inner: SecretManager::from_identity(parsed_identity),
        })
    }
}

/// Wrapper for EnvLoader in Node.js
#[napi]
pub struct JsEnvLoader {
    inner: EnvLoader,
}

#[napi]
impl JsEnvLoader {
    /// Creates a new EnvLoader with a default SecretManager
    #[napi]
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: EnvLoader::new()
                .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?,
        })
    }

    /// Creates an EnvLoader with a specific SecretManager
    #[napi(factory)]
    pub fn with_manager(manager: &JsSecretManager) -> Self {
        Self {
            inner: EnvLoader::with_manager(manager.inner.clone()),
        }
    }

    /// Loads `.env` files from the current directory in standard order.
    /// Decrypted values are loaded into the process environment.
    /// Returns the list of file paths that were actually loaded, in load order.
    #[napi]
    pub fn load(&self) -> Result<Vec<String>> {
        let paths = self
            .inner
            .load()
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;
        Ok(paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect())
    }

    /// Loads `.env` files from a specific directory using the same order.
    /// Returns the list of file paths that were actually loaded, in load order.
    #[napi]
    pub fn load_from_dir(&self, dir: String) -> Result<Vec<String>> {
        let paths = self
            .inner
            .load_from_dir(Path::new(&dir))
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;
        Ok(paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect())
    }

    /// Gets all variable names from all loaded `.env` files
    #[napi]
    pub fn get_all_variable_names(&self) -> Result<Vec<String>> {
        self.inner
            .get_all_variable_names()
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))
    }

    /// Gets all variable names from `.env` files in a specific directory
    #[napi]
    pub fn get_all_variable_names_from_dir(&self, dir: String) -> Result<Vec<String>> {
        self.inner
            .get_all_variable_names_from_dir(Path::new(&dir))
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))
    }

    /// Computes the ordered list of env file paths to load
    #[napi]
    pub fn resolve_env_paths(&self, dir: String) -> Result<Vec<String>> {
        let paths = self
            .inner
            .resolve_env_paths(Path::new(&dir))
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        Ok(paths)
    }

    /// Gets all environment variables as a map (decrypted)
    /// Note: This loads variables into the process environment first
    #[napi]
    pub fn get_all_variables(&self) -> Result<std::collections::HashMap<String, String>> {
        // First load into environment (ignore returned paths)
        let _ = self
            .inner
            .load()
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        let names = self
            .inner
            .get_all_variable_names()
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        // Collect variables into a HashMap
        let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for name in names {
            if let Ok(value) = std::env::var(&name) {
                vars.insert(name, value);
            }
        }

        Ok(vars)
    }

    /// Gets all environment variables from a specific directory as a map
    /// (decrypted) Note: This loads variables into the process environment
    /// first
    #[napi]
    pub fn get_all_variables_from_dir(
        &self,
        dir: String,
    ) -> Result<std::collections::HashMap<String, String>> {
        // First load into environment (ignore returned paths)
        let _ = self
            .inner
            .load_from_dir(Path::new(&dir))
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        let names = self
            .inner
            .get_all_variable_names_from_dir(Path::new(&dir))
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        // Collect variables into a HashMap
        let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for name in names {
            if let Ok(value) = std::env::var(&name) {
                vars.insert(name, value);
            }
        }

        Ok(vars)
    }
}

/// Checks if a key name should be encrypted based on auto-detection patterns
#[napi]
pub fn should_encrypt(key: String) -> bool {
    AutoDetectPatterns::should_encrypt(&key)
}

/// Module initialization - exported but does nothing
#[napi]
pub fn init() {}
