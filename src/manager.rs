//! Secret manager implementation for encryption and decryption using age.
//!
//! This module provides the core [`SecretManager`] type for encrypting and
//! decrypting sensitive values using the
//! [age encryption tool](https://age-encryption.org/).
//!
//! It also provides types for managing key storage across user-level and
//! system-level credential stores, enabling daemon processes to access
//! encryption keys without embedded secrets.

use std::io::{
    Read,
    Write,
};
use std::path::{
    Path,
    PathBuf,
};

use age::secrecy::ExposeSecret;
use age::x25519;
use base64::Engine as _;

use crate::error::{
    SecretsError,
    SecretsResult,
};

/// Target credential store for key operations.
///
/// Controls where keys are saved and loaded from. Used with
/// [`SecretManager::generate_and_save`] and related methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreTarget {
    /// User-level OS credential store:
    /// - macOS: Login Keychain
    /// - Linux: kernel keyutils
    /// - Windows: Credential Manager
    OsKeychain,
    /// System-level store for daemon processes:
    /// - macOS: System Keychain (`/Library/Keychains/System.keychain`)
    /// - Linux: `/etc/dotenvage/<key-name>.key`
    /// - Windows: `%ProgramData%\dotenvage\<key-name>.key`
    ///
    /// Requires elevated privileges (sudo/admin) to write.
    SystemStore,
    /// Key file on disk at the XDG-compliant path.
    File,
    /// Both user-level OS keychain and file.
    OsKeychainAndFile,
}

/// Describes where a key was saved.
#[derive(Debug, Clone)]
pub enum KeyLocation {
    /// Saved to the user-level OS keychain.
    OsKeychain {
        /// The service name used for the keychain entry.
        service: String,
        /// The account name used for the keychain entry.
        account: String,
    },
    /// Saved to the macOS System Keychain.
    SystemKeychain {
        /// The service name used for the keychain entry.
        service: String,
        /// The account name used for the keychain entry.
        account: String,
    },
    /// Saved to a system-level protected file (Linux/Windows).
    SystemFile(PathBuf),
    /// Saved to a user-level key file.
    UserFile(PathBuf),
}

/// Options for key generation via [`SecretManager::generate_and_save`].
#[derive(Debug, Clone)]
pub struct KeyGenOptions {
    /// Where to save the generated key.
    pub target: KeyStoreTarget,
    /// Explicit key name (overrides `AGE_KEY_NAME` and `.env`
    /// file discovery). Example: `"ekg/wwkg"`.
    pub key_name: Option<String>,
    /// Explicit file path (overrides XDG path derivation).
    /// Only used when target includes [`KeyStoreTarget::File`].
    pub file_path: Option<PathBuf>,
    /// Overwrite existing key if present.
    pub force: bool,
}

/// Result of a key generation operation.
pub struct KeyGenResult {
    /// The manager holding the generated key.
    pub manager: SecretManager,
    /// Where the key was persisted.
    pub locations: Vec<KeyLocation>,
    /// Public key string (`age1...`).
    pub public_key: String,
}

impl std::fmt::Debug for KeyGenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyGenResult")
            .field("locations", &self.locations)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Manages encryption and decryption of secrets using age/X25519.
///
/// `SecretManager` provides a simple interface for encrypting and decrypting
/// sensitive values. It uses the age encryption format with X25519 keys.
///
/// Encrypted values are stored in the compact format: `ENC[AGE:b64:...]`
///
/// # Examples
///
/// ```rust
/// use dotenvage::SecretManager;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a new key
/// let manager = SecretManager::generate()?;
///
/// // Encrypt a value
/// let encrypted = manager.encrypt_value("my-secret-token")?;
/// assert!(SecretManager::is_encrypted(&encrypted));
///
/// // Decrypt it back
/// let decrypted = manager.decrypt_value(&encrypted)?;
/// assert_eq!(decrypted, "my-secret-token");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SecretManager {
    identity: x25519::Identity,
}

trait KeyBackend {
    fn load_identity_string(&self) -> SecretsResult<Option<String>>;
    fn save_identity_string(&self, _identity: &str) -> SecretsResult<()> {
        Err(SecretsError::KeySaveFailed(
            "save operation not implemented for this backend".to_string(),
        ))
    }
}

struct FileKeyBackend {
    path: PathBuf,
}

impl FileKeyBackend {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeyBackend for FileKeyBackend {
    fn load_identity_string(&self) -> SecretsResult<Option<String>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let key_data = std::fs::read_to_string(&self.path).map_err(|e| {
            SecretsError::KeyLoadFailed(format!("read {}: {}", self.path.display(), e))
        })?;
        Ok(Some(key_data))
    }

    fn save_identity_string(&self, identity: &str) -> SecretsResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                SecretsError::KeySaveFailed(format!("create dir {}: {}", parent.display(), e))
            })?;
        }

        std::fs::write(&self.path, identity.as_bytes()).map_err(|e| {
            SecretsError::KeySaveFailed(format!("write {}: {}", self.path.display(), e))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.path)
                .map_err(|e| {
                    SecretsError::KeySaveFailed(format!("metadata {}: {}", self.path.display(), e))
                })?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&self.path, perms).map_err(|e| {
                SecretsError::KeySaveFailed(format!("chmod {}: {}", self.path.display(), e))
            })?;
        }

        Ok(())
    }
}

struct OsKeychainBackend {
    service: String,
    account: String,
}

impl OsKeychainBackend {
    fn new(service: String, account: String) -> Self {
        Self { service, account }
    }
}

impl KeyBackend for OsKeychainBackend {
    fn load_identity_string(&self) -> SecretsResult<Option<String>> {
        load_from_os_keychain(&self.service, &self.account)
    }

    fn save_identity_string(&self, identity: &str) -> SecretsResult<()> {
        save_to_os_keychain(&self.service, &self.account, identity)
    }
}

fn normalize_key_data(data: &str) -> Option<String> {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(feature = "os-keychain")]
fn ensure_default_store() -> Result<(), String> {
    use std::sync::OnceLock;
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    INIT.get_or_init(|| {
        #[cfg(target_os = "macos")]
        {
            let store = apple_native_keyring_store::keychain::Store::new()
                .map_err(|e| format!("failed to init macOS keychain store: {e}"))?;
            keyring_core::set_default_store(store);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            let store = linux_keyutils_keyring_store::Store::new()
                .map_err(|e| format!("failed to init linux keyutils store: {e}"))?;
            keyring_core::set_default_store(store);
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            let store = windows_native_keyring_store::Store::new()
                .map_err(|e| format!("failed to init windows credential store: {e}"))?;
            keyring_core::set_default_store(store);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err("no OS keychain backend available for this platform".to_string())
        }
    })
    .clone()
}

#[cfg(feature = "os-keychain")]
fn load_from_os_keychain(service: &str, account: &str) -> SecretsResult<Option<String>> {
    if ensure_default_store().is_err() {
        return Ok(None);
    }
    let entry = match keyring_core::Entry::new(service, account) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    match entry.get_password() {
        Ok(password) => Ok(normalize_key_data(&password)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(keyring_core::Error::PlatformFailure(_)) => Ok(None),
        Err(e) => Err(SecretsError::KeyLoadFailed(format!(
            "OS keychain read failed (service='{}', account='{}'): {}",
            service, account, e
        ))),
    }
}

#[cfg(not(feature = "os-keychain"))]
fn load_from_os_keychain(_service: &str, _account: &str) -> SecretsResult<Option<String>> {
    Ok(None)
}

#[cfg(feature = "os-keychain")]
fn save_to_os_keychain(service: &str, account: &str, identity: &str) -> SecretsResult<()> {
    ensure_default_store().map_err(SecretsError::KeySaveFailed)?;
    let entry = keyring_core::Entry::new(service, account).map_err(|e| {
        SecretsError::KeySaveFailed(format!("failed to create keychain entry: {}", e))
    })?;
    entry.set_password(identity).map_err(|e| {
        SecretsError::KeySaveFailed(format!(
            "failed to save to OS keychain (service='{}', account='{}'): {}",
            service, account, e
        ))
    })
}

#[cfg(not(feature = "os-keychain"))]
fn save_to_os_keychain(_service: &str, _account: &str, _identity: &str) -> SecretsResult<()> {
    Err(SecretsError::KeySaveFailed(
        "OS keychain support not compiled (enable 'os-keychain' feature)".to_string(),
    ))
}

#[cfg(feature = "os-keychain")]
fn delete_from_os_keychain(service: &str, account: &str) -> SecretsResult<()> {
    ensure_default_store().map_err(SecretsError::KeySaveFailed)?;
    let entry = keyring_core::Entry::new(service, account).map_err(|e| {
        SecretsError::KeySaveFailed(format!("failed to create keychain entry: {}", e))
    })?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(e) => Err(SecretsError::KeySaveFailed(format!(
            "failed to delete from OS keychain (service='{}', account='{}'): {}",
            service, account, e
        ))),
    }
}

// ── System store backend ─────────────────────────────────────

struct SystemStoreBackend {
    key_name: String,
}

impl SystemStoreBackend {
    fn new(key_name: String) -> Self {
        Self { key_name }
    }

    #[allow(dead_code)]
    fn path(&self) -> PathBuf {
        system_store_path_for(&self.key_name)
    }
}

impl KeyBackend for SystemStoreBackend {
    fn load_identity_string(&self) -> SecretsResult<Option<String>> {
        load_from_system_store_impl(&self.key_name)
    }

    fn save_identity_string(&self, identity: &str) -> SecretsResult<()> {
        save_to_system_store_impl(&self.key_name, identity)
    }
}

/// Returns the system store path for a given key name.
///
/// When `DOTENVAGE_SYSTEM_STORE_DIR` is set, uses that directory
/// instead of the platform default. This lets daemon processes
/// store keys alongside their other configuration (e.g.
/// `/etc/myapp/` instead of `/etc/dotenvage/`).
///
/// Default directories:
/// - Unix (macOS/Linux): `/etc/dotenvage/<key-name>.key`
/// - Windows: `%ProgramData%\dotenvage\<key-name>.key`
fn system_store_path_for(_key_name: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("DOTENVAGE_SYSTEM_STORE_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join(format!("{}.key", _key_name));
    }

    #[cfg(unix)]
    {
        PathBuf::from("/etc/dotenvage").join(format!("{}.key", _key_name))
    }

    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base)
            .join("dotenvage")
            .join(format!("{}.key", _key_name))
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        PathBuf::from("/etc/dotenvage").join(format!("{}.key", _key_name))
    }
}

fn load_from_system_store_impl(key_name: &str) -> SecretsResult<Option<String>> {
    // Try the System Keychain first on macOS (interactive users).
    #[cfg(target_os = "macos")]
    if let Some(data) = load_from_macos_system_keychain(key_name)? {
        return Ok(Some(data));
    }

    // Fall back to the file-based system store on all platforms.
    // On macOS this serves daemon processes that cannot access the
    // System Keychain due to ACL restrictions.
    let path = system_store_path_for(key_name);
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| SecretsError::KeyLoadFailed(format!("read {}: {}", path.display(), e)))?;
    Ok(normalize_key_data(&data))
}

fn save_to_system_store_impl(key_name: &str, identity: &str) -> SecretsResult<()> {
    #[cfg(target_os = "macos")]
    {
        save_to_macos_system_keychain(key_name, identity)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let path = system_store_path_for(key_name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    return SecretsError::InsufficientPrivileges(format!(
                        "cannot create {}: {} (try with sudo/admin)",
                        parent.display(),
                        e
                    ));
                }
                SecretsError::KeySaveFailed(format!("create dir {}: {}", parent.display(), e))
            })?;
        }
        std::fs::write(&path, identity.as_bytes()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return SecretsError::InsufficientPrivileges(format!(
                    "cannot write {}: {} (try with sudo/admin)",
                    path.display(),
                    e
                ));
            }
            SecretsError::KeySaveFailed(format!("write {}: {}", path.display(), e))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| {
                    SecretsError::KeySaveFailed(format!("metadata {}: {}", path.display(), e))
                })?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).map_err(|e| {
                SecretsError::KeySaveFailed(format!("chmod {}: {}", path.display(), e))
            })?;
        }

        Ok(())
    }
}

/// Resolve the home directory for a given username.
fn resolve_user_home(username: &str) -> SecretsResult<PathBuf> {
    #[cfg(unix)]
    {
        use nix::unistd::User;

        let user = User::from_name(username).map_err(|e| {
            SecretsError::KeyLoadFailed(format!("failed to look up user '{}': {}", username, e))
        })?;
        match user {
            Some(u) => Ok(u.dir),
            None => Err(SecretsError::KeyLoadFailed(format!(
                "user '{}' not found",
                username
            ))),
        }
    }

    #[cfg(windows)]
    {
        // On Windows, user profiles are at C:\Users\<username>.
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        Ok(PathBuf::from(drive).join("Users").join(username))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = username;
        Err(SecretsError::KeyLoadFailed(
            "resolve_user_home not supported on this platform".to_string(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn load_from_macos_system_keychain(key_name: &str) -> SecretsResult<Option<String>> {
    use security_framework::os::macos::keychain::SecKeychain;

    let keychain = SecKeychain::open("/Library/Keychains/System.keychain")
        .map_err(|e| SecretsError::KeyLoadFailed(format!("cannot open System Keychain: {}", e)))?;

    let service = SecretManager::keychain_service_name();
    match keychain.find_generic_password(&service, key_name) {
        Ok((password, _item)) => {
            let data = String::from_utf8(password.as_ref().to_vec()).map_err(|e| {
                SecretsError::KeyLoadFailed(format!("invalid keychain data: {}", e))
            })?;
            Ok(normalize_key_data(&data))
        }
        // errSecItemNotFound = -25300
        Err(e) if e.code() == -25300 => Ok(None),
        Err(_) => Ok(None), // Keychain inaccessible (locked, permissions)
    }
}

#[cfg(target_os = "macos")]
fn save_to_macos_system_keychain(key_name: &str, identity: &str) -> SecretsResult<()> {
    use security_framework::os::macos::keychain::SecKeychain;

    let keychain = SecKeychain::open("/Library/Keychains/System.keychain")
        .map_err(|e| SecretsError::KeySaveFailed(format!("cannot open System Keychain: {e}")))?;

    let service = SecretManager::keychain_service_name();
    keychain
        .set_generic_password(&service, key_name, identity.as_bytes())
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("Authorization") || msg.contains("permission") || e.code() == -25293 {
                return SecretsError::InsufficientPrivileges(format!(
                    "cannot write to System Keychain \
                     (try with sudo): {msg}"
                ));
            }
            SecretsError::KeySaveFailed(format!(
                "failed to save to macOS System Keychain \
                 (service='{service}', account='{key_name}'): {msg}"
            ))
        })
}

/// Dotenvage configuration variables discovered from a `.env`
/// file before key loading.
struct DotenvageVars {
    /// `AGE_KEY_NAME` or `*_AGE_KEY_NAME` value.
    age_key_name: Option<String>,
    /// `DOTENVAGE_SYSTEM_STORE_DIR` value.
    system_store_dir: Option<String>,
}

impl SecretManager {
    /// Creates a new `SecretManager` by loading the key from standard
    /// locations.
    ///
    /// # Key Loading Order
    ///
    /// 0. **Auto-discover** `AGE_KEY_NAME` from `.env` or `.env.local` files
    ///    (looks for `AGE_KEY_NAME` or `*_AGE_KEY_NAME`)
    /// 1. `DOTENVAGE_AGE_KEY` environment variable (full identity string)
    /// 2. `AGE_KEY` environment variable (for compatibility)
    /// 3. `EKG_AGE_KEY` environment variable (for EKG project compatibility)
    /// 4. OS keychain entry using:
    ///    - Service: `DOTENVAGE_KEYCHAIN_SERVICE` or `dotenvage`
    ///    - Account: `AGE_KEY_NAME` or `{CARGO_PKG_NAME}/dotenvage`
    /// 5. Key file at path determined by `AGE_KEY_NAME` (e.g.,
    ///    `~/.local/state/ekg/myproject.key` if `AGE_KEY_NAME=ekg/myproject`)
    /// 6. Default key file: `~/.local/state/{CARGO_PKG_NAME}/dotenvage.key`
    ///
    /// # Errors
    ///
    /// Returns an error if no key can be found or if the key is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::SecretManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> SecretsResult<Self> {
        Self::load_key()
    }

    /// Generates a new random identity.
    ///
    /// Use this when creating a new encryption key. You'll typically want to
    /// save this key using [`save_key`](Self::save_key) or
    /// [`save_key_to_default`](Self::save_key_to_default).
    ///
    /// # Errors
    ///
    /// This function always succeeds and returns `Ok`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::SecretManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::generate()?;
    /// println!("Public key: {}", manager.public_key_string());
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate() -> SecretsResult<Self> {
        Ok(Self {
            identity: x25519::Identity::generate(),
        })
    }

    /// Creates a `SecretManager` from an existing identity.
    ///
    /// Use this when you have an age X25519 identity that you want to use
    /// directly.
    pub fn from_identity(identity: x25519::Identity) -> Self {
        Self { identity }
    }

    /// Gets the public key (recipient) corresponding to this identity.
    ///
    /// The public key can be shared with others who want to encrypt values
    /// that only you can decrypt.
    pub fn public_key(&self) -> x25519::Recipient {
        self.identity.to_public()
    }

    /// Gets the public key as a string in age format (starts with `age1`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::SecretManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::generate()?;
    /// let public_key = manager.public_key_string();
    /// assert!(public_key.starts_with("age1"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn public_key_string(&self) -> String {
        self.public_key().to_string()
    }

    /// Encrypts a plaintext value and wraps it in the format
    /// `ENC[AGE:b64:...]`.
    ///
    /// The encrypted value can be safely stored in `.env` files and version
    /// control.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::SecretManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::generate()?;
    /// let encrypted = manager.encrypt_value("sk_live_abc123")?;
    /// assert!(encrypted.starts_with("ENC[AGE:b64:"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_value(&self, plaintext: &str) -> SecretsResult<String> {
        let recipient = self.public_key();
        let recipients: Vec<&dyn age::Recipient> = vec![&recipient];
        let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
            .map_err(|e: age::EncryptError| SecretsError::EncryptionFailed(e.to_string()))?;

        let mut encrypted = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e: std::io::Error| SecretsError::EncryptionFailed(e.to_string()))?;
        writer
            .write_all(plaintext.as_bytes())
            .map_err(|e: std::io::Error| SecretsError::EncryptionFailed(e.to_string()))?;
        writer
            .finish()
            .map_err(|e: std::io::Error| SecretsError::EncryptionFailed(e.to_string()))?;

        let b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        Ok(format!("ENC[AGE:b64:{}]", b64))
    }

    /// Decrypts a value if it's encrypted; otherwise returns it unchanged.
    ///
    /// This method automatically detects whether a value is encrypted by
    /// checking for the `ENC[AGE:b64:...]` prefix or the legacy armor
    /// format. If the value is not encrypted, it's returned as-is.
    ///
    /// # Supported Formats
    ///
    /// - Compact: `ENC[AGE:b64:...]` (recommended)
    /// - Legacy: `-----BEGIN AGE ENCRYPTED FILE-----`
    ///
    /// # Errors
    ///
    /// Returns an error if the value is encrypted but decryption fails
    /// (e.g., wrong key, corrupted data).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::SecretManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::generate()?;
    ///
    /// // Decrypt an encrypted value
    /// let encrypted = manager.encrypt_value("secret")?;
    /// let decrypted = manager.decrypt_value(&encrypted)?;
    /// assert_eq!(decrypted, "secret");
    ///
    /// // Pass through unencrypted values
    /// let plain = manager.decrypt_value("not-encrypted")?;
    /// assert_eq!(plain, "not-encrypted");
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_value(&self, value: &str) -> SecretsResult<String> {
        let trimmed = value.trim();

        // Compact format: ENC[AGE:b64:...]
        if let Some(inner) = trimmed
            .strip_prefix("ENC[AGE:b64:")
            .and_then(|s| s.strip_suffix(']'))
        {
            let encrypted = base64::engine::general_purpose::STANDARD
                .decode(inner)
                .map_err(|e| SecretsError::DecryptionFailed(format!("invalid base64: {}", e)))?;

            let decryptor = age::Decryptor::new(&encrypted[..])
                .map_err(|e: age::DecryptError| SecretsError::DecryptionFailed(e.to_string()))?;
            let identities: Vec<&dyn age::Identity> = vec![&self.identity];
            let mut reader = decryptor
                .decrypt(identities.into_iter())
                .map_err(|e: age::DecryptError| SecretsError::DecryptionFailed(e.to_string()))?;

            let mut decrypted = Vec::new();
            reader
                .read_to_end(&mut decrypted)
                .map_err(|e: std::io::Error| SecretsError::DecryptionFailed(e.to_string()))?;
            return String::from_utf8(decrypted)
                .map_err(|e| SecretsError::DecryptionFailed(e.to_string()));
        }

        // Legacy armor format
        if trimmed.starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
            let armor_reader = age::armor::ArmoredReader::new(trimmed.as_bytes());
            let decryptor = age::Decryptor::new(armor_reader)
                .map_err(|e: age::DecryptError| SecretsError::DecryptionFailed(e.to_string()))?;
            let identities: Vec<&dyn age::Identity> = vec![&self.identity];
            let mut reader = decryptor
                .decrypt(identities.into_iter())
                .map_err(|e: age::DecryptError| SecretsError::DecryptionFailed(e.to_string()))?;

            let mut decrypted = Vec::new();
            reader
                .read_to_end(&mut decrypted)
                .map_err(|e: std::io::Error| SecretsError::DecryptionFailed(e.to_string()))?;
            return String::from_utf8(decrypted)
                .map_err(|e| SecretsError::DecryptionFailed(e.to_string()));
        }

        Ok(value.to_string())
    }

    /// Checks if a value is in a recognized encrypted format.
    ///
    /// Returns `true` if the value starts with `ENC[AGE:b64:` or the legacy
    /// age armor format.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::SecretManager;
    ///
    /// assert!(SecretManager::is_encrypted(
    ///     "ENC[AGE:b64:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+...]"
    /// ));
    /// assert!(!SecretManager::is_encrypted("plaintext"));
    /// ```
    pub fn is_encrypted(value: &str) -> bool {
        let t = value.trim();
        t.starts_with("ENC[AGE:b64:") || t.starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
    }

    /// Saves the private identity to a file with restricted permissions.
    ///
    /// On Unix systems, the file permissions are set to `0o600` (readable and
    /// writable only by the owner).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or written.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::SecretManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::generate()?;
    /// manager.save_key("my-key.txt")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn save_key(&self, path: impl AsRef<Path>) -> SecretsResult<()> {
        let backend = FileKeyBackend::new(path.as_ref().to_path_buf());
        backend.save_identity_string(&self.identity_string())
    }

    /// Saves the key to the default path and returns that path.
    ///
    /// The default path is typically `~/.local/state/dotenvage/dotenvage.key`
    /// on Unix systems.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or written.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::SecretManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::generate()?;
    /// let path = manager.save_key_to_default()?;
    /// println!("Key saved to: {}", path.display());
    /// # Ok(())
    /// # }
    /// ```
    pub fn save_key_to_default(&self) -> SecretsResult<PathBuf> {
        let p = Self::default_key_path();
        self.save_key(&p)?;
        Ok(p)
    }

    /// Saves the private key to the OS keychain.
    ///
    /// Uses:
    /// - Service: `DOTENVAGE_KEYCHAIN_SERVICE` or `dotenvage`
    /// - Account: `AGE_KEY_NAME` or `{CARGO_PKG_NAME}/dotenvage`
    ///
    /// Returns the `(service, account)` pair used.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be saved to the OS keychain.
    pub fn save_key_to_os_keychain(&self) -> SecretsResult<(String, String)> {
        let service = Self::keychain_service_name();
        let account = Self::key_name_from_env_or_default();
        let backend = OsKeychainBackend::new(service.clone(), account.clone());
        backend.save_identity_string(&self.identity_string())?;
        Ok((service, account))
    }

    /// Saves this key to the system-level credential store.
    ///
    /// - **macOS**: System Keychain (`/Library/Keychains/System.keychain`)
    /// - **Linux**: `/etc/dotenvage/<key-name>.key`
    /// - **Windows**: `%ProgramData%\dotenvage\<key-name>.key`
    ///
    /// Requires elevated privileges (sudo/admin).
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::InsufficientPrivileges`] if the process
    /// lacks write access to the system store.
    pub fn save_key_to_system_store(&self) -> SecretsResult<KeyLocation> {
        let key_name = Self::key_name_from_env_or_default();
        self.save_key_to_system_store_as(&key_name)
    }

    /// Saves this key to the system-level store with an explicit
    /// key name.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::InsufficientPrivileges`] if the process
    /// lacks write access to the system store.
    pub fn save_key_to_system_store_as(&self, key_name: &str) -> SecretsResult<KeyLocation> {
        let backend = SystemStoreBackend::new(key_name.to_string());
        backend.save_identity_string(&self.identity_string())?;

        #[cfg(target_os = "macos")]
        {
            let service = Self::keychain_service_name();
            Ok(KeyLocation::SystemKeychain {
                service,
                account: key_name.to_string(),
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            Ok(KeyLocation::SystemFile(backend.path()))
        }
    }

    /// Generates a new key and saves it to the specified store(s).
    ///
    /// This is the programmatic equivalent of
    /// `dotenvage keygen --store <target>`.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or saving fails, or if
    /// a key already exists and `force` is not set.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::{
    ///     KeyGenOptions,
    ///     KeyStoreTarget,
    ///     SecretManager,
    /// };
    ///
    /// let result = SecretManager::generate_and_save(KeyGenOptions {
    ///     target: KeyStoreTarget::OsKeychain,
    ///     key_name: Some("ekg/wwkg".into()),
    ///     file_path: None,
    ///     force: false,
    /// })?;
    /// println!("Public key: {}", result.public_key);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_and_save(options: KeyGenOptions) -> SecretsResult<KeyGenResult> {
        // If key_name is provided, set it in the environment so all
        // downstream path resolution uses it.
        if let Some(ref name) = options.key_name {
            unsafe {
                std::env::set_var("AGE_KEY_NAME", name);
            }
        } else {
            Self::discover_age_key_name_from_env_files()?;
        }

        let manager = Self::generate()?;
        let mut locations = Vec::new();

        match options.target {
            KeyStoreTarget::File => {
                let path = options
                    .file_path
                    .unwrap_or_else(Self::key_path_from_env_or_default);
                if path.exists() && !options.force {
                    return Err(SecretsError::KeyAlreadyExists(format!(
                        "key file at {}",
                        path.display()
                    )));
                }
                manager.save_key(&path)?;
                locations.push(KeyLocation::UserFile(path));
            }
            KeyStoreTarget::OsKeychain => {
                let (service, account) = manager.save_key_to_os_keychain()?;
                locations.push(KeyLocation::OsKeychain { service, account });
            }
            KeyStoreTarget::SystemStore => {
                let key_name = Self::key_name_from_env_or_default();
                let loc = manager.save_key_to_system_store_as(&key_name)?;
                locations.push(loc);
            }
            KeyStoreTarget::OsKeychainAndFile => {
                let (service, account) = manager.save_key_to_os_keychain()?;
                locations.push(KeyLocation::OsKeychain { service, account });
                let path = options
                    .file_path
                    .unwrap_or_else(Self::key_path_from_env_or_default);
                if path.exists() && !options.force {
                    return Err(SecretsError::KeyAlreadyExists(format!(
                        "key file at {}",
                        path.display()
                    )));
                }
                manager.save_key(&path)?;
                locations.push(KeyLocation::UserFile(path));
            }
        }

        let public_key = manager.public_key_string();
        Ok(KeyGenResult {
            manager,
            locations,
            public_key,
        })
    }

    /// Loads the key specifically from the system-level store.
    ///
    /// Unlike [`new`](Self::new) which tries the full discovery
    /// chain, this only checks the system store.
    ///
    /// # Errors
    ///
    /// Returns an error if no key is found in the system store.
    pub fn load_from_system_store() -> SecretsResult<Self> {
        Self::discover_age_key_name_from_env_files()?;
        let key_name = Self::key_name_from_env_or_default();
        let backend = SystemStoreBackend::new(key_name.clone());
        match backend.load_identity_string()? {
            Some(data) => Self::load_from_string(&data),
            None => Err(SecretsError::KeyLoadFailed(format!(
                "no key found in system store for '{}'",
                key_name
            ))),
        }
    }

    /// Loads a key from another user's file store.
    ///
    /// Resolves the key file path for `~<username>/.local/state/...`
    /// based on the current `AGE_KEY_NAME`. This is intended for use
    /// during `sudo` operations where the invoking user's key needs
    /// to be read by the elevated process.
    ///
    /// # Errors
    ///
    /// Returns an error if the user's home directory cannot be
    /// resolved or no key file is found.
    pub fn load_from_user(username: &str) -> SecretsResult<Self> {
        Self::discover_age_key_name_from_env_files()?;
        let key_name = Self::key_name_from_env_or_default();

        let home = resolve_user_home(username)?;
        let key_path = home
            .join(".local/state")
            .join(&key_name)
            .with_extension("key");

        let backend = FileKeyBackend::new(key_path.clone());
        match backend.load_identity_string()? {
            Some(data) => Self::load_from_string(&data),
            None => Err(SecretsError::KeyLoadFailed(format!(
                "no key file for user '{}' at {}",
                username,
                key_path.display()
            ))),
        }
    }

    /// Checks whether a key exists in the OS user keychain.
    pub fn key_exists_in_os_keychain() -> bool {
        let _ = Self::discover_age_key_name_from_env_files();
        let key_name = Self::key_name_from_env_or_default();
        let service = Self::keychain_service_name();
        let backend = OsKeychainBackend::new(service, key_name);
        matches!(backend.load_identity_string(), Ok(Some(_)))
    }

    /// Checks whether a key exists in the system-level store.
    pub fn key_exists_in_system_store() -> bool {
        let _ = Self::discover_age_key_name_from_env_files();
        let key_name = Self::key_name_from_env_or_default();
        let backend = SystemStoreBackend::new(key_name);
        matches!(backend.load_identity_string(), Ok(Some(_)))
    }

    /// Deletes the key from the OS user keychain.
    ///
    /// # Errors
    ///
    /// Returns an error if the deletion fails. Does not error if
    /// no key exists.
    #[cfg(feature = "os-keychain")]
    pub fn delete_from_os_keychain() -> SecretsResult<()> {
        let _ = Self::discover_age_key_name_from_env_files();
        let key_name = Self::key_name_from_env_or_default();
        let service = Self::keychain_service_name();
        delete_from_os_keychain(&service, &key_name)
    }

    /// Returns the system store path for the current platform
    /// and key name.
    ///
    /// - **macOS**: `/Library/Keychains/System.keychain`
    /// - **Linux**: `/etc/dotenvage/<key-name>.key`
    /// - **Windows**: `%ProgramData%\dotenvage\<key-name>.key`
    pub fn system_store_path() -> PathBuf {
        let _ = Self::discover_age_key_name_from_env_files();
        let key_name = Self::key_name_from_env_or_default();
        system_store_path_for(&key_name)
    }

    /// Loads the identity from standard locations.
    ///
    /// This is called internally by [`new`](Self::new).
    ///
    /// ## Key Loading Priority
    ///
    /// 0. Read .env files to discover `AGE_KEY_NAME` (or `*_AGE_KEY_NAME`) for
    ///    project-specific keys
    /// 1. `DOTENVAGE_AGE_KEY` env var (full identity string)
    /// 2. `AGE_KEY` env var (full identity string)
    /// 3. `EKG_AGE_KEY` env var (for EKG project compatibility)
    /// 4. OS user keychain (via `keyring` crate)
    /// 5. System-level store (macOS System Keychain, or
    ///    `/etc/dotenvage/<key>.key` on Linux,
    ///    `%ProgramData%\dotenvage\<key>.key` on Windows)
    /// 6. Key file at path determined by `AGE_KEY_NAME` from .env or
    ///    environment
    /// 7. Default key file: `~/.local/state/{CARGO_PKG_NAME or
    ///    "dotenvage"}/dotenvage.key`
    ///
    /// # Errors
    ///
    /// Returns an error if no key can be found in any of the standard
    /// locations or if the key file/string is invalid.
    pub fn load_key() -> SecretsResult<Self> {
        // FIRST: Try to discover AGE_KEY_NAME from .env files before
        // doing anything else. This allows project-specific key
        // discovery from .env configuration.
        Self::discover_age_key_name_from_env_files()?;

        if let Ok(data) = std::env::var("DOTENVAGE_AGE_KEY") {
            return Self::load_from_string(&data);
        }
        if let Ok(data) = std::env::var("AGE_KEY") {
            return Self::load_from_string(&data);
        }
        if let Ok(data) = std::env::var("EKG_AGE_KEY") {
            return Self::load_from_string(&data);
        }

        // Step 4: OS user keychain
        let key_name = Self::key_name_from_env_or_default();
        let keychain_service = Self::keychain_service_name();
        let os_keychain_backend = OsKeychainBackend::new(keychain_service, key_name.clone());
        if let Some(data) = os_keychain_backend.load_identity_string()? {
            return Self::load_from_string(&data);
        }

        // Step 5: System-level store
        let system_backend = SystemStoreBackend::new(key_name);
        if let Some(data) = system_backend.load_identity_string()? {
            return Self::load_from_string(&data);
        }

        // Step 6-7: File-based key
        let key_path = Self::key_path_from_env_or_default();
        let file_backend = FileKeyBackend::new(key_path.clone());
        if let Some(data) = file_backend.load_identity_string()? {
            return Self::load_from_string(&data);
        }
        Err(SecretsError::KeyLoadFailed(format!(
            "no key found (env vars, OS keychain, system store, \
             or key file at {})",
            key_path.display()
        )))
    }

    /// Attempts to discover AGE_KEY_NAME from .env files in the current
    /// directory.
    ///
    /// This reads .env files (without decryption) to find AGE_KEY_NAME or
    /// *_AGE_KEY_NAME variables and sets them in the environment so they
    /// can be used for key path resolution.
    ///
    /// Priority order for .env files:
    /// 1. .env.local
    /// 2. .env
    ///
    /// # Errors
    ///
    /// Returns an error if an AGE key name variable (e.g., `EKG_AGE_KEY_NAME`)
    /// is found but encrypted. AGE key name variables must be plaintext because
    /// they are needed for key discovery, which happens before decryption.
    pub fn discover_age_key_name_from_env_files() -> SecretsResult<()> {
        // Try to read .env.local first, then .env
        let env_files = [".env.local", ".env"];

        for env_file in &env_files {
            let vars = Self::find_dotenvage_vars_in_file(env_file)?;
            if let Some(key_name) = vars.age_key_name
                && std::env::var("AGE_KEY_NAME").is_err()
            {
                // SAFETY: called during single-threaded startup.
                unsafe {
                    std::env::set_var("AGE_KEY_NAME", key_name);
                }
            }
            if let Some(dir) = vars.system_store_dir
                && std::env::var("DOTENVAGE_SYSTEM_STORE_DIR").is_err()
            {
                unsafe {
                    std::env::set_var("DOTENVAGE_SYSTEM_STORE_DIR", dir);
                }
            }
        }

        Ok(())
    }

    /// Searches a single `.env` file for dotenvage configuration
    /// variables that must be resolved before key loading.
    ///
    /// Discovered variables:
    /// - `AGE_KEY_NAME` or `*_AGE_KEY_NAME` — determines which key file or
    ///   keychain account to load.
    /// - `DOTENVAGE_SYSTEM_STORE_DIR` — overrides the directory for the
    ///   file-based system store (default `/etc/dotenvage/`).
    ///
    /// # Errors
    ///
    /// Returns an error if an AGE key name variable is found but
    /// encrypted.
    fn find_dotenvage_vars_in_file(file_path: &str) -> SecretsResult<DotenvageVars> {
        let mut vars = DotenvageVars {
            age_key_name: None,
            system_store_dir: None,
        };

        let Ok(content) = std::fs::read_to_string(file_path) else {
            return Ok(vars);
        };

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim().trim_matches('"').trim_matches('\'');

            if (key == "AGE_KEY_NAME" || key.ends_with("_AGE_KEY_NAME")) && !value.is_empty() {
                if Self::is_encrypted(value) {
                    return Err(SecretsError::KeyLoadFailed(format!(
                        "found encrypted AGE key name variable \
                         '{key}' in {file_path}: AGE key name \
                         variables must be plaintext because they \
                         are used to discover the encryption key."
                    )));
                }
                vars.age_key_name = Some(value.to_string());
            }

            if key == "DOTENVAGE_SYSTEM_STORE_DIR" && !value.is_empty() {
                vars.system_store_dir = Some(value.to_string());
            }
        }

        Ok(vars)
    }

    fn load_from_string(data: &str) -> SecretsResult<Self> {
        let identity = data
            .parse::<x25519::Identity>()
            .map_err(|e| SecretsError::KeyLoadFailed(format!("parse key: {}", e)))?;
        Ok(Self { identity })
    }

    /// Returns the raw identity string (`AGE-SECRET-KEY-1...`).
    ///
    /// Use this when you need to embed the key in a service definition
    /// for environments where keychain access is unavailable (e.g.,
    /// containers). Handle the returned string carefully — it is the
    /// private key in plaintext.
    pub fn identity_string(&self) -> String {
        self.identity.to_string().expose_secret().to_string()
    }

    fn key_name_from_env_or_default() -> String {
        std::env::var("AGE_KEY_NAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                // Default to CARGO_PKG_NAME/dotenvage for project-specific keys
                format!("{}/dotenvage", env!("CARGO_PKG_NAME"))
            })
    }

    fn keychain_service_name() -> String {
        std::env::var("DOTENVAGE_KEYCHAIN_SERVICE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "dotenvage".to_string())
    }

    /// Returns the key path based on AGE_KEY_NAME or project default.
    ///
    /// ## Priority:
    /// 1. If `AGE_KEY_NAME` is set in environment (e.g., from .env), use it
    /// 2. Otherwise default to `{CARGO_PKG_NAME}/dotenvage`
    ///
    /// ## Path Construction:
    /// - XDG-compliant: `$XDG_STATE_HOME/{name}.key`
    /// - Fallback: `~/.local/state/{name}.key`
    ///
    /// ## Examples
    ///
    /// With `AGE_KEY_NAME=myapp/production` in .env:
    /// - Returns: `~/.local/state/myapp/production.key`
    ///
    /// Without AGE_KEY_NAME (default for "ekg-backend" crate):
    /// - Returns: `~/.local/state/ekg-backend/dotenvage.key`
    pub fn key_path_from_env_or_default() -> PathBuf {
        let key_name = Self::key_name_from_env_or_default();

        // Construct XDG-compliant path
        Self::xdg_base_dir_for(&key_name)
            .unwrap_or_else(|| PathBuf::from(".").join(&key_name))
            .with_extension("key")
    }

    /// Returns the default key path (for backward compatibility).
    ///
    /// Prefer using `key_path_from_env_or_default()` which respects
    /// AGE_KEY_NAME.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::SecretManager;
    ///
    /// let path = SecretManager::default_key_path();
    /// println!("Default key path: {}", path.display());
    /// ```
    pub fn default_key_path() -> PathBuf {
        Self::xdg_base_dir_for("dotenvage")
            .unwrap_or_else(|| PathBuf::from(".").join("dotenvage"))
            .join("dotenvage.key")
    }

    fn xdg_base_dir_for(name: &str) -> Option<PathBuf> {
        if let Ok(p) = std::env::var("XDG_STATE_HOME")
            && !p.is_empty()
        {
            return Some(PathBuf::from(p).join(name));
        }
        if let Ok(p) = std::env::var("XDG_CONFIG_HOME")
            && !p.is_empty()
        {
            return Some(PathBuf::from(p).join(name));
        }
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(home);
            let state_dir = home_path.join(".local/state").join(name);
            // Prefer state dir unless config dir already exists
            if state_dir.exists() || !home_path.join(".config").join(name).exists() {
                return Some(state_dir);
            }
            return Some(home_path.join(".config").join(name));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let manager = SecretManager::generate().expect("failed to generate manager");
        let plaintext = "sk_live_abc123";
        let encrypted = manager.encrypt_value(plaintext).expect("encryption failed");
        assert!(SecretManager::is_encrypted(&encrypted));
        let decrypted = manager
            .decrypt_value(&encrypted)
            .expect("decryption failed");
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_unencrypted_value() {
        let manager = SecretManager::generate().expect("failed to generate manager");
        let plaintext = "not_encrypted";
        let result = manager
            .decrypt_value(plaintext)
            .expect("decrypt should pass through");
        assert_eq!(plaintext, result);
    }

    #[test]
    #[serial]
    fn test_key_path_from_env_or_default_with_age_key_name() {
        // This test must clear ALL env vars that affect key path discovery
        let orig_age_key_name = std::env::var("AGE_KEY_NAME").ok();
        let orig_xdg_state = std::env::var("XDG_STATE_HOME").ok();
        let orig_xdg_config = std::env::var("XDG_CONFIG_HOME").ok();

        // Test with AGE_KEY_NAME set
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME"); // Clear any XDG_CONFIG_HOME
            std::env::set_var("AGE_KEY_NAME", "myproject/myapp");
            std::env::set_var("XDG_STATE_HOME", "/tmp/xdg-state");
        }

        let path = SecretManager::key_path_from_env_or_default();
        assert_eq!(
            path,
            std::path::PathBuf::from("/tmp/xdg-state/myproject/myapp.key")
        );

        // Restore env
        unsafe {
            std::env::remove_var("AGE_KEY_NAME");
            std::env::remove_var("XDG_STATE_HOME");
            if let Some(val) = orig_age_key_name {
                std::env::set_var("AGE_KEY_NAME", val);
            }
            if let Some(val) = orig_xdg_state {
                std::env::set_var("XDG_STATE_HOME", val);
            }
            if let Some(val) = orig_xdg_config {
                std::env::set_var("XDG_CONFIG_HOME", val);
            }
        }
    }

    #[test]
    #[serial]
    fn test_key_path_from_env_or_default_without_age_key_name() {
        // Save original env
        let orig_age_key_name = std::env::var("AGE_KEY_NAME").ok();
        let orig_xdg_state = std::env::var("XDG_STATE_HOME").ok();
        let orig_xdg_config = std::env::var("XDG_CONFIG_HOME").ok();

        // Test without AGE_KEY_NAME - should default to CARGO_PKG_NAME/dotenvage
        unsafe {
            std::env::remove_var("AGE_KEY_NAME");
            std::env::remove_var("XDG_CONFIG_HOME"); // Clear any XDG_CONFIG_HOME
            std::env::set_var("XDG_STATE_HOME", "/tmp/xdg-state");
        }

        let path = SecretManager::key_path_from_env_or_default();
        let expected = format!("/tmp/xdg-state/{}/dotenvage.key", env!("CARGO_PKG_NAME"));
        assert_eq!(path, std::path::PathBuf::from(expected));

        // Restore env
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            if let Some(val) = orig_age_key_name {
                std::env::set_var("AGE_KEY_NAME", val);
            }
            if let Some(val) = orig_xdg_state {
                std::env::set_var("XDG_STATE_HOME", val);
            }
            if let Some(val) = orig_xdg_config {
                std::env::set_var("XDG_CONFIG_HOME", val);
            }
        }
    }

    #[test]
    #[serial]
    fn test_key_name_from_env_or_default() {
        let orig_age_key_name = std::env::var("AGE_KEY_NAME").ok();

        unsafe {
            std::env::set_var("AGE_KEY_NAME", "myproject/prod");
        }
        assert_eq!(
            SecretManager::key_name_from_env_or_default(),
            "myproject/prod"
        );

        unsafe {
            std::env::set_var("AGE_KEY_NAME", "   ");
        }
        assert_eq!(
            SecretManager::key_name_from_env_or_default(),
            format!("{}/dotenvage", env!("CARGO_PKG_NAME"))
        );

        unsafe {
            if let Some(val) = orig_age_key_name {
                std::env::set_var("AGE_KEY_NAME", val);
            } else {
                std::env::remove_var("AGE_KEY_NAME");
            }
        }
    }

    #[test]
    #[serial]
    fn test_keychain_service_name() {
        let orig = std::env::var("DOTENVAGE_KEYCHAIN_SERVICE").ok();

        unsafe {
            std::env::set_var("DOTENVAGE_KEYCHAIN_SERVICE", "team-secrets");
        }
        assert_eq!(SecretManager::keychain_service_name(), "team-secrets");

        unsafe {
            std::env::set_var("DOTENVAGE_KEYCHAIN_SERVICE", "   ");
        }
        assert_eq!(SecretManager::keychain_service_name(), "dotenvage");

        unsafe {
            if let Some(val) = orig {
                std::env::set_var("DOTENVAGE_KEYCHAIN_SERVICE", val);
            } else {
                std::env::remove_var("DOTENVAGE_KEYCHAIN_SERVICE");
            }
        }
    }

    #[test]
    #[serial]
    fn test_xdg_base_dir_for() {
        // Save original env
        let orig_xdg_state = std::env::var("XDG_STATE_HOME").ok();
        let orig_xdg_config = std::env::var("XDG_CONFIG_HOME").ok();
        let orig_home = std::env::var("HOME").ok();

        // Test with XDG_STATE_HOME
        unsafe {
            std::env::set_var("XDG_STATE_HOME", "/custom/state");
        }
        let path = SecretManager::xdg_base_dir_for("test");
        assert_eq!(path, Some(std::path::PathBuf::from("/custom/state/test")));

        // Test with HOME fallback
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::set_var("HOME", "/home/user");
        }
        let path = SecretManager::xdg_base_dir_for("test");
        assert_eq!(
            path,
            Some(std::path::PathBuf::from("/home/user/.local/state/test"))
        );

        // Restore env
        unsafe {
            if let Some(val) = orig_xdg_state {
                std::env::set_var("XDG_STATE_HOME", val);
            } else {
                std::env::remove_var("XDG_STATE_HOME");
            }
            if let Some(val) = orig_xdg_config {
                std::env::set_var("XDG_CONFIG_HOME", val);
            } else {
                std::env::remove_var("XDG_CONFIG_HOME");
            }
            if let Some(val) = orig_home {
                std::env::set_var("HOME", val);
            } else {
                std::env::remove_var("HOME");
            }
        }
    }
}
