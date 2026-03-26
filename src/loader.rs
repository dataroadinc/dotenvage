//! Environment loader with automatic secret decryption.
//!
//! This module provides [`EnvLoader`] for loading and decrypting environment
//! files, and [`AutoDetectPatterns`] for automatically identifying sensitive
//! variables.

use std::collections::{
    HashMap,
    HashSet,
};
use std::io::Write;
use std::path::{
    Path,
    PathBuf,
};

use crate::error::{
    SecretsError,
    SecretsResult,
};
use crate::manager::SecretManager;

/// Supported CPU architectures for file naming.
///
/// These are the canonical architecture names used in `.env.<ARCH>` file
/// patterns. Input values are normalized to these canonical forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// AMD64/x86-64 architecture
    ///
    /// Matches: `amd64`, `x64`, `x86_64`
    Amd64,

    /// ARM64/AArch64 architecture
    ///
    /// Matches: `arm64`, `aarch64`
    Arm64,

    /// 32-bit ARM architecture
    ///
    /// Matches: `arm`, `armv7`, `armv7l`
    Arm,

    /// 32-bit x86 architecture
    ///
    /// Matches: `i386`, `i686`, `x86`
    I386,

    /// RISC-V 64-bit architecture
    ///
    /// Matches: `riscv64`, `riscv64gc`
    Riscv64,

    /// PowerPC 64-bit Little Endian
    ///
    /// Matches: `ppc64le`, `powerpc64le`
    Ppc64le,

    /// IBM System/390 (s390x)
    ///
    /// Matches: `s390x`
    S390x,
}

impl Arch {
    /// Returns the canonical file name suffix for this architecture.
    ///
    /// This is the value used in `.env.<ARCH>` file patterns.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
            Self::Arm => "arm",
            Self::I386 => "i386",
            Self::Riscv64 => "riscv64",
            Self::Ppc64le => "ppc64le",
            Self::S390x => "s390x",
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Arch {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lower = s.to_lowercase();
        match s_lower.as_str() {
            // AMD64 / x86-64 - NO DOTS ALLOWED
            "amd64" | "x64" | "x86_64" => Ok(Self::Amd64),
            // ARM64 / AArch64
            "arm64" | "aarch64" => Ok(Self::Arm64),
            // 32-bit ARM
            "arm" | "armv7" | "armv7l" | "armhf" => Ok(Self::Arm),
            // 32-bit x86
            "i386" | "i686" | "x86" => Ok(Self::I386),
            // RISC-V 64
            "riscv64" | "riscv64gc" => Ok(Self::Riscv64),
            // PowerPC 64 LE
            "ppc64le" | "powerpc64le" => Ok(Self::Ppc64le),
            // s390x
            "s390x" => Ok(Self::S390x),
            _ => Err(()),
        }
    }
}

/// Supported operating systems for file naming.
///
/// These are the canonical OS names used in `.env.<OS>` file patterns.
/// Input values are normalized to these canonical forms.
///
/// **Important**: Canonical values must NOT contain dots to maintain
/// unambiguous parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux
    ///
    /// Matches: `linux`
    Linux,

    /// macOS / Darwin
    ///
    /// Matches: `macos`, `darwin`, `osx`
    Macos,

    /// Windows
    ///
    /// Matches: `windows`, `win32`, `win`
    Windows,

    /// FreeBSD
    ///
    /// Matches: `freebsd`
    Freebsd,

    /// OpenBSD
    ///
    /// Matches: `openbsd`
    Openbsd,

    /// NetBSD
    ///
    /// Matches: `netbsd`
    Netbsd,

    /// Android
    ///
    /// Matches: `android`
    Android,

    /// iOS
    ///
    /// Matches: `ios`
    Ios,
}

impl Os {
    /// Returns the canonical file name suffix for this OS.
    ///
    /// This is the value used in `.env.<OS>` file patterns.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Freebsd => "freebsd",
            Self::Openbsd => "openbsd",
            Self::Netbsd => "netbsd",
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Os {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lower = s.to_lowercase();
        match s_lower.as_str() {
            "linux" => Ok(Self::Linux),
            "macos" | "darwin" | "osx" => Ok(Self::Macos),
            "windows" | "win32" | "win" => Ok(Self::Windows),
            "freebsd" => Ok(Self::Freebsd),
            "openbsd" => Ok(Self::Openbsd),
            "netbsd" => Ok(Self::Netbsd),
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            _ => Err(()),
        }
    }
}

/// Loads environment files with automatic decryption of encrypted values.
///
/// `EnvLoader` reads `.env` files in a specific order and automatically
/// decrypts any encrypted values it encounters. It supports multiple
/// environment variants and user-specific configuration files.
///
/// # Examples
///
/// ```rust,no_run
/// use dotenvage::EnvLoader;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Load from current directory
/// let loaded_files = EnvLoader::new()?.load()?;
/// println!("Loaded {} .env files", loaded_files.len());
///
/// // Now encrypted values are available via std::env::var
/// let api_key = std::env::var("API_KEY")?;
/// # Ok(())
/// # }
/// ```
///
/// # File Loading Order
///
/// Files are loaded in the following order (later files override earlier ones):
///
/// 1. `.env` - Base configuration
/// 2. `.env.<ENV>` - Environment-specific
/// 3. `.env.<ENV>.<ARCH>` - Architecture-specific (if `<ARCH>` is set)
/// 4. `.env.<USER>` - User-specific overrides (if `<USER>` is set)
/// 5. `.env.<ENV>.<USER>` - User overrides for specific environment
/// 6. `.env.<ENV>.<ARCH>.<USER>` - User overrides for env+arch combo
/// 7. `.env.<VARIANT>` - Variant-specific (e.g., docker, kubernetes)
/// 8. `.env.pr-<PR_NUMBER>` - PR-specific (GitHub Actions only)
///
/// **Note**: Separators can be either `.` or `-` (e.g., `.env.local` or
/// `.env-local`)
///
/// # Placeholders
///
/// The following placeholders are resolved from environment variables:
///
/// - **`<ENV>`**: Environment name (see [`resolve_env()`](Self::resolve_env))
/// - **`<OS>`**: Operating system (see [`resolve_os()`](Self::resolve_os))
/// - **`<ARCH>`**: Architecture name (see
///   [`resolve_arch()`](Self::resolve_arch))
/// - **`<USER>`**: Username (see [`resolve_user()`](Self::resolve_user))
/// - **`<VARIANT>`**: Deployment variant (see
///   [`resolve_variant()`](Self::resolve_variant))
/// - **`<PR_NUMBER>`**: Pull request number (see
///   [`resolve_pr_number()`](Self::resolve_pr_number))
pub struct EnvLoader {
    manager: SecretManager,
}

impl EnvLoader {
    fn find_file_case_insensitive(dir: &Path, filename: &str) -> Option<PathBuf> {
        let target = filename.to_lowercase();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().to_lowercase() == target {
                    return Some(entry.path());
                }
            }
        }
        None
    }

    fn add_exact_if_exist(dir: &Path, paths: &mut Vec<PathBuf>, filename: &str) {
        if let Some(p) = Self::find_file_case_insensitive(dir, filename)
            && !paths.iter().any(|x| x == &p)
        {
            paths.push(p);
        }
    }

    /// Creates a new `EnvLoader` with a default `SecretManager`.
    ///
    /// This will load the encryption key from standard locations:
    /// 0. **Auto-discover** `AGE_KEY_NAME` from `.env` or `.env.local` files
    /// 1. `DOTENVAGE_AGE_KEY` environment variable (full identity string)
    /// 2. `AGE_KEY` environment variable
    /// 3. Key file at path determined by discovered `AGE_KEY_NAME`
    /// 4. Default key file at XDG path (e.g.,
    ///    `~/.local/state/dotenvage/dotenvage.key`)
    ///
    /// # Errors
    ///
    /// Returns an error if no encryption key can be found or loaded.
    pub fn new() -> SecretsResult<Self> {
        Ok(Self {
            manager: SecretManager::new()?,
        })
    }

    /// Creates an `EnvLoader` with a specific `SecretManager`.
    ///
    /// Use this when you want to provide your own encryption key.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::{
    ///     EnvLoader,
    ///     SecretManager,
    /// };
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = SecretManager::generate()?;
    /// let loader = EnvLoader::with_manager(manager);
    /// let loaded_files = loader.load()?;
    /// println!("Loaded {} .env files", loaded_files.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_manager(manager: SecretManager) -> Self {
        Self { manager }
    }

    /// Loads `.env` files from the current directory in standard order.
    ///
    /// Decrypted values are loaded into the process environment and can be
    /// accessed via `std::env::var()`.
    ///
    /// # Errors
    ///
    /// Returns an error if any file cannot be read or parsed, or if
    /// decryption fails for any encrypted value.
    ///
    /// # Returns
    ///
    /// Returns the list of file paths that were actually loaded, in load order.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::EnvLoader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let loaded_files = EnvLoader::new()?.load()?;
    /// println!("Loaded {} .env files", loaded_files.len());
    /// let secret = std::env::var("API_TOKEN")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn load(&self) -> SecretsResult<Vec<PathBuf>> {
        self.load_from_dir(".")
    }

    /// Loads `.env` files from a specific directory using the same order as
    /// [`load`](Self::load).
    ///
    /// This method implements **dynamic dimension discovery**: dimension
    /// configuration values (like `NODE_ENV=production` or `VARIANT=docker`)
    /// found in loaded files can cause additional files to be loaded.
    ///
    /// The loading algorithm:
    /// 1. Load `.env` first (if it exists)
    /// 2. Discover dimension configs from loaded values and set in environment
    /// 3. Iteratively:
    ///    - Compute file paths based on current dimension values
    ///    - Find next unloaded file in specificity order
    ///    - If none, break
    ///    - Load file, discover new dimensions, update environment
    /// 4. Set all accumulated variables in the process environment
    ///
    /// Files are never loaded twice - a `HashSet` tracks loaded paths.
    ///
    /// # Returns
    ///
    /// Returns the list of file paths that were actually loaded, in load order.
    ///
    /// # Errors
    ///
    /// Returns an error if any file cannot be read or parsed, or if
    /// decryption fails for any encrypted value.
    pub fn load_from_dir(&self, dir: impl AsRef<Path>) -> SecretsResult<Vec<PathBuf>> {
        let dir = dir.as_ref();
        let mut env_vars = HashMap::new();
        let mut loaded_files: HashSet<PathBuf> = HashSet::new();
        let mut loaded_order: Vec<PathBuf> = Vec::new();

        // Step 1: Load base .env first
        if let Some(base_path) = Self::find_file_case_insensitive(dir, ".env")
            && base_path.exists()
        {
            let vars = self.load_env_file(&base_path)?;
            env_vars.extend(vars.clone());
            loaded_order.push(base_path.clone());
            loaded_files.insert(base_path);

            // Step 2: Discover dimensions from base file
            for (key, value) in Self::discover_dimensions_from_vars(&vars) {
                unsafe {
                    std::env::set_var(&key, &value);
                }
            }
        }

        // Step 3: Iteratively load files and discover new dimensions
        loop {
            // Compute paths based on current dimension values
            let candidate_paths = self.resolve_env_paths(dir);

            // Find next unloaded file in specificity order
            let next_file = candidate_paths
                .into_iter()
                .find(|p| !loaded_files.contains(p) && p.exists());

            let Some(path) = next_file else {
                break;
            };

            // Load the file
            let vars = self.load_env_file(&path)?;
            env_vars.extend(vars.clone());
            loaded_order.push(path.clone());
            loaded_files.insert(path);

            // Discover new dimensions from this file
            for (key, value) in Self::discover_dimensions_from_vars(&vars) {
                unsafe {
                    std::env::set_var(&key, &value);
                }
            }
        }

        // Step 4: Set all accumulated variables in process environment
        for (k, v) in env_vars {
            unsafe {
                std::env::set_var(k, v);
            }
        }
        Ok(loaded_order)
    }

    /// Collects all environment variables from `.env` files using dynamic
    /// dimension discovery, without modifying the process environment.
    ///
    /// This method implements the same **dynamic dimension discovery** as
    /// [`load_from_dir`](Self::load_from_dir), but returns the collected
    /// variables instead of setting them in the environment.
    ///
    /// Use this method when you need the merged variables for inspection
    /// (e.g., `list` or `dump` commands) without side effects.
    ///
    /// # Returns
    ///
    /// A tuple of (variables, loaded_paths) where:
    /// - `variables` is a HashMap of all decrypted key-value pairs
    /// - `loaded_paths` is the list of file paths that were loaded, in order
    ///
    /// # Errors
    ///
    /// Returns an error if any file cannot be read or parsed, or if
    /// decryption fails for any encrypted value.
    pub fn collect_all_vars_from_dir(
        &self,
        dir: impl AsRef<Path>,
    ) -> SecretsResult<(HashMap<String, String>, Vec<PathBuf>)> {
        let dir = dir.as_ref();
        let mut env_vars = HashMap::new();
        let mut loaded_files: HashSet<PathBuf> = HashSet::new();
        let mut loaded_order: Vec<PathBuf> = Vec::new();

        // Save current environment state for dimension variables
        let saved_env = Self::save_dimension_env_vars();

        // Step 1: Load base .env first
        if let Some(base_path) = Self::find_file_case_insensitive(dir, ".env")
            && base_path.exists()
        {
            let vars = self.load_env_file(&base_path)?;
            env_vars.extend(vars.clone());
            loaded_order.push(base_path.clone());
            loaded_files.insert(base_path);

            // Step 2: Discover dimensions from base file
            for (key, value) in Self::discover_dimensions_from_vars(&vars) {
                unsafe {
                    std::env::set_var(&key, &value);
                }
            }
        }

        // Step 3: Iteratively load files and discover new dimensions
        loop {
            // Compute paths based on current dimension values
            let candidate_paths = self.resolve_env_paths(dir);

            // Find next unloaded file in specificity order
            let next_file = candidate_paths
                .into_iter()
                .find(|p| !loaded_files.contains(p) && p.exists());

            let Some(path) = next_file else {
                break;
            };

            // Load the file
            let vars = self.load_env_file(&path)?;
            env_vars.extend(vars.clone());
            loaded_order.push(path.clone());
            loaded_files.insert(path);

            // Discover new dimensions from this file
            for (key, value) in Self::discover_dimensions_from_vars(&vars) {
                unsafe {
                    std::env::set_var(&key, &value);
                }
            }
        }

        // Restore original environment state
        Self::restore_dimension_env_vars(&saved_env);

        Ok((env_vars, loaded_order))
    }

    /// Saves the current values of dimension environment variables.
    fn save_dimension_env_vars() -> HashMap<String, Option<String>> {
        let keys = [
            "DOTENVAGE_ENV",
            "EKG_ENV",
            "VERCEL_ENV",
            "NODE_ENV",
            "DOTENVAGE_OS",
            "EKG_OS",
            "DOTENVAGE_ARCH",
            "EKG_ARCH",
            "DOTENVAGE_USER",
            "EKG_USER",
            "DOTENVAGE_VARIANT",
            "EKG_VARIANT",
            "VARIANT",
        ];
        keys.iter()
            .map(|&k| (k.to_string(), std::env::var(k).ok()))
            .collect()
    }

    /// Restores dimension environment variables to their saved state.
    fn restore_dimension_env_vars(saved: &HashMap<String, Option<String>>) {
        for (key, value) in saved {
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// Computes the ordered list of env file paths to load.
    ///
    /// This method uses a **power-set generation** approach: it resolves ENV,
    /// OS, ARCH, USER, and VARIANT from the environment, then generates all
    /// possible combinations of these values (maintaining canonical order:
    /// ENV, OS, ARCH, USER, VARIANT).
    ///
    /// Files are loaded in specificity order - more parts means more specific,
    /// which means higher precedence.
    ///
    /// # Returns
    ///
    /// A vector of paths in load order (later paths override earlier ones).
    ///
    /// # Examples
    ///
    /// With `ENV=local`, `OS=linux`, `ARCH=amd64`, `USER=alice`,
    /// `VARIANT=docker`, this generates all combinations like:
    /// - `.env`
    /// - `.env.local`
    /// - `.env.linux`
    /// - `.env.amd64`
    /// - `.env.alice`
    /// - `.env.docker`
    /// - `.env.local.linux`
    /// - `.env.local.docker`
    /// - ... (all 31 non-empty subsets)
    /// - `.env.local.linux.amd64.alice.docker`
    /// - `.env.pr-<NUMBER>` (if applicable)
    pub fn resolve_env_paths(&self, dir: &Path) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = Vec::new();

        // Always start with base .env
        Self::add_exact_if_exist(dir, &mut paths, ".env");

        // Discover ENV configuration from .env file before resolving dimensions
        // This allows NODE_ENV in .env to determine which files to load
        Self::discover_env_from_env_file(dir);

        // Resolve all dimensions
        let env = Self::resolve_env();
        let os = Self::resolve_os();
        let arch = Self::resolve_arch();
        let user = Self::resolve_user();
        let variant = Self::resolve_variant();

        // Generate power set: all combinations of [env, os, arch, user, variant]
        // We use a bitmask approach: 5 bits for 5 optional values
        // Bit 0 = ENV, Bit 1 = OS, Bit 2 = ARCH, Bit 3 = USER, Bit 4 = VARIANT
        for mask in 1..32 {
            // mask from 1 to 31 (excluding 0 which is just .env)
            let mut parts = Vec::new();

            // Maintain canonical order: ENV, OS, ARCH, USER, VARIANT
            if mask & 1 != 0 {
                parts.push(env.as_str());
            }
            if mask & 2 != 0 {
                if let Some(ref o) = os {
                    parts.push(o.as_str());
                } else {
                    continue; // Skip this combination if OS not available
                }
            }
            if mask & 4 != 0 {
                if let Some(ref a) = arch {
                    parts.push(a.as_str());
                } else {
                    continue; // Skip this combination if ARCH not available
                }
            }
            if mask & 8 != 0 {
                if let Some(ref u) = user {
                    parts.push(u.as_str());
                } else {
                    continue; // Skip this combination if USER not available
                }
            }
            if mask & 16 != 0 {
                if let Some(ref v) = variant {
                    parts.push(v.as_str());
                } else {
                    continue; // Skip this combination if VARIANT not available
                }
            }

            // Build filename with dots as separators
            let filename = format!(".env.{}", parts.join("."));
            Self::add_exact_if_exist(dir, &mut paths, &filename);
        }

        // PR-specific always comes last (highest precedence)
        if let Some(pr_number) = Self::resolve_pr_number() {
            Self::add_exact_if_exist(dir, &mut paths, &format!(".env.pr-{}", pr_number));
        }

        paths
    }

    /// Loads and decrypts a single `.env` file, returning key/value pairs.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if decryption fails.
    pub fn load_env_file(&self, path: &Path) -> SecretsResult<HashMap<String, String>> {
        let content =
            std::fs::read_to_string(path).map_err(|e| SecretsError::EnvFileReadFailed {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
        self.parse_and_decrypt(&content, path)
    }

    /// Parses env file content and decrypts encrypted values.
    ///
    /// # Errors
    ///
    /// Returns an error if the content cannot be parsed or if decryption fails.
    pub fn parse_and_decrypt(
        &self,
        content: &str,
        path: &Path,
    ) -> SecretsResult<HashMap<String, String>> {
        let mut vars = HashMap::new();
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let mut value = value.trim().to_string();
                if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    value = value[1..value.len() - 1].to_string();
                }
                let decrypted = self.manager.decrypt_value(&value).map_err(|e| {
                    SecretsError::EnvFileParseFailed {
                        path: path.display().to_string(),
                        reason: format!("line {} for '{}': {}", line_num + 1, key, e),
                    }
                })?;
                vars.insert(key, decrypted);
            }
        }
        Ok(vars)
    }

    /// Gets a decrypted environment variable value from the process
    /// environment.
    ///
    /// If the value is encrypted, it will be automatically decrypted.
    ///
    /// # Errors
    ///
    /// Returns an error if the variable is not set or if decryption fails.
    pub fn get_var(&self, key: &str) -> SecretsResult<String> {
        let value = std::env::var(key).map_err(|_| SecretsError::EnvVarNotFound {
            key: key.to_string(),
        })?;
        self.manager.decrypt_value(&value)
    }

    /// Gets a decrypted environment variable, or returns a default if not set.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::EnvLoader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let loader = EnvLoader::new()?;
    /// let port = loader.get_var_or("PORT", "8080");
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_var_or(&self, key: &str, default: &str) -> String {
        self.get_var(key).unwrap_or_else(|_| default.to_string())
    }

    /// Sets a variable in `.env.local` in the current directory.
    ///
    /// Values are automatically encrypted when
    /// [`AutoDetectPatterns::should_encrypt`] returns `true`, except AGE key
    /// configuration variables (e.g., `AGE_KEY_NAME`) which are always stored
    /// as plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target file cannot be read or parsed
    /// - Encryption fails
    /// - The updated file cannot be written
    pub fn set_var(&self, key: &str, value: &str) -> SecretsResult<PathBuf> {
        self.set_var_in_dir(key, value, ".")
    }

    /// Sets a variable in `.env.local` in a specific directory.
    ///
    /// Returns the path that was written (`{dir}/.env.local`).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target file cannot be read or parsed
    /// - Encryption fails
    /// - The updated file cannot be written
    pub fn set_var_in_dir(
        &self,
        key: &str,
        value: &str,
        dir: impl AsRef<Path>,
    ) -> SecretsResult<PathBuf> {
        let path = dir.as_ref().join(".env.local");
        self.set_var_in_file(key, value, &path)?;
        Ok(path)
    }

    /// Sets a variable in a specific `.env` file path.
    ///
    /// Existing key-value pairs are preserved (with the target key updated),
    /// and output is written in deterministic sorted order.
    ///
    /// Values are automatically encrypted when
    /// [`AutoDetectPatterns::should_encrypt`] returns `true`, except AGE key
    /// configuration variables (e.g., `AGE_KEY_NAME`) which are always stored
    /// as plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target file cannot be read or parsed
    /// - Encryption fails
    /// - The updated file cannot be written
    pub fn set_var_in_file(
        &self,
        key: &str,
        value: &str,
        path: impl AsRef<Path>,
    ) -> SecretsResult<()> {
        let path = path.as_ref();
        let mut vars = Self::read_env_file_for_write(path)?;

        // AGE key variables must stay plaintext for key discovery.
        let final_value =
            if !Self::is_age_key_variable(key) && AutoDetectPatterns::should_encrypt(key) {
                self.manager.encrypt_value(value)?
            } else {
                value.to_string()
            };

        vars.insert(key.to_string(), final_value);
        Self::write_env_file_for_write(path, &vars)
    }

    /// Removes a variable from `.env.local` in the current working directory.
    ///
    /// Returns the path that was written (`{cwd}/.env.local`), or the path
    /// unchanged if the file did not exist or did not contain the key.
    ///
    /// # Errors
    ///
    /// Returns an error if the target file cannot be read, parsed, or written.
    pub fn unset_var(&self, key: &str) -> SecretsResult<PathBuf> {
        self.unset_var_in_dir(key, ".")
    }

    /// Removes a variable from `.env.local` in a specific directory.
    ///
    /// Returns the path that was written (`{dir}/.env.local`).
    ///
    /// # Errors
    ///
    /// Returns an error if the target file cannot be read, parsed, or written.
    pub fn unset_var_in_dir(&self, key: &str, dir: impl AsRef<Path>) -> SecretsResult<PathBuf> {
        let path = dir.as_ref().join(".env.local");
        self.unset_var_in_file(key, &path)?;
        Ok(path)
    }

    /// Removes a variable from a specific `.env` file path.
    ///
    /// If the file does not exist or does not contain `key`, this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the target file cannot be read, parsed, or written.
    pub fn unset_var_in_file(&self, key: &str, path: impl AsRef<Path>) -> SecretsResult<()> {
        let path = path.as_ref();
        let mut vars = Self::read_env_file_for_write(path)?;
        if vars.remove(key).is_some() {
            Self::write_env_file_for_write(path, &vars)?;
        }
        Ok(())
    }

    /// Parses an env file into a key-value map for write/update operations.
    fn read_env_file_for_write(path: &Path) -> SecretsResult<HashMap<String, String>> {
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let content =
            std::fs::read_to_string(path).map_err(|e| SecretsError::EnvFileReadFailed {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;

        dotenvy::from_read_iter(content.as_bytes())
            .collect::<Result<HashMap<String, String>, _>>()
            .map_err(|e| SecretsError::EnvFileParseFailed {
                path: path.display().to_string(),
                reason: e.to_string(),
            })
    }

    /// Writes key-value pairs to an env file in sorted KEY=VALUE format.
    fn write_env_file_for_write(path: &Path, vars: &HashMap<String, String>) -> SecretsResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecretsError::WriteFailed(e.to_string()))?;
        }

        let mut file =
            std::fs::File::create(path).map_err(|e| SecretsError::WriteFailed(e.to_string()))?;
        let mut keys: Vec<_> = vars.keys().cloned().collect();
        keys.sort();

        for key in keys {
            let value = vars
                .get(&key)
                .ok_or_else(|| SecretsError::WriteFailed("missing key during write".to_string()))?;
            if Self::needs_env_file_quoting(value) {
                writeln!(file, "{}=\"{}\"", key, Self::escape_env_file_value(value))
                    .map_err(|e| SecretsError::WriteFailed(e.to_string()))?;
            } else {
                writeln!(file, "{}={}", key, value)
                    .map_err(|e| SecretsError::WriteFailed(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Check if a value needs quoting in `.env` output.
    fn needs_env_file_quoting(value: &str) -> bool {
        value.is_empty()
            || value.contains(char::is_whitespace)
            || value.contains('$')
            || value.contains('\n')
            || value.contains('"')
    }

    /// Escape a value for `.env` double-quoted output.
    fn escape_env_file_value(value: &str) -> String {
        value.replace('"', "\\\"")
    }

    /// Gets all variable names from all `.env*` files that would be loaded.
    ///
    /// This method uses the standard file-loading algorithm (via
    /// [`resolve_env_paths`](Self::resolve_env_paths)) to determine which
    /// files would be loaded, then collects all unique variable names across
    /// those files.
    ///
    /// Files are processed in the same order as [`load()`](Self::load), but
    /// this method only collects the variable names without loading them into
    /// the environment.
    ///
    /// # Returns
    ///
    /// A vector of unique variable names found across all `.env*` files that
    /// would be loaded. If a variable appears in multiple files, it only
    /// appears once in the result.
    ///
    /// **Note:** AGE key variables (`DOTENVAGE_AGE_KEY`, `AGE_KEY`,
    /// `EKG_AGE_KEY`, `AGE_KEY_NAME`, and any variable ending with
    /// `_AGE_KEY_NAME`) are filtered out for security reasons.
    ///
    /// # Errors
    ///
    /// Returns an error if any file cannot be read or parsed. Unlike
    /// [`load()`](Self::load), this method fails fast on the first error
    /// encountered.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::EnvLoader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let loader = EnvLoader::new()?;
    /// let variable_names = loader.get_all_variable_names()?;
    /// println!("Found {} variables", variable_names.len());
    /// for name in &variable_names {
    ///     println!("  - {}", name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_all_variable_names(&self) -> SecretsResult<Vec<String>> {
        self.get_all_variable_names_from_dir(".")
    }

    /// Gets all variable names from all `.env*` files in a specific directory.
    ///
    /// Like [`get_all_variable_names()`](Self::get_all_variable_names), but
    /// loads from a specific directory instead of the current directory.
    ///
    /// **Note:** AGE key variables are filtered out for security reasons.
    ///
    /// # Errors
    ///
    /// Returns an error if any file cannot be read or parsed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotenvage::EnvLoader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let loader = EnvLoader::new()?;
    /// let variable_names = loader.get_all_variable_names_from_dir("./config")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_all_variable_names_from_dir(
        &self,
        dir: impl AsRef<Path>,
    ) -> SecretsResult<Vec<String>> {
        let (vars, _paths) = self.collect_all_vars_from_dir(dir)?;

        // Filter out AGE key variables - we don't expose these secrets
        Ok(vars
            .keys()
            .filter(|k| !Self::is_age_key_variable(k))
            .cloned()
            .collect())
    }

    /// Write all merged .env variables in KEY=VALUE format to a writer.
    ///
    /// Automatically filters out AGE key variables (`DOTENVAGE_AGE_KEY`,
    /// `AGE_KEY`, `EKG_AGE_KEY`, `AGE_KEY_NAME`, and any variable ending
    /// with `_AGE_KEY_NAME`).
    ///
    /// This function:
    /// 1. Loads all `.env*` files in standard order
    /// 2. Merges variables (later files override earlier ones)
    /// 3. Decrypts encrypted values
    /// 4. Filters out AGE key variables
    /// 5. Writes in simple KEY=VALUE format (quotes added when needed)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Writing to the writer fails
    /// - .env files cannot be loaded
    /// - Decryption fails for any encrypted value
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::io::Cursor;
    ///
    /// use dotenvage::EnvLoader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let loader = EnvLoader::new()?;
    /// let mut buffer = Vec::new();
    /// loader.dump_to_writer(&mut buffer)?;
    /// let output = String::from_utf8(buffer)?;
    /// println!("{}", output);
    /// # Ok(())
    /// # }
    /// ```
    pub fn dump_to_writer<W: std::io::Write>(&self, writer: W) -> SecretsResult<()> {
        self.dump_to_writer_from_dir(".", writer)
    }

    /// Write all merged .env variables in KEY=VALUE format to a writer from a
    /// specific directory.
    ///
    /// Same as [`dump_to_writer`](Self::dump_to_writer) but loads from a
    /// specific directory.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Writing to the writer fails
    /// - .env files cannot be loaded
    /// - Decryption fails for any encrypted value
    pub fn dump_to_writer_from_dir<W: std::io::Write>(
        &self,
        dir: impl AsRef<Path>,
        mut writer: W,
    ) -> SecretsResult<()> {
        // Use dynamic discovery to collect all variables
        let (merged_vars, _paths) = self.collect_all_vars_from_dir(dir)?;

        // Sort keys for consistent output
        let mut keys: Vec<_> = merged_vars.keys().cloned().collect();
        keys.sort();

        // Write each variable (filtering AGE keys and decrypting)
        for key in keys {
            // Filter out AGE key variables
            if Self::is_age_key_variable(&key) {
                continue;
            }

            if let Some(value) = merged_vars.get(&key) {
                let decrypted_value = self.manager.decrypt_value(value)?;

                // Write in KEY=VALUE format (add quotes if needed)
                if Self::needs_quoting(&decrypted_value) {
                    writeln!(
                        writer,
                        "{}=\"{}\"",
                        key,
                        Self::escape_value(&decrypted_value)
                    )
                    .map_err(|e| SecretsError::WriteFailed(e.to_string()))?;
                } else {
                    writeln!(writer, "{}={}", key, decrypted_value)
                        .map_err(|e| SecretsError::WriteFailed(e.to_string()))?;
                }
            }
        }

        Ok(())
    }

    /// Check if a variable name is an AGE key variable that should be filtered.
    fn is_age_key_variable(key: &str) -> bool {
        let key_upper = key.to_uppercase();
        matches!(
            key_upper.as_str(),
            "DOTENVAGE_AGE_KEY" | "AGE_KEY" | "EKG_AGE_KEY" | "AGE_KEY_NAME"
        ) || key_upper.ends_with("_AGE_KEY_NAME")
    }

    /// Check if a value needs quoting in .env format.
    fn needs_quoting(value: &str) -> bool {
        value.is_empty()
            || value.contains(char::is_whitespace)
            || value.contains('"')
            || value.contains('\'')
            || value.contains('=')
            || value.contains('#')
    }

    /// Escape a value for use in double quotes.
    fn escape_value(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    /// Attempts to discover ENV configuration from .env file as a fallback.
    ///
    /// This reads the `.env` file (without decryption) to find environment
    /// configuration variables (DOTENVAGE_ENV, EKG_ENV, VERCEL_ENV, or
    /// NODE_ENV) and sets them in the environment so they can be used for
    /// file path resolution.
    ///
    /// This is a fallback mechanism - environment variables always take
    /// precedence. This function only runs if no ENV configuration variables
    /// are already set in the process environment.
    ///
    /// Unlike AGE_KEY_NAME, ENV configuration variables can be encrypted, but
    /// if they are encrypted, they won't be available for file path resolution
    /// and the system will fall back to defaulting to "local".
    fn discover_env_from_env_file(dir: &Path) {
        // Skip if any ENV variable is already set in environment
        // Environment variables always take precedence over .env file
        if std::env::var("DOTENVAGE_ENV").is_ok()
            || std::env::var("EKG_ENV").is_ok()
            || std::env::var("VERCEL_ENV").is_ok()
            || std::env::var("NODE_ENV").is_ok()
        {
            return;
        }

        // Try to read .env file
        let env_file = dir.join(".env");
        if let Some(config_key) = Self::find_env_config_in_file(&env_file) {
            // Set the first ENV config variable we find (in priority order)
            // This will be read by resolve_env() later
            unsafe {
                std::env::set_var(config_key.0, config_key.1);
            }
        }
    }

    /// Searches a single .env file for ENV configuration variables.
    ///
    /// Returns `Some((key, value))` if a plaintext ENV config variable is
    /// found, `None` if no ENV config variable is found.
    ///
    /// Checks variables in priority order: DOTENVAGE_ENV, EKG_ENV, VERCEL_ENV,
    /// NODE_ENV. Returns the highest priority one found. If a variable is
    /// encrypted, it's skipped.
    fn find_env_config_in_file(file_path: &Path) -> Option<(String, String)> {
        let content = std::fs::read_to_string(file_path).ok()?;

        // Check in priority order across all lines
        // Priority: DOTENVAGE_ENV > EKG_ENV > VERCEL_ENV > NODE_ENV
        for key in &["DOTENVAGE_ENV", "EKG_ENV", "VERCEL_ENV", "NODE_ENV"] {
            if let Some(value) = Self::find_key_value_in_content(&content, key) {
                return Some((key.to_string(), value));
            }
        }

        None
    }

    /// Helper function to find a key-value pair in file content.
    /// Returns the value if found and not encrypted, None otherwise.
    fn find_key_value_in_content(content: &str, key: &str) -> Option<String> {
        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Look for KEY=value patterns
            let (line_key, value) = line.split_once('=')?;
            let line_key = line_key.trim();
            let value = value.trim().trim_matches('"').trim_matches('\'');

            // Check if this is the key we're looking for
            if line_key != key || value.is_empty() {
                continue;
            }

            // Skip encrypted values - we can't decrypt them without a SecretManager
            if SecretManager::is_encrypted(value) {
                continue;
            }

            return Some(value.to_string());
        }

        None
    }

    /// Discovers dimension configuration from loaded environment variables.
    ///
    /// This function checks loaded variables for dimension configuration values
    /// and returns them as key-value pairs that should be set in the process
    /// environment. This enables dynamic file loading where `.env` can set
    /// `NODE_ENV=production`, causing `.env.production` to also be loaded.
    ///
    /// For each dimension, checks the following variables (in priority order):
    /// - **ENV**: `DOTENVAGE_ENV`, `EKG_ENV`, `VERCEL_ENV`, `NODE_ENV`
    /// - **OS**: `DOTENVAGE_OS`, `EKG_OS`
    /// - **ARCH**: `DOTENVAGE_ARCH`, `EKG_ARCH`
    /// - **USER**: `DOTENVAGE_USER`, `EKG_USER`
    /// - **VARIANT**: `DOTENVAGE_VARIANT`, `EKG_VARIANT`, `VARIANT`
    ///
    /// Encrypted values are skipped since they cannot be decrypted at this
    /// stage (the key may not have been discovered yet).
    ///
    /// # Returns
    ///
    /// A vector of `(key, value)` pairs for dimension configs found in the
    /// loaded variables that are not already set in the process environment.
    fn discover_dimensions_from_vars(vars: &HashMap<String, String>) -> Vec<(String, String)> {
        let mut discovered = Vec::new();

        // ENV dimension - check multiple variable names in priority order
        let env_keys = ["DOTENVAGE_ENV", "EKG_ENV", "VERCEL_ENV", "NODE_ENV"];
        if !env_keys
            .iter()
            .any(|k| std::env::var(k).ok().filter(|s| !s.is_empty()).is_some())
        {
            for key in &env_keys {
                if let Some(value) = vars.get(*key)
                    && !value.is_empty()
                    && !SecretManager::is_encrypted(value)
                {
                    discovered.push((key.to_string(), value.clone()));
                    break;
                }
            }
        }

        // OS dimension
        let os_keys = ["DOTENVAGE_OS", "EKG_OS"];
        if !os_keys
            .iter()
            .any(|k| std::env::var(k).ok().filter(|s| !s.is_empty()).is_some())
        {
            for key in &os_keys {
                if let Some(value) = vars.get(*key)
                    && !value.is_empty()
                    && !SecretManager::is_encrypted(value)
                {
                    discovered.push((key.to_string(), value.clone()));
                    break;
                }
            }
        }

        // ARCH dimension
        let arch_keys = ["DOTENVAGE_ARCH", "EKG_ARCH"];
        if !arch_keys
            .iter()
            .any(|k| std::env::var(k).ok().filter(|s| !s.is_empty()).is_some())
        {
            for key in &arch_keys {
                if let Some(value) = vars.get(*key)
                    && !value.is_empty()
                    && !SecretManager::is_encrypted(value)
                {
                    discovered.push((key.to_string(), value.clone()));
                    break;
                }
            }
        }

        // USER dimension
        let user_keys = ["DOTENVAGE_USER", "EKG_USER"];
        if !user_keys
            .iter()
            .any(|k| std::env::var(k).ok().filter(|s| !s.is_empty()).is_some())
        {
            for key in &user_keys {
                if let Some(value) = vars.get(*key)
                    && !value.is_empty()
                    && !SecretManager::is_encrypted(value)
                {
                    discovered.push((key.to_string(), value.clone()));
                    break;
                }
            }
        }

        // VARIANT dimension
        let variant_keys = ["DOTENVAGE_VARIANT", "EKG_VARIANT", "VARIANT"];
        if !variant_keys
            .iter()
            .any(|k| std::env::var(k).ok().filter(|s| !s.is_empty()).is_some())
        {
            for key in &variant_keys {
                if let Some(value) = vars.get(*key)
                    && !value.is_empty()
                    && !SecretManager::is_encrypted(value)
                {
                    discovered.push((key.to_string(), value.clone()));
                    break;
                }
            }
        }

        discovered
    }

    /// Resolves the `<ENV>` placeholder for environment-specific file names.
    ///
    /// The environment name is resolved in the following order (higher numbers
    /// take precedence):
    ///
    /// 1. `DOTENVAGE_ENV` environment variable (preferred)
    /// 2. `EKG_ENV` environment variable (alternative)
    /// 3. `VERCEL_ENV` environment variable
    /// 4. `NODE_ENV` environment variable
    /// 5. `.env` file (as fallback - checks for DOTENVAGE_ENV, EKG_ENV,
    ///    VERCEL_ENV, or NODE_ENV - plaintext only)
    /// 6. Defaults to `"local"` if none of the above are set
    ///
    /// Note: Environment variables always take precedence over values in
    /// `.env` files. The `.env` file is only checked if no environment
    /// variables are set.
    ///
    /// The value is always converted to lowercase.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::EnvLoader;
    ///
    /// // With DOTENVAGE_ENV=production, returns "production"
    /// // Without any env vars set, returns "local"
    /// let env = EnvLoader::resolve_env();
    /// println!("Environment: {}", env);
    /// ```
    pub fn resolve_env() -> String {
        std::env::var("DOTENVAGE_ENV")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("EKG_ENV").ok().filter(|s| !s.is_empty()))
            .or_else(|| std::env::var("VERCEL_ENV").ok().filter(|s| !s.is_empty()))
            .or_else(|| std::env::var("NODE_ENV").ok().filter(|s| !s.is_empty()))
            .map(|e| e.to_lowercase())
            .unwrap_or_else(|| "local".to_string())
    }

    /// Resolves the `<ARCH>` placeholder for architecture-specific file names.
    ///
    /// The architecture name is resolved from the first available source:
    ///
    /// 1. `DOTENVAGE_ARCH` environment variable (preferred)
    /// 2. `EKG_ARCH` environment variable (alternative)
    /// 3. `CARGO_CFG_TARGET_ARCH` environment variable (Cargo build-time, e.g.,
    ///    "x86_64", "aarch64")
    /// 4. `TARGET` environment variable (parsed for arch from target triple,
    ///    e.g., "x86_64-unknown-linux-gnu" → "x86_64")
    /// 5. `TARGETARCH` environment variable (Docker multi-platform builds,
    ///    e.g., "amd64", "arm64")
    /// 6. `TARGETPLATFORM` environment variable (Docker, parsed for arch, e.g.,
    ///    "linux/arm64" → "arm64")
    /// 7. `RUNNER_ARCH` environment variable (GitHub Actions, e.g., "X64",
    ///    "ARM64")
    /// 8. Returns `None` if none are set
    ///
    /// # Supported Architectures
    ///
    /// The following architectures are recognized and normalized to canonical
    /// names:
    ///
    /// - **`amd64`**: AMD64/x86-64 (aliases: `x64`, `x86_64`, `x86-64`)
    /// - **`arm64`**: ARM 64-bit (aliases: `aarch64`)
    /// - **`arm`**: ARM 32-bit (aliases: `armv7`, `armv7l`, `armhf`)
    /// - **`i386`**: x86 32-bit (aliases: `i686`, `x86`)
    /// - **`riscv64`**: RISC-V 64-bit (aliases: `riscv64gc`)
    /// - **`ppc64le`**: PowerPC 64-bit LE (aliases: `powerpc64le`)
    /// - **`s390x`**: IBM System/390
    ///
    /// Unknown values are passed through as-is (lowercase) for custom use
    /// cases.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::EnvLoader;
    ///
    /// // With TARGETARCH=arm64 (Docker build), resolves to Some("arm64")
    /// // With RUNNER_ARCH=X64 (GitHub Actions), resolves to Some("amd64")
    /// if let Some(arch) = EnvLoader::resolve_arch() {
    ///     println!("Architecture: {}", arch);
    /// }
    /// ```
    pub fn resolve_arch() -> Option<String> {
        let arch = std::env::var("DOTENVAGE_ARCH")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("EKG_ARCH").ok().filter(|s| !s.is_empty()))
            .or_else(|| {
                std::env::var("CARGO_CFG_TARGET_ARCH")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| {
                // Parse TARGET triple (e.g., "x86_64-unknown-linux-gnu" → "x86_64")
                std::env::var("TARGET")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|t| t.split('-').next().map(String::from))
            })
            .or_else(|| std::env::var("TARGETARCH").ok().filter(|s| !s.is_empty()))
            .or_else(|| {
                // Parse TARGETPLATFORM (e.g., "linux/arm64" → "arm64")
                std::env::var("TARGETPLATFORM")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|p| p.split('/').nth(1).map(String::from))
            })
            .or_else(|| std::env::var("RUNNER_ARCH").ok().filter(|s| !s.is_empty()))?;

        // Try to normalize to a canonical architecture name
        // If not recognized, pass through as lowercase for custom values
        Some(
            arch.parse::<Arch>()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| arch.to_lowercase()),
        )
    }

    /// Resolves the `<OS>` placeholder for OS-specific file names.
    ///
    /// The operating system is resolved from the first available source:
    ///
    /// 1. `DOTENVAGE_OS` environment variable (preferred)
    /// 2. `EKG_OS` environment variable (alternative)
    /// 3. `CARGO_CFG_TARGET_OS` environment variable (Cargo build-time, e.g.,
    ///    "linux", "macos", "windows")
    /// 4. `TARGET` environment variable (parsed from target triple, e.g.,
    ///    "x86_64-unknown-linux-gnu" → "linux")
    /// 5. `RUNNER_OS` environment variable (GitHub Actions, e.g., "Linux",
    ///    "macOS", "Windows")
    /// 6. `std::env::consts::OS` (runtime detection)
    ///
    /// # Supported Operating Systems
    ///
    /// - **`linux`**: Linux
    /// - **`macos`**: macOS (aliases: `darwin`, `osx`)
    /// - **`windows`**: Windows (aliases: `win32`, `win`)
    /// - **`freebsd`**: FreeBSD
    /// - **`openbsd`**: OpenBSD
    /// - **`netbsd`**: NetBSD
    /// - **`android`**: Android
    /// - **`ios`**: iOS
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::EnvLoader;
    ///
    /// // Typically auto-detects from runtime or build-time
    /// if let Some(os) = EnvLoader::resolve_os() {
    ///     println!("OS: {}", os);
    /// }
    /// ```
    pub fn resolve_os() -> Option<String> {
        let os = std::env::var("DOTENVAGE_OS")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("EKG_OS").ok().filter(|s| !s.is_empty()))
            .or_else(|| {
                std::env::var("CARGO_CFG_TARGET_OS")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| {
                // Parse TARGET triple (e.g., "x86_64-unknown-linux-gnu" → "linux")
                std::env::var("TARGET")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|t| t.split('-').nth(2).map(String::from))
            })
            .or_else(|| std::env::var("RUNNER_OS").ok().filter(|s| !s.is_empty()))
            .or_else(|| Some(std::env::consts::OS.to_string()))?;

        // Try to normalize to a canonical OS name
        Some(
            os.parse::<Os>()
                .map(|o| o.to_string())
                .unwrap_or_else(|_| os.to_lowercase()),
        )
    }

    /// Resolves the `<USER>` placeholder for user-specific file names.
    ///
    /// The username is resolved from the first available environment variable:
    ///
    /// 1. `DOTENVAGE_USER` (preferred)
    /// 2. `EKG_USER`
    /// 3. `GITHUB_ACTOR` (GitHub Actions)
    /// 4. `GITHUB_TRIGGERING_ACTOR` (GitHub Actions)
    /// 5. `GITHUB_REPOSITORY_OWNER` (GitHub Actions)
    /// 6. `USER` (Unix standard)
    /// 7. `USERNAME` (Windows standard)
    /// 8. Returns `None` if none are set
    ///
    /// The value is always converted to lowercase.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::EnvLoader;
    ///
    /// // Typically resolves from $USER on Unix or %USERNAME% on Windows
    /// if let Some(user) = EnvLoader::resolve_user() {
    ///     println!("User: {}", user);
    /// }
    /// ```
    pub fn resolve_user() -> Option<String> {
        std::env::var("DOTENVAGE_USER")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("EKG_USER").ok().filter(|s| !s.is_empty()))
            .or_else(|| std::env::var("GITHUB_ACTOR").ok().filter(|s| !s.is_empty()))
            .or_else(|| {
                std::env::var("GITHUB_TRIGGERING_ACTOR")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| {
                std::env::var("GITHUB_REPOSITORY_OWNER")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| std::env::var("USER").ok().filter(|s| !s.is_empty()))
            .or_else(|| std::env::var("USERNAME").ok().filter(|s| !s.is_empty()))
            .map(|u| u.to_lowercase())
    }

    /// Resolves the `<VARIANT>` placeholder for variant-specific file names.
    ///
    /// The variant name is resolved from the first available environment
    /// variable:
    ///
    /// 1. `DOTENVAGE_VARIANT` (preferred)
    /// 2. `EKG_VARIANT`
    /// 3. `VARIANT`
    /// 4. Returns `None` if none are set
    ///
    /// The value is always converted to lowercase.
    ///
    /// This dimension is useful for deployment variants like:
    /// - `docker` - Docker containerized deployment
    /// - `kubernetes` or `k8s` - Kubernetes deployment
    /// - `lambda` - AWS Lambda deployment
    /// - `canary` - Canary release
    /// - `blue` / `green` - Blue-green deployment variants
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::EnvLoader;
    ///
    /// // With VARIANT=docker, returns Some("docker")
    /// // Without any variant set, returns None
    /// if let Some(variant) = EnvLoader::resolve_variant() {
    ///     println!("Variant: {}", variant);
    /// }
    /// ```
    pub fn resolve_variant() -> Option<String> {
        std::env::var("DOTENVAGE_VARIANT")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("EKG_VARIANT").ok().filter(|s| !s.is_empty()))
            .or_else(|| std::env::var("VARIANT").ok().filter(|s| !s.is_empty()))
            .map(|v| v.to_lowercase())
    }

    /// Resolves the `<PR_NUMBER>` placeholder for PR-specific file names.
    ///
    /// The PR number is only resolved in GitHub Actions pull request contexts:
    ///
    /// 1. Checks that `GITHUB_EVENT_NAME` starts with `"pull_request"`
    /// 2. Reads from `PR_NUMBER` environment variable
    /// 3. Falls back to parsing `GITHUB_REF` (e.g., `refs/pull/123/merge`)
    /// 4. Returns `None` if not in a PR context
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::EnvLoader;
    ///
    /// // In GitHub Actions PR, resolves to Some("123")
    /// // Outside of PR context, returns None
    /// if let Some(pr_number) = EnvLoader::resolve_pr_number() {
    ///     println!("PR Number: {}", pr_number);
    /// }
    /// ```
    pub fn resolve_pr_number() -> Option<String> {
        // Only resolve in GitHub Actions pull request context
        if let Ok(event) = std::env::var("GITHUB_EVENT_NAME")
            && event.starts_with("pull_request")
            && let Some(pr) = std::env::var("PR_NUMBER").ok().filter(|s| !s.is_empty())
        {
            return Some(pr);
        }

        // Try parsing from GITHUB_REF
        if let Ok(gref) = std::env::var("GITHUB_REF")
            && let Some(idx) = gref.find("/pull/")
        {
            let mut pr_number = String::new();
            for c in gref[idx + 6..].chars() {
                if c.is_ascii_digit() {
                    pr_number.push(c);
                } else {
                    break;
                }
            }
            if !pr_number.is_empty() {
                return Some(pr_number);
            }
        }

        None
    }
}

/// Auto-detection patterns for identifying sensitive environment variables.
///
/// This utility helps determine which environment variables should be encrypted
/// based on their names. It uses common patterns to identify secrets like
/// tokens, passwords, and API keys.
///
/// # Examples
///
/// ```rust
/// use dotenvage::AutoDetectPatterns;
///
/// assert!(AutoDetectPatterns::should_encrypt("API_TOKEN"));
/// assert!(AutoDetectPatterns::should_encrypt("DATABASE_PASSWORD"));
/// assert!(AutoDetectPatterns::should_encrypt("RECOVERY_PHRASE"));
/// assert!(!AutoDetectPatterns::should_encrypt("PORT"));
/// assert!(!AutoDetectPatterns::should_encrypt("AWS_REGION"));
/// ```
pub struct AutoDetectPatterns;

impl AutoDetectPatterns {
    /// Patterns indicating a variable should be encrypted.
    ///
    /// Variables containing any of these substrings (case-insensitive) will be
    /// automatically encrypted unless they match a pattern in
    /// [`NEVER_ENCRYPT`](Self::NEVER_ENCRYPT).
    pub const ENCRYPT_PATTERNS: &'static [&'static str] = &[
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSPHRASE",
        "PHRASE",
        "CREDENTIAL",
        "_KEY",
        "API_KEY",
        "PRIVATE_KEY",
    ];

    /// Variables that should never be encrypted.
    ///
    /// These are typically configuration values that need to be plaintext for
    /// readability or compatibility reasons.
    pub const NEVER_ENCRYPT: &'static [&'static str] = &[
        "AWS_REGION",
        "FLY_PRIMARY_REGION",
        "PORT",
        "RUST_LOG",
        "DATABASE_NAME",
        "APP_NAME",
        "ENDPOINT_URL",
        "ORG",
        "PUBLIC_KEY",
        "PUB_KEY",
    ];

    /// Returns `true` if an environment variable name should be encrypted.
    ///
    /// This checks the variable name against
    /// [`ENCRYPT_PATTERNS`](Self::ENCRYPT_PATTERNS)
    /// and [`NEVER_ENCRYPT`](Self::NEVER_ENCRYPT) lists.
    /// AGE key variables (like `EKG_AGE_KEY_NAME`, `AGE_KEY_NAME`, etc.) are
    /// never encrypted as they are used for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::AutoDetectPatterns;
    ///
    /// assert!(AutoDetectPatterns::should_encrypt("STRIPE_API_KEY"));
    /// assert!(AutoDetectPatterns::should_encrypt("github_token"));
    /// assert!(!AutoDetectPatterns::should_encrypt("DATABASE_NAME"));
    /// assert!(!AutoDetectPatterns::should_encrypt("EKG_AGE_KEY_NAME"));
    /// assert!(!AutoDetectPatterns::should_encrypt("AGE_KEY_NAME"));
    /// ```
    pub fn should_encrypt(key: &str) -> bool {
        // Never encrypt AGE key variables - these are configuration values
        // that must remain plaintext
        if Self::is_age_key_variable(key) {
            return false;
        }

        let key_upper = key.to_uppercase();
        if Self::NEVER_ENCRYPT.iter().any(|p| key_upper.contains(p)) {
            return false;
        }
        Self::ENCRYPT_PATTERNS.iter().any(|p| key_upper.contains(p))
    }

    /// Check if a variable name is an AGE key variable that should never be
    /// encrypted.
    ///
    /// AGE key variables are used for configuration and must remain plaintext.
    /// This includes:
    /// - `DOTENVAGE_AGE_KEY`
    /// - `AGE_KEY`
    /// - `EKG_AGE_KEY`
    /// - `AGE_KEY_NAME`
    /// - Any variable ending with `_AGE_KEY_NAME` (e.g., `EKG_AGE_KEY_NAME`)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotenvage::AutoDetectPatterns;
    ///
    /// assert!(AutoDetectPatterns::is_age_key_variable("EKG_AGE_KEY_NAME"));
    /// assert!(AutoDetectPatterns::is_age_key_variable("AGE_KEY_NAME"));
    /// assert!(AutoDetectPatterns::is_age_key_variable("DOTENVAGE_AGE_KEY"));
    /// assert!(!AutoDetectPatterns::is_age_key_variable("API_KEY"));
    /// ```
    pub fn is_age_key_variable(key: &str) -> bool {
        let key_upper = key.to_uppercase();
        matches!(
            key_upper.as_str(),
            "DOTENVAGE_AGE_KEY" | "AGE_KEY" | "EKG_AGE_KEY" | "AGE_KEY_NAME"
        ) || key_upper.ends_with("_AGE_KEY_NAME")
    }
}
