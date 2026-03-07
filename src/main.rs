//! # dotenvage
//!
//! Dotenv with age encryption: encrypt/decrypt secrets in .env files.
//!
//! This crate provides a CLI tool for managing .env files with age-based
//! encryption, allowing secure storage and handling of sensitive environment
//! variables.

use std::collections::HashMap;
use std::io::Write;
use std::path::{
    Path,
    PathBuf,
};

use anyhow::{
    Context,
    Result,
};
use clap::{
    Parser,
    Subcommand,
    ValueEnum,
};
use dotenvage::{
    AutoDetectPatterns,
    SecretManager,
};

/// Options for dumping environment variables
#[derive(Debug, Clone, Copy)]
struct DumpOptions {
    bash: bool,
    make: bool,
    make_eval: bool,
    export: bool,
    docker: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum KeyStore {
    File,
    Os,
    Both,
    System,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Generate a new encryption key pair
    #[command(alias = "gen")]
    Keygen {
        /// Output file path (default: XDG path)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Force overwrite if key already exists
        #[arg(short, long)]
        force: bool,
        /// Where to store the private key
        #[arg(long, value_enum, default_value_t = KeyStore::File)]
        store: KeyStore,
    },
    /// Encrypt sensitive values in an environment file
    Encrypt {
        /// Path to environment file (e.g., .env.local)
        #[arg(default_value = ".env.local")]
        file: PathBuf,
        /// Specific keys to encrypt (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        keys: Option<Vec<String>>,
        /// Use auto-detection based on key name patterns
        #[arg(short, long, default_value = "true")]
        auto: bool,
    },
    /// Edit an environment file (decrypts, opens editor, re-encrypts)
    Edit {
        #[arg(default_value = ".env.local")]
        file: PathBuf,
    },
    /// Set a secret value
    Set {
        /// KEY=VALUE pair to set
        pair: String,
        /// Environment file to update
        #[arg(short, long, default_value = ".env.local")]
        file: PathBuf,
    },
    /// Get a decrypted secret value (scans .env files in order)
    Get {
        /// Environment variable name
        key: String,
        /// Specific file to read from (if not provided, scans .env* files)
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// List environment variables and their encryption status
    List {
        /// Specific file to list from (if not provided, scans all .env* files
        /// in standard order)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Show values (decrypted)
        #[arg(long)]
        show_values: bool,
        /// Plain ASCII output (no icons, just variable names)
        #[arg(short, long)]
        plain: bool,
        /// JSON output format
        #[arg(short, long)]
        json: bool,
    },
    /// Dump environment file to stdout with all values decrypted
    Dump {
        /// Specific file to dump (if not provided, scans .env* files in order)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Use bash-compliant escaping rules (strict quoting and escaping)
        #[arg(short, long)]
        bash: bool,
        /// Output in GNU Make format (VAR := value) with Make-safe escaping
        #[arg(short, long)]
        make: bool,
        /// Output as Make $(eval ...) statements for direct inclusion (no temp
        /// file needed)
        #[arg(long)]
        make_eval: bool,
        /// Prefix each line with 'export ' for bash sourcing
        #[arg(short, long)]
        export: bool,
        /// Docker --env-file format (no quotes, inline escaping)
        #[arg(short, long)]
        docker: bool,
    },
}

#[derive(Parser, Debug, Clone)]
#[command(name = "dotenvage", version, about = "Dotenv with age encryption")]
struct Cli {
    /// Show which files are being read
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

fn parse_env_file(content: &str) -> Result<HashMap<String, String>> {
    dotenvy::from_read_iter(content.as_bytes())
        .collect::<Result<HashMap<String, String>, _>>()
        .context("Failed to parse .env file")
}

fn write_env_file(path: &Path, vars: &HashMap<String, String>) -> Result<()> {
    let mut file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    let mut keys: Vec<_> = vars.keys().collect();
    keys.sort();
    for key in keys {
        let value = vars.get(key).unwrap();
        if value.contains(' ') || value.contains('$') || value.contains('\n') {
            writeln!(file, "{}=\"{}\"", key, value.replace('"', "\\\""))?;
        } else {
            writeln!(file, "{}={}", key, value)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    match cli.command {
        Commands::Keygen {
            output,
            force,
            store,
        } => keygen(output, force, store),
        Commands::Encrypt { file, keys, auto } => encrypt(file, keys, auto),
        Commands::Edit { file } => edit(file),
        Commands::Set { pair, file } => set(pair, file),
        Commands::Get { key, file } => get(key, file, cli.verbose),
        Commands::List {
            file,
            show_values,
            plain,
            json,
        } => list(file, show_values, plain, json, cli.verbose),
        Commands::Dump {
            file,
            bash,
            make,
            make_eval,
            export,
            docker,
        } => {
            let options = DumpOptions {
                bash,
                make,
                make_eval,
                export,
                docker,
            };
            dump(file, options, cli.verbose)
        }
    }
}

fn keygen(output: Option<PathBuf>, force: bool, store: KeyStore) -> Result<()> {
    use dotenvage::{
        KeyGenOptions,
        KeyLocation,
        KeyStoreTarget,
    };

    if matches!(store, KeyStore::Os | KeyStore::System) && output.is_some() {
        anyhow::bail!("--output is only valid when --store is 'file' or 'both'");
    }

    let target = match store {
        KeyStore::File => KeyStoreTarget::File,
        KeyStore::Os => KeyStoreTarget::OsKeychain,
        KeyStore::Both => KeyStoreTarget::OsKeychainAndFile,
        KeyStore::System => KeyStoreTarget::SystemStore,
    };

    let result = SecretManager::generate_and_save(KeyGenOptions {
        target,
        key_name: None,
        file_path: output,
        force,
    })
    .context("Failed to generate and save key")?;

    for loc in &result.locations {
        match loc {
            KeyLocation::UserFile(p) => {
                println!("Private key saved to: {}", p.display());
            }
            KeyLocation::OsKeychain { service, account } => {
                println!(
                    "Private key saved to OS keychain \
                     (service: {}, account: {})",
                    service, account
                );
            }
            KeyLocation::SystemKeychain { service, account } => {
                println!(
                    "Private key saved to System Keychain \
                     (service: {}, account: {})",
                    service, account
                );
            }
            KeyLocation::SystemFile(p) => {
                println!("Private key saved to system store: {}", p.display());
            }
        }
    }

    println!("Public recipient: {}", result.public_key);
    Ok(())
}

fn encrypt(file: PathBuf, keys: Option<Vec<String>>, auto: bool) -> Result<()> {
    let manager = SecretManager::new().context("Failed to load encryption key")?;
    if !file.exists() {
        anyhow::bail!("File not found: {}", file.display());
    }
    let content = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read {}", file.display()))?;
    let mut vars = parse_env_file(&content)?;
    let mut encrypted_count = 0;
    let keys_to_encrypt: Vec<String> = if let Some(specific) = keys {
        // Filter out AGE key variables even when explicitly provided
        specific
            .into_iter()
            .filter(|k| !AutoDetectPatterns::is_age_key_variable(k))
            .collect()
    } else if auto {
        vars.keys()
            .filter(|k| AutoDetectPatterns::should_encrypt(k))
            .cloned()
            .collect()
    } else {
        anyhow::bail!("Either --keys or --auto must be specified");
    };
    for key in &keys_to_encrypt {
        if let Some(value) = vars.get(key)
            && !SecretManager::is_encrypted(value)
        {
            let encrypted = manager
                .encrypt_value(value)
                .with_context(|| format!("Failed to encrypt {}", key))?;
            vars.insert(key.clone(), encrypted);
            encrypted_count += 1;
        }
    }
    write_env_file(&file, &vars)?;
    println!(
        "✓ Encrypted {} value(s) in {}",
        encrypted_count,
        file.display()
    );
    if encrypted_count > 0 {
        println!("  Encrypted keys:");
        for key in &keys_to_encrypt {
            if vars
                .get(key)
                .is_some_and(|v| SecretManager::is_encrypted(v))
            {
                println!("    - {}", key);
            }
        }
    }
    Ok(())
}

/// Edit an environment file by decrypting, opening in editor, and re-encrypting
/// changes.
fn edit(file: PathBuf) -> Result<()> {
    let manager = SecretManager::new().context("Failed to load encryption key")?;
    if !file.exists() {
        anyhow::bail!("File not found: {}", file.display());
    }
    let content = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read {}", file.display()))?;
    let mut vars = parse_env_file(&content)?;
    let mut keys_to_encrypt = Vec::new();
    for (key, value) in &mut vars {
        if SecretManager::is_encrypted(value) {
            // Don't track AGE key variables for re-encryption - they should remain
            // plaintext
            if !AutoDetectPatterns::is_age_key_variable(key) {
                keys_to_encrypt.push(key.clone());
            }
            *value = manager
                .decrypt_value(value)
                .with_context(|| format!("Failed to decrypt {}", key))?;
        }
    }
    let temp = tempfile::Builder::new()
        .suffix(".env")
        .tempfile()
        .context("Failed to create temp file")?;
    write_env_file(temp.path(), &vars)?;
    let original = std::fs::read_to_string(temp.path()).context("Failed to read temp file")?;
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor)
        .arg(temp.path())
        .status()
        .with_context(|| format!("Failed to launch editor: {}", editor))?;
    if !status.success() {
        anyhow::bail!("Editor exited with non-zero status");
    }
    let edited = std::fs::read_to_string(temp.path()).context("Failed to read edited file")?;
    if edited == original {
        println!("No changes made.");
        return Ok(());
    }
    let mut edited_vars = parse_env_file(&edited)?;
    for key in &keys_to_encrypt {
        // Double-check: never encrypt AGE key variables (shouldn't be in list, but be
        // safe)
        if AutoDetectPatterns::is_age_key_variable(key) {
            continue;
        }
        if let Some(value) = edited_vars.get_mut(key)
            && !SecretManager::is_encrypted(value)
        {
            *value = manager
                .encrypt_value(value)
                .with_context(|| format!("Failed to encrypt {}", key))?;
        }
    }
    write_env_file(&file, &edited_vars)?;
    println!("✓ Saved encrypted changes to {}", file.display());
    Ok(())
}

fn set(pair: String, file: PathBuf) -> Result<()> {
    let manager = SecretManager::new().context("Failed to load encryption key")?;
    let (key, value) = pair.split_once('=').context("Invalid KEY=VALUE format")?;
    let loader = dotenvage::EnvLoader::with_manager(manager);
    loader
        .set_var_in_file(key, value, &file)
        .with_context(|| format!("Failed to write {}", file.display()))?;

    let final_value = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read {}", file.display()))
        .and_then(|content| {
            parse_env_file(&content)?
                .get(key)
                .cloned()
                .context("Key not found after write")
        })?;
    let status = if SecretManager::is_encrypted(&final_value) {
        "encrypted"
    } else {
        "plain"
    };
    println!("✓ Set {} ({}) in {}", key, status, file.display());
    Ok(())
}

fn get(key: String, file: Option<PathBuf>, verbose_files: bool) -> Result<()> {
    let manager = SecretManager::new().context("Failed to load encryption key")?;
    let value = if let Some(file_path) = file {
        if verbose_files {
            eprintln!("Reading: {}", file_path.display());
        }
        let content = std::fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        let vars = parse_env_file(&content)?;
        vars.get(&key)
            .with_context(|| format!("Key '{}' not found in {}", key, file_path.display()))?
            .clone()
    } else {
        // Scan ordered files with dynamic dimension discovery
        let loader = dotenvage::EnvLoader::with_manager(manager.clone());
        let (vars, paths) = loader
            .collect_all_vars_from_dir(Path::new("."))
            .context("Failed to collect environment variables")?;
        if verbose_files {
            for p in &paths {
                eprintln!("Reading: {}", p.display());
            }
        }
        vars.get(&key)
            .with_context(|| format!("Key '{}' not found in any .env* file", key))?
            .clone()
    };
    let decrypted = manager
        .decrypt_value(&value)
        .context("Failed to decrypt value")?;
    println!("{}", decrypted);
    Ok(())
}

fn list(
    file: Option<PathBuf>,
    show_values: bool,
    plain: bool,
    json: bool,
    verbose_files: bool,
) -> Result<()> {
    let manager = SecretManager::new().context("Failed to load encryption key")?;

    // Collect variables from either a specific file or all .env* files
    let vars = if let Some(file_path) = file {
        // Single file mode
        if !file_path.exists() {
            anyhow::bail!("File not found: {}", file_path.display());
        }
        if verbose_files {
            eprintln!("Reading: {}", file_path.display());
        }
        let content = std::fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        parse_env_file(&content)?
    } else {
        // Scan all .env* files with dynamic dimension discovery
        let loader = dotenvage::EnvLoader::with_manager(manager.clone());
        let (all_vars, paths) = loader
            .collect_all_vars_from_dir(Path::new("."))
            .context("Failed to collect environment variables")?;
        if verbose_files {
            for path in &paths {
                eprintln!("Reading: {}", path.display());
            }
        }
        all_vars
    };

    let mut keys: Vec<_> = vars.keys().collect();
    keys.sort();

    if json {
        // JSON output format
        let mut output = HashMap::new();
        for key in keys {
            // Filter out AGE key variables - we don't expose these secrets
            if is_age_key_variable(key) {
                continue;
            }
            let value = vars.get(key).unwrap();
            let is_encrypted = SecretManager::is_encrypted(value);
            let mut entry = HashMap::new();
            entry.insert("encrypted", is_encrypted.to_string());
            if show_values {
                let display_value = if is_encrypted {
                    manager
                        .decrypt_value(value)
                        .unwrap_or_else(|_| "<decryption failed>".to_string())
                } else {
                    value.clone()
                };
                entry.insert("value", display_value);
            }
            output.insert(key, entry);
        }
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Text output (plain or with icons)
        for key in keys {
            // Filter out AGE key variables - we don't expose these secrets
            if is_age_key_variable(key) {
                continue;
            }
            let value = vars.get(key).unwrap();
            let is_encrypted = SecretManager::is_encrypted(value);
            print_list_entry(&manager, key, value, is_encrypted, show_values, plain)?;
        }
    }
    Ok(())
}

/// Helper function to print a single list entry
fn print_list_entry(
    manager: &SecretManager,
    key: &str,
    value: &str,
    is_encrypted: bool,
    verbose: bool,
    plain: bool,
) -> Result<()> {
    let lock_icon = if is_encrypted { "🔒" } else { "  " };

    match (verbose, plain) {
        (true, true) => {
            // Plain verbose: KEY = value
            let display_value = if is_encrypted {
                manager
                    .decrypt_value(value)
                    .unwrap_or_else(|_| "<decryption failed>".to_string())
            } else {
                value.to_string()
            };
            println!("{} = {}", key, display_value);
        }
        (true, false) => {
            // Icon verbose: 🔒 KEY = value
            let display_value = if is_encrypted {
                manager
                    .decrypt_value(value)
                    .unwrap_or_else(|_| "<decryption failed>".to_string())
            } else {
                value.to_string()
            };
            println!("{} {} = {}", lock_icon, key, display_value);
        }
        (false, true) => {
            // Plain: KEY
            println!("{}", key);
        }
        (false, false) => {
            // Icon: 🔒 KEY
            println!("{} {}", lock_icon, key);
        }
    }
    Ok(())
}

fn dump(file: Option<PathBuf>, options: DumpOptions, verbose_files: bool) -> Result<()> {
    let manager = SecretManager::new().context("Failed to load encryption key")?;

    if let Some(file_path) = file {
        // Dump specific file only (no comments, just vars)
        if !file_path.exists() {
            anyhow::bail!("File not found: {}", file_path.display());
        }
        if verbose_files {
            eprintln!("Reading: {}", file_path.display());
        }
        let content = std::fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        let all_vars = parse_env_file(&content)?;
        dump_vars(&manager, &all_vars, options)?;
    } else {
        // Collect all variables with dynamic dimension discovery
        // This matches the actual precedence behavior (last value wins)
        let loader = dotenvage::EnvLoader::with_manager(manager.clone());
        let (merged_vars, paths) = loader
            .collect_all_vars_from_dir(Path::new("."))
            .context("Failed to collect environment variables")?;
        if verbose_files {
            for path in &paths {
                eprintln!("Reading: {}", path.display());
            }
        }
        dump_vars(&manager, &merged_vars, options)?;
    }

    Ok(())
}

fn dump_vars(
    manager: &SecretManager,
    vars: &HashMap<String, String>,
    options: DumpOptions,
) -> Result<()> {
    let mut keys: Vec<_> = vars.keys().cloned().collect();
    keys.sort();

    for key in keys {
        // Filter out AGE key variables - we don't propagate these secrets
        if is_age_key_variable(&key) {
            continue;
        }

        if let Some(value) = vars.get(&key) {
            let decrypted_value = manager
                .decrypt_value(value)
                .with_context(|| format!("Failed to decrypt {}", key))?;

            dump_single_var(&key, &decrypted_value, options);
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

/// Output a single variable in the appropriate format
fn dump_single_var(key: &str, value: &str, options: DumpOptions) {
    if options.make_eval {
        dump_make_eval_var(key, value, options.export);
    } else if options.make {
        dump_make_var(key, value, options.export);
    } else {
        dump_env_var(key, value, options);
    }
}

/// Output variable in GNU Make $(eval ...) format
fn dump_make_eval_var(key: &str, value: &str, export: bool) {
    let prefix = if export { "export " } else { "" };
    let escaped_value = escape_for_make_eval(value);
    println!("$(eval {}{} := {})", prefix, key, escaped_value);
}

/// Output variable in GNU Make format
fn dump_make_var(key: &str, value: &str, export: bool) {
    let prefix = if export { "export " } else { "" };
    let escaped_value = escape_for_make(value);
    println!("{}{} := {}", prefix, key, escaped_value);
}

/// Output variable in env/bash format
fn dump_env_var(key: &str, value: &str, options: DumpOptions) {
    let prefix = if options.export { "export " } else { "" };

    if options.docker {
        dump_docker_var(key, value, prefix);
    } else if options.bash || options.export {
        dump_bash_var(key, value, prefix);
    } else {
        dump_simple_var(key, value, prefix);
    }
}

/// Output variable in Docker --env-file format (no quotes, raw value)
fn dump_docker_var(key: &str, value: &str, prefix: &str) {
    // Docker's --env-file format: KEY=value (no quotes, value extends to EOL)
    // Docker handles special characters correctly without escaping
    println!("{}{}={}", prefix, key, value);
}

/// Output variable with bash-compliant escaping
fn dump_bash_var(key: &str, value: &str, prefix: &str) {
    if needs_bash_quoting(value) {
        println!(
            "{}{}=\"{}\"",
            prefix,
            key,
            escape_for_bash_double_quotes(value)
        );
    } else {
        println!("{}{}={}", prefix, key, value);
    }
}

/// Output variable with simple .env format escaping
fn dump_simple_var(key: &str, value: &str, prefix: &str) {
    if needs_simple_quoting(value) {
        println!("{}{}=\"{}\"", prefix, key, escape_for_simple_quotes(value));
    } else {
        println!("{}{}={}", prefix, key, value);
    }
}

/// Checks if a value needs simple quoting (for .env format)
fn needs_simple_quoting(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }

    // Simple check for basic .env format
    value.contains(char::is_whitespace)
        || value.contains('=')
        || value.contains('"')
        || value.contains('\'')
}

/// Escapes a string for use inside simple double quotes (.env format)
fn escape_for_simple_quotes(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Checks if a value needs to be quoted for bash safety
fn needs_bash_quoting(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }

    // Bash special characters that require quoting
    const SPECIAL_CHARS: &[char] = &[
        ' ', '\t', '\n', '\r', // Whitespace
        '$', '`', '\\', // Expansion/escaping
        '"', '\'', // Quotes
        '&', '|', ';', // Command separators
        '<', '>', // Redirection
        '(', ')', '{', '}', // Grouping
        '[', ']', // Globbing
        '*', '?', // Wildcards
        '!', // History expansion (in interactive shells)
        '~', // Tilde expansion
        '#', // Comments
        '=', // Assignment (problematic in some contexts)
    ];

    value.chars().any(|c| SPECIAL_CHARS.contains(&c))
}

/// Escapes a string for use inside bash double quotes
fn escape_for_bash_double_quotes(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            // Characters that need escaping inside double quotes
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '$' => result.push_str("\\$"),
            '`' => result.push_str("\\`"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            // Exclamation mark can trigger history expansion in interactive bash
            // but it's generally safe in scripts and with 'set +H'
            // We'll escape it to be extra safe
            '!' => result.push_str("\\!"),
            _ => result.push(c),
        }
    }
    result
}

/// Escapes a string for use in GNU Make variable assignment (without quotes)
///
/// The value will be stored in a Make variable, exported to the environment,
/// and accessed as $$VAR in shell recipes. We need to escape for Make's
/// processing during the include and variable expansion.
///
/// Key insight: When a Make variable is exported and accessed as $$VAR in a
/// recipe, the value passes through:
/// 1. include/assignment: $$ becomes $ in the variable value
/// 2. export: the variable value is set in the environment
/// 3. recipe: $$VAR expands to the environment variable value
///
/// So we use $$ to get a literal $ in the final environment variable.
fn escape_for_make(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            // Use $$ to get literal $ in the environment variable
            '$' => result.push_str("$$"),
            // Hash starts a comment in Make - escape it
            '#' => result.push_str("\\#"),
            // Backslash needs escaping
            '\\' => result.push_str("\\\\"),
            // Spaces and other chars are fine in Make variable values
            _ => result.push(c),
        }
    }
    result
}

/// Escapes a string for use in GNU Make $(eval ...) statements
///
/// When using $(eval $(shell dotenvage dump --make-eval)), the value passes
/// through:
/// 1. shell: returns the string with $(eval ...) statements
/// 2. $(eval ...): processes the assignment, $$ becomes $
/// 3. Variable is stored and exported
/// 4. Recipe: $$VAR accesses the environment variable
///
/// So we use $$$$ which becomes $$ after eval, then $ in the environment
/// variable, and finally $ in the shell when accessed as $$VAR.
fn escape_for_make_eval(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            // Use $$$$ to get literal $ through eval processing
            '$' => result.push_str("$$$$"),
            // Hash starts a comment in Make - escape it
            '#' => result.push_str("\\#"),
            // Backslash needs escaping
            '\\' => result.push_str("\\\\"),
            // Spaces and other chars are fine in Make variable values
            _ => result.push(c),
        }
    }
    result
}
