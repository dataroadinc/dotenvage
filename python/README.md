# dotenvage

Python bindings for
[dotenvage](https://github.com/dataroadinc/dotenvage) — encrypt
secrets in `.env` files using age encryption (X25519).

## Installation

```bash
pip install dotenvage
# or with uv
uv add dotenvage
```

## Quick start

```python
import dotenvage

# Generate a new identity (key pair)
manager = dotenvage.SecretManager.generate()
print(f"Public key: {manager.public_key_string()}")

# Encrypt a secret
encrypted = manager.encrypt_value("my-secret-password")
print(f"Encrypted: {encrypted}")
# Output: ENC[AGE:b64:...]

# Decrypt it back
decrypted = manager.decrypt_value(encrypted)
print(f"Decrypted: {decrypted}")
# Output: my-secret-password

# Check if a value is encrypted
print(dotenvage.SecretManager.is_encrypted(encrypted))  # True
print(dotenvage.SecretManager.is_encrypted("plain"))    # False
```

## Loading .env files

```python
import dotenvage

# Load .env files (decrypts encrypted values automatically)
loader = dotenvage.EnvLoader()
loaded_files = loader.load()
print(f"Loaded: {loaded_files}")

# Or get all variables as a dict
variables = loader.get_all_variables()
print(variables)
```

## Auto-detection

dotenvage can detect which keys should be encrypted based on naming
patterns:

```python
import dotenvage

# Keys containing PASSWORD, SECRET, KEY, TOKEN, etc. are detected
dotenvage.should_encrypt("API_KEY")         # True
dotenvage.should_encrypt("DATABASE_URL")    # False
dotenvage.should_encrypt("SECRET_TOKEN")    # True
```

## Key discovery

The `SecretManager` automatically discovers keys in this order:

0. Auto-discover `AGE_KEY_NAME` from `.env` or `.env.local` files
1. `DOTENVAGE_AGE_KEY` environment variable (full identity string)
2. `AGE_KEY` environment variable
3. `EKG_AGE_KEY` environment variable
4. OS keychain entry (service: `dotenvage` or
   `DOTENVAGE_KEYCHAIN_SERVICE`; account: `AGE_KEY_NAME` or
   `{CARGO_PKG_NAME}/dotenvage`)
5. Key file from `AGE_KEY_NAME` → `~/.local/state/{namespace}/{keyname}.key`
6. Default: `~/.local/state/dotenvage/dotenvage.key`

OS keychain lookup currently uses:
- macOS: Keychain via `security`
- Linux/Unix: Secret Service via `secret-tool`
- Windows: lookup falls back to file/env sources (no keychain lookup yet);
  `keygen --store os|both` stores using `cmdkey`

`AGE_KEY_NAME` format is `{namespace}/{keyname}`, e.g., `myapp/production`
→ `~/.local/state/myapp/production.key`

## API reference

### SecretManager

Manager for encrypting and decrypting secrets using age encryption.

```python
class SecretManager:
    def __init__(self) -> None:
        """Create from discovered key file."""

    @staticmethod
    def generate() -> SecretManager:
        """Generate a new random identity (key pair)."""

    @staticmethod
    def from_identity_string(identity: str) -> SecretManager:
        """Create from an age identity string (AGE-SECRET-KEY-...)."""

    @staticmethod
    def is_encrypted(value: str) -> bool:
        """Check if a value is in encrypted format."""

    def public_key_string(self) -> str:
        """Get public key as age1... string."""

    def encrypt_value(self, plaintext: str) -> str:
        """Encrypt to ENC[AGE:b64:...] format."""

    def decrypt_value(self, value: str) -> str:
        """Decrypt if encrypted, otherwise return unchanged."""
```

### EnvLoader

Loader for `.env` files with automatic decryption.

```python
class EnvLoader:
    def __init__(self) -> None:
        """Create with default SecretManager."""

    @staticmethod
    def with_manager(manager: SecretManager) -> EnvLoader:
        """Create with a specific SecretManager."""

    def load(self) -> list[str]:
        """Load .env files from current directory. Returns loaded paths."""

    def load_from_dir(self, dir: str) -> list[str]:
        """Load .env files from specific directory."""

    def get_all_variable_names(self) -> list[str]:
        """Get all variable names from .env files."""

    def get_all_variable_names_from_dir(self, dir: str) -> list[str]:
        """Get all variable names from .env files in directory."""

    def get_all_variables(self) -> dict[str, str]:
        """Load and return all variables as dict (decrypted)."""

    def get_all_variables_from_dir(self, dir: str) -> dict[str, str]:
        """Load and return all variables from directory (decrypted)."""

    def resolve_env_paths(self, dir: str) -> list[str]:
        """Get ordered list of .env file paths that would be loaded."""
```

### Functions

```python
def should_encrypt(key: str) -> bool:
    """Check if key name should be encrypted based on patterns."""
```

## License

[CC-BY-SA-4.0](https://github.com/dataroadinc/dotenvage/blob/main/LICENSE)
