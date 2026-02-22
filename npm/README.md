# @dotenvage/node

[![npm version](https://badge.fury.io/js/%40dotenvage%2Fnode.svg)](https://www.npmjs.com/package/@dotenvage/node)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/dataroadinc/dotenvage/blob/main/LICENSE)

Node.js bindings for
[dotenvage](https://github.com/dataroadinc/dotenvage) - **Dotenv with
age encryption**.

## Features

- 🔒 **Encrypt secrets in `.env` files** - Safely commit encrypted
  secrets to version control
- 📦 **Native performance** - Built with NAPI-RS for fast Rust
  performance
- 🔄 **Auto-detection** - Automatically identifies which keys should
  be encrypted
- 🌳 **File layering** - Multiple `.env*` files with automatic
  precedence
- 💻 **CLI support** - Includes `dotenvage` command-line tool
- 📝 **TypeScript support** - Full TypeScript definitions included

## Installation

```bash
npm install @dotenvage/node
```

## Quick Start

### Basic Usage (Like dotenv)

```typescript
import * as dotenvage from "@dotenvage/node";

// Load encrypted .env files into process.env
const loader = dotenvage.JsEnvLoaderNew();
loader.load(); // Mutates process.env (like dotenv.config())

// Now access variables
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
```

### Get Variables as Object (Non-mutating)

```typescript
import * as dotenvage from "@dotenvage/node";

const loader = dotenvage.JsEnvLoaderNew();
const env = loader.getAllVariables(); // Returns Record<string, string>

// Use without modifying process.env
console.log(env.API_KEY);
console.log(env.DATABASE_URL);
```

### Encrypt and Decrypt Values

```typescript
import * as dotenvage from "@dotenvage/node";

// Generate a new key pair
const manager = dotenvage.JsSecretManagerGenerate();
const publicKey = manager.publicKeyString(); // Share this public key

// Encrypt a secret
const secret = "sk_live_abc123";
const encrypted = manager.encryptValue(secret);
// Returns: "ENC[AGE:b64:...]"

// Decrypt it back
const decrypted = manager.decryptValue(encrypted);
console.log(decrypted === secret); // true
```

## API Reference

### JsEnvLoader

Loads and decrypts `.env` files.

#### `JsEnvLoaderNew(): JsEnvLoader`

Creates a new loader with a default SecretManager.

```typescript
const loader = dotenvage.JsEnvLoaderNew();
```

#### `load(): void`

Loads `.env` files from the current directory into `process.env`.

```typescript
loader.load(); // Sets variables in process.env
```

#### `loadFromDir(dir: string): void`

Loads `.env` files from a specific directory.

```typescript
loader.loadFromDir("./config");
```

#### `getAllVariableNames(): string[]`

Gets all variable names from all loaded `.env` files (without loading
into environment).

```typescript
const names = loader.getAllVariableNames();
console.log(names); // ["API_KEY", "DATABASE_URL", ...]
```

#### `getAllVariables(): Record<string, string>`

Gets all environment variables as an object (decrypted). Note: This
loads variables into the process environment first.

```typescript
const env = loader.getAllVariables();
console.log(env.API_KEY);
```

#### `resolveEnvPaths(dir: string): string[]`

Computes the ordered list of env file paths that would be loaded.

```typescript
const paths = loader.resolveEnvPaths(".");
console.log(paths); // [".env", ".env.local", ...]
```

### JsSecretManager

Manages encryption and decryption of secrets.

#### `JsSecretManagerGenerate(): JsSecretManager`

Generates a new random encryption key pair.

```typescript
const manager = dotenvage.JsSecretManagerGenerate();
```

#### `JsSecretManagerNew(): JsSecretManager`

Creates a SecretManager by loading the key from standard locations:

1. `DOTENVAGE_AGE_KEY` environment variable
2. `AGE_KEY` environment variable
3. `EKG_AGE_KEY` environment variable
4. OS keychain entry (service: `dotenvage` or `DOTENVAGE_KEYCHAIN_SERVICE`;
   account: `AGE_KEY_NAME` or `{CARGO_PKG_NAME}/dotenvage`)
5. Key file at `~/.local/state/dotenvage/dotenvage.key`

OS keychain lookup currently uses:
- macOS: Keychain via `security`
- Linux/Unix: Secret Service via `secret-tool`
- Windows: lookup falls back to file/env sources (no keychain lookup yet);
  `keygen --store os|both` stores using `cmdkey`

```typescript
const manager = dotenvage.JsSecretManagerNew();
```

#### `publicKeyString(): string`

Gets the public key as a string (starts with `age1`).

```typescript
const publicKey = manager.publicKeyString();
```

#### `encryptValue(plaintext: string): string`

Encrypts a plaintext value.

```typescript
const encrypted = manager.encryptValue("secret");
```

#### `decryptValue(value: string): string`

Decrypts a value if it's encrypted; otherwise returns it unchanged.

```typescript
const decrypted = manager.decryptValue(encrypted);
```

#### `isEncrypted(value: string): boolean`

Checks if a value is in a recognized encrypted format.

```typescript
const isEncrypted = manager.isEncrypted("ENC[AGE:b64:...]");
```

### Utility Functions

#### `shouldEncrypt(key: string): boolean`

Checks if a key name should be encrypted based on auto-detection
patterns.

```typescript
dotenvage.shouldEncrypt("API_KEY"); // true
dotenvage.shouldEncrypt("PORT"); // false
```

## CLI Usage

The package includes a `dotenvage` CLI command:

```bash
npx dotenvage list
npx dotenvage get API_KEY
npx dotenvage dump --export
```

See the
[main dotenvage README](https://github.com/dataroadinc/dotenvage#usage)
for full CLI documentation.

## Next.js Integration

For Next.js applications, use the dedicated integration utilities:

```typescript
// In next.config.mjs
import { loadEnv } from "@dotenvage/node/nextjs";
loadEnv();
```

Or use the pre-initialization loader to ensure environment variables
are available for Edge Runtime (middleware):

```json
{
  "scripts": {
    "dev": "node -r @dotenvage/node/nextjs/preinit node_modules/.bin/next dev"
  }
}
```

See [`nextjs/README.md`](./nextjs/README.md) for complete Next.js
integration documentation.

## TypeScript Examples

See the `examples/` directory for TypeScript examples:

- `load-env.ts` - Loading environment variables
- `encrypt-decrypt.ts` - Encryption and decryption
- `app-config.ts` - Type-safe application configuration
- `auto-encrypt.ts` - Auto-detection patterns
- `nextjs-config.ts` - Basic Next.js usage example

## File Layering

dotenvage supports automatic file layering with precedence:

1. `.env` - Base configuration
2. `.env.<ENV>` - Environment-specific (e.g., `.env.production`)
3. `.env.<ENV>.<OS>` - OS-specific (e.g., `.env.production.linux`)
4. `.env.<ENV>.<OS>.<ARCH>` - Architecture-specific
5. `.env.<ENV>.<OS>.<ARCH>.<USER>` - User-specific overrides
6. `.env.<ENV>.<OS>.<ARCH>.<USER>.<VARIANT>` - Variant-specific
   (e.g., `.env.production.linux.amd64.alice.docker`)

Files are loaded in specificity order - more specific files override
less specific ones. Dimension values can also be discovered from
loaded files (e.g., `NODE_ENV=production` in `.env` causes
`.env.production` to load).

## Key Management

### Setting the Encryption Key

Set one of these environment variables:

```bash
export DOTENVAGE_AGE_KEY="AGE-SECRET-KEY-1..."
export AGE_KEY="AGE-SECRET-KEY-1..."
export EKG_AGE_KEY="AGE-SECRET-KEY-1..."
```

### Generating a Key

```typescript
const manager = dotenvage.JsSecretManagerGenerate();
const publicKey = manager.publicKeyString();
console.log(`Public key: ${publicKey}`);
console.log(`Set: export DOTENVAGE_AGE_KEY="<private-key>"`);
```

Or use the CLI:

```bash
npx dotenvage keygen
```

## Comparison with dotenv

| Feature              | dotenv | @dotenvage/node |
| -------------------- | ------ | --------------- |
| Load `.env` files    | ✅     | ✅              |
| Mutate `process.env` | ✅     | ✅              |
| Encrypt secrets      | ❌     | ✅              |
| Commit to git safely | ❌     | ✅              |
| File layering        | ❌     | ✅              |
| Auto-detection       | ❌     | ✅              |
| Native performance   | ❌     | ✅ (Rust)       |

## Requirements

- Node.js >= 18.0.0
- Valid age encryption key (set via environment variable or key file)

## Building from Source

From the `npm/` directory:

```bash
cd npm
npm install
npm run build
```

Or from the project root:

```bash
npm run npm:install
npm run npm:build
```

## License

MIT - See
[LICENSE](https://github.com/dataroadinc/dotenvage/blob/main/LICENSE)

## Links

- [GitHub Repository](https://github.com/dataroadinc/dotenvage)
- [Rust Crate](https://crates.io/crates/dotenvage)
- [Rust Documentation](https://docs.rs/dotenvage)
- [Main README](https://github.com/dataroadinc/dotenvage#readme)
