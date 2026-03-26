# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when
working with code in this repository.

## Related Projects

This crate is part of a family of Rust projects that share the same
coding standards, tooling, and workflows:

Cargo plugins:

- `cargo-fmt-toml` - Format and normalize Cargo.toml files
- `cargo-nightly` - Nightly toolchain management
- `cargo-plugin-utils` - Shared utilities for cargo plugins
- `cargo-propagate-features` - Propagate features to dependencies
- `cargo-version-info` - Dynamic version computation

Other Rust crates:

- `dotenvage` - Environment variable management

All projects use identical configurations for rustfmt, clippy,
markdownlint, cocogitto, and git hooks. When making changes to
tooling or workflow conventions, apply them consistently across
all repositories.

## Project Overview

dotenvage is a Rust CLI and library for encrypting secrets in `.env`
files using age encryption (X25519). It enables safe version control
of `.env*` files with encrypted sensitive values.

## Build Commands

```bash
# Build (auto-installs git hooks via rhusky)
cargo build

# Format (requires nightly)
cargo +nightly fmt

# Lint (treats warnings as errors)
cargo clippy --all-targets --all-features -- -D warnings

# Run all tests
cargo test

# Run single test
cargo test test_name

# Doc tests
cargo test --doc

# Build/test npm bindings (from npm/ directory)
npm run build
npm test
```

## Architecture

### Rust Core (`src/`)

- **lib.rs** - Public exports: `SecretManager`, `EnvLoader`, `AutoDetectPatterns`, error types
- **manager.rs** - X25519 encryption/decryption, key discovery, `ENC[AGE:b64:...]` format
- **loader.rs** - `.env*` file loading with power-set layering algorithm, OS/arch normalization
- **main.rs** - CLI implementation (keygen, encrypt, decrypt, edit, set, get, list, dump)
- **error.rs** - `SecretsError` enum and `SecretsResult<T>`

### Node.js Bindings (`npm/`)

- NAPI-RS bindings with pre-built binaries for 9 platforms
- Next.js integration module in `npm/nextjs/`
- Tests in `npm/__tests__/`

### File Layering System

Files load in specificity order (later overrides earlier):
1. `.env` (base)
2. Single-part: `.env.<ENV>`, `.env.<OS>`, `.env.<ARCH>`, `.env.<USER>`,
   `.env.<VARIANT>`
3. Two/three/four/five-part combinations
4. `.env.pr-<NUMBER>` (GitHub Actions)

Placeholders resolved from environment variables with fallbacks.
Dimension values can also be discovered dynamically from loaded files
(e.g., `NODE_ENV=production` in `.env` causes `.env.production` to
load).

## Code Style

- **Rust Edition**: 2024, MSRV 1.94.1
- **Formatting**: Uses nightly rustfmt with vertical imports grouped
  by std/external/crate
- **Clippy**: Nightly with strict settings, `-D warnings` enforced
- **Documentation**: All public items must have docs
- **Security-critical project** - handles encrypted secrets
- **All commits must be signed** (GPG or SSH)

## Git Workflow

- Commits follow Angular Conventional Commits:
  `<type>(<scope>): <subject>`
- Types: feat, fix, docs, refactor, test, style, perf, build, ci,
  chore, revert
- Use lowercase for type, scope, and subject start
- Never bypass git hooks with `--no-verify`
- Never execute `git push` - user must push manually
- Prefer `git rebase` over `git merge` for linear history

Git hooks in `.githooks/` are auto-installed via `rhusky` during
build.

Use detailed multi-line commit messages:

```bash
git commit \
  -m "feat: add feature description" \
  -m "- Bullet point explaining change" \
  -m "- Another detail"
```

## Markdown Formatting

- Maximum line length: 70 characters
- Use `-` for unordered lists (not `*` or `+`)
- Use sentence case for headers (not Title Case)
- Indent nested lists with 2 spaces
- Surround lists and code blocks with blank lines

## Key Discovery Priority

1. `DOTENVAGE_AGE_KEY` env var
2. `AGE_KEY` env var
3. `EKG_AGE_KEY` env var
4. OS user keychain (via `keyring` crate)
5. System-level store (macOS System Keychain,
   `/etc/dotenvage/` on Linux,
   `%ProgramData%\dotenvage\` on Windows)
6. `AGE_KEY_NAME` from `.env` → `$XDG_STATE_HOME/{name}.key`
7. Default: `~/.local/state/dotenvage/dotenvage.key`

## Version Management

Use `cargo version-info bump` (requires v0.0.14+) for version
management. This command updates Cargo.toml and creates a commit,
but does NOT create tags (tags are created by CI after tests pass).

```bash
cargo version-info bump --patch   # 0.0.1 -> 0.0.2
cargo version-info bump --minor   # 0.1.0 -> 0.2.0
cargo version-info bump --major   # 1.0.0 -> 2.0.0
```

**Do NOT use `cog bump`** - it creates local tags which conflict
with CI's tag creation workflow, and requires a clean working tree.

**Workflow:**

1. Create PR with version bump commit
2. Merge PR to main
3. CI detects version change, creates tag, publishes release

Single source of truth is workspace `Cargo.toml`. Version sync across
npm is handled by `scripts/sync-npm-version.sh` (called by
`cargo version-info bump` via `pre_bump_hooks` in Cargo.toml's
`[package.metadata.version-info]` section).
