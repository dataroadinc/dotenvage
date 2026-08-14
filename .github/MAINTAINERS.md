# Maintainer Guide

This document contains information for repository maintainers.

## Security-Critical Project

⚠️ **Important**: dotenvage is a security and cryptography tool. Users
trust us with their encrypted secrets, API keys, and passwords. This
demands:

- **Strict review standards** - Security implications must be
  considered for every change
- **Mandatory signed commits** - Verify authenticity of all code
  changes
- **Linear history** - Makes auditing and rollback simpler
- **Comprehensive CI** - Every commit must pass all checks
- **Zero-warning policy** - Clippy warnings can hide real issues

These requirements are non-negotiable for a security tool.

## GitHub Repository Settings

### Enforce Commit Signing

To ensure all commits are signed, configure branch protection rules:

1. Go to repository **Settings** → **Branches**
2. Edit (or create) branch protection rule for `main`
3. Enable: **"Require signed commits"**
4. Save changes

**To verify current settings:**

```bash
# Using GitHub CLI
gh api repos/agnos-ai/dotenvage/branches/main/protection

# Or check in the web UI:
# https://github.com/legra-ai/dotenvage/settings/branch_protection_rules
```

### Required Branch Protection Rules

**For a security-critical project, ALL of these must be enabled** on
the `main` branch:

- [x] **Require a pull request before merging** ⚠️ REQUIRED
  - Require approvals: 1 minimum
  - Dismiss stale pull request approvals when new commits are pushed
- [x] **Require status checks to pass before merging** ⚠️ REQUIRED
  - Require branches to be up to date before merging
  - Status checks: `fmt`, `clippy`, `build`, `test`
- [x] **Require conversation resolution before merging** ⚠️ REQUIRED
- [x] **Require signed commits** ⚠️ REQUIRED
- [x] **Require linear history** ⚠️ REQUIRED
- [x] **Do not allow bypassing the above settings** ⚠️ REQUIRED
- [x] **Restrict who can push to matching branches** - Maintainers
      only

**Why so strict?** This is a security tool. A compromised commit could
leak users' encrypted secrets. Every safeguard matters.

### Secrets Configuration

Ensure these secrets are configured:

- `CRATES_IO_TOKEN`: For automated publishing to crates.io
  - Generate at: https://crates.io/me
  - Set at: Repository Settings → Secrets → Actions

## Release Process

Releases are automated via GitHub Actions when the version in
`Cargo.toml` changes:

1. Update version in `Cargo.toml`
2. Commit and push to `main`
3. CI will automatically:
   - Create git tag
   - Generate changelog
   - Create GitHub release
   - Publish to crates.io

## Security Review Guidelines

### Threat Model

dotenvage handles:

- Encrypted secrets (passwords, API keys, tokens)
- Cryptographic keys (age/X25519 identities)
- Environment variables that may contain sensitive data

### Review Checklist for Security-Sensitive Changes

When reviewing PRs that touch cryptography, key handling, or file I/O:

- [ ] **Cryptography changes**: Verify age library usage is correct
- [ ] **Key handling**: Ensure keys are never logged or leaked
- [ ] **File permissions**: Check that key files have proper
      permissions (0600)
- [ ] **Input validation**: Validate all user inputs and file contents
- [ ] **Error messages**: Don't leak sensitive info in error messages
- [ ] **Dependencies**: Audit new dependencies for security issues
- [ ] **Tests**: Require tests for all security-critical code paths

### Security Best Practices

- All maintainer commits must be signed
- Review all PRs for security implications - consider threat models
- Never commit secrets, keys, or plaintext sensitive data
- Use age encryption for any sensitive values in test fixtures
- Report security vulnerabilities privately (not via public issues)
- Keep dependencies updated, especially `age`, `base64`, and
  crypto-related crates
