# Publishing Guide

This project uses a **version-change detection** workflow for
automated publishing to crates.io.

## Branch Protection & Linear History

The `main` branch is protected with the following rules:

- ✅ **No direct pushes** - all changes via pull requests
- ✅ **Required approvals** - CODEOWNERS must approve
- ✅ **Required CI checks** - all tests must pass
- ✅ **Linear history** - only rebase merges allowed
- ❌ No merge commits or squash merges

This ensures a clean, linear git history.

## How Publishing Works

The CI workflow automatically detects when the version in `Cargo.toml`
changes and:

1. ✅ Runs all checks (format, clippy, build, test, npm tests)
2. ✅ Verifies version sync across Rust and npm packages
3. 📝 Generates changelog from conventional commits
4. 📌 Creates and pushes a git tag (e.g., `v0.0.2`)
5. 🎉 Creates a GitHub Release with generated changelog
6. 📦 Publishes to crates.io (Rust crate)
7. 📦 Publishes to npmjs.org (`@dotenvage/node` package)

**Lock-step releases**: The npm package version is automatically
synced with the Rust crate version, ensuring both are published
together with the same version number.

**No manual tagging required!** Just bump the version in a PR and
merge. Both packages will be published together.

## Setup (One-time)

### 1. Add crates.io Token to GitHub Secrets

1. Get your crates.io API token:

   ```bash
   # Visit https://crates.io/settings/tokens
   # Create a new token with "publish-new" and
   # "publish-update" scopes
   ```

2. Add to GitHub repository secrets:
   - Go to:
     https://github.com/legra-ai/dotenvage/settings/secrets/actions
   - Click "New repository secret"
   - Name: `CRATES_IO` (or `CRATES_IO_TOKEN`)
   - Value: `<your-crates-io-token>`

### 2. Configure npm Trusted Publishing (OIDC)

This project uses npm's **Trusted Publishing** with OpenID Connect
(OIDC) for secure, token-free publishing. No npm tokens are needed!

**Setup Steps:**

1. Navigate to your package on npmjs.com:

   - Go to: https://www.npmjs.com/package/@dotenvage/node
   - Click on the package name, then go to **Package settings**

2. Set up Trusted Publisher:

   - Scroll down to **"Trusted Publishers"** section
   - Click **"Add Trusted Publisher"** or **"Set up Trusted
     Publishing"**
   - Select **"GitHub Actions"** as the publisher type

3. Configure the Trusted Publisher (all fields are case-sensitive):

   - **Owner:** `legra-ai`
   - **Repository:** `dotenvage`
   - **Workflow filename:** `ci.yml` (the exact filename in
     `.github/workflows/`)
   - **Environment:** Leave empty (or create an environment named
     `npm` if you want additional protection)

4. Save the configuration

**Important:** The workflow file name (`ci.yml`) and repository
details must match exactly. The workflow already has the correct
configuration:

- ✅ `id-token: write` permission (required for OIDC)
- ✅ `--provenance` flag in publish command
- ✅ No `NODE_AUTH_TOKEN` needed

**Note**: Make sure you have access to publish to the `@dotenvage`
scope on npm. If you need to create the organization/scope on npm, do
that first.

## Publishing a New Version

### Step-by-Step Process (via Pull Request)

Since the `main` branch is protected, all changes must go through pull
requests:

```bash
# 1. Ensure you're on main and up to date
git checkout main
git pull origin main

# 2. Create a feature branch for the version bump
git checkout -b release/v0.0.2

# 3. Update version in Cargo.toml (npm versions sync automatically)
vim Cargo.toml  # Change version = "0.0.1" to "0.0.2"

# Or use cog to bump version (recommended - syncs all versions automatically):
cog bump --patch  # or --minor, --major
# This will automatically update:
# - Cargo.toml (main crate)
# - npm/dotenvage-napi/Cargo.toml (workspace member)
# - npm/package.json (via sync script)

# 4. Commit the version bump (using conventional
#    commit format)
git add Cargo.toml Cargo.lock npm/package.json npm/dotenvage-napi/Cargo.toml package.json
git commit -m "chore: bump version to 0.0.2"

# 5. Push the branch to GitHub
git push origin release/v0.0.2

# 6. Create a pull request
gh pr create --title "chore: bump version to 0.0.2" \
  --body "Release v0.0.2"

# 7. Review and approve the PR (as CODEOWNER)
# 8. Merge using rebase (to maintain linear history)

# 9. Watch the magic happen! ✨
# After merging, GitHub Actions will automatically:
#   - Run all checks (Rust + npm tests)
#   - Verify version sync across all packages
#   - Generate changelog from commits
#   - Create git tag v0.0.2
#   - Create GitHub Release
#   - Publish to crates.io (Rust crate)
#   - Publish to npmjs.org (@dotenvage/node)
```

### What Gets Published

The changelog will include all commits since the last version with
types:

- ✅ **feat**: New features
- ✅ **fix**: Bug fixes
- ✅ **docs**: Documentation changes
- ✅ **refactor**: Code refactoring
- ✅ **perf**: Performance improvements
- ✅ **build**: Build system changes
- ✅ **revert**: Reverted commits

Excluded from changelog:

- ❌ **style**: Code style changes
- ❌ **test**: Test updates
- ❌ **ci**: CI/CD changes
- ❌ **chore**: Maintenance tasks

## Conventional Commits

All commits should follow the
[Conventional Commits](https://www.conventionalcommits.org/) format:

```bash
<type>(<scope>): <subject>
```

### Examples

```bash
# Features
feat(loader): add Docker architecture detection
feat: support VERCEL_ENV variable

# Bug Fixes
fix(manager): correct Windows path handling
fix: handle empty environment values

# Documentation
docs: update README with new examples
docs(api): improve rustdoc comments

# Refactoring
refactor(loader): simplify env resolution
refactor: extract common logic

# Chores (won't appear in changelog)
chore: bump version to 0.0.2
chore: update dependencies
test: add integration tests
ci: improve workflow caching
```

### Breaking Changes

Use `!` after type and include `BREAKING CHANGE:` footer:

```bash
feat!: change default key location

BREAKING CHANGE: Default key path changed from
~/.config to ~/.local/state
```

## Monitoring the Release

After pushing your version bump:

1. Go to: https://github.com/legra-ai/dotenvage/actions
2. Watch the "CI/CD" workflow
3. The "Release" job will show:
   - Version sync verification
   - Changelog generation
   - Tag creation
   - GitHub Release creation
   - crates.io publication (Rust)
   - npmjs.org publication (Node.js)

## Verification

After the workflow completes:

```bash
# Check the new release
open https://github.com/legra-ai/dotenvage/releases

# Check crates.io (Rust crate)
open https://crates.io/crates/dotenvage

# Check npmjs.org (Node.js package)
open https://www.npmjs.com/package/@dotenvage/node

# Check documentation (Rust)
open https://docs.rs/dotenvage

# Pull the new tag locally
git pull --tags

# Verify npm package (optional)
npm view @dotenvage/node version
```

## Version Bump Types

- **Patch** (0.0.1 → 0.0.2): Bug fixes, minor improvements
- **Minor** (0.0.1 → 0.1.0): New features, backwards compatible
- **Major** (0.0.1 → 1.0.0): Breaking changes

## Troubleshooting

### "Version hasn't changed"

The workflow only runs when the version in `Cargo.toml` differs from
the latest git tag.

**Solution**: Make sure you actually bumped the version number.

### "Changelog is empty"

If no conventional commits exist since the last tag, the changelog
will be minimal.

**Solution**: Use conventional commit format for meaningful commits.

### "Tag already exists"

You can't publish the same version twice.

**Solution**: Bump to a new version number.

### "Authentication failed" (npm)

The npm Trusted Publishing (OIDC) configuration is missing or
incorrect.

**Solution**:

- Verify Trusted Publisher is configured on npmjs.com:
  - Go to https://www.npmjs.com/package/@dotenvage/node → Package
    settings → Trusted Publishers
  - Check that all fields match exactly:
    - Owner: `legra-ai`
    - Repository: `dotenvage`
    - Workflow filename: `ci.yml`
- Ensure the workflow has `id-token: write` permission (already
  configured)
- The publish command uses `--provenance` flag (already configured)
- No `NPM_TOKEN` secret is needed with OIDC

### "Authentication failed" (crates.io)

The crates.io token is missing or invalid.

**Solution**: Check that `CRATES_IO_TOKEN` (or `CRATES_IO`) secret is
set correctly in GitHub settings:

- Go to:
  https://github.com/legra-ai/dotenvage/settings/secrets/actions
- Ensure `CRATES_IO` or `CRATES_IO_TOKEN` exists with a valid token

### "Version mismatch detected"

The CI workflow verifies that all package versions are in sync. If you
see this error, versions don't match across Rust and npm packages.

**Solution**: Ensure all versions are synchronized:

- Check `Cargo.toml`
- Check `npm/package.json`
- Check `npm/dotenvage-napi/Cargo.toml`
- If using `cog bump --patch`, the pre_bump_hooks should sync
  automatically via `scripts/sync-npm-version.sh`

### "CI checks failed"

The release won't happen if any check fails.

**Solution**: Fix the failing checks and push again.

## First Release Checklist

- [x] Version in `Cargo.toml` is `0.0.1`
- [x] Version in `npm/package.json` is `0.0.1` (synced)
- [x] Version in `npm/dotenvage-napi/Cargo.toml` is `0.0.1`
- [x] `LICENSE` file exists
- [x] `README.md` is complete
- [x] All Rust tests pass locally (`cargo test`)
- [x] All npm tests pass locally (`cd npm && pnpm test`)
- [x] Code is formatted (`cargo fmt`)
- [x] Clippy passes (`cargo clippy`)
- [ ] `CRATES_IO` token added to GitHub secrets
- [ ] npm Trusted Publishing (OIDC) configured on npmjs.com
  - [ ] Owner: `legra-ai`
  - [ ] Repository: `dotenvage`
  - [ ] Workflow: `ci.yml`
- [ ] `@dotenvage` scope exists on npmjs.org
- [ ] Have publish access to `@dotenvage` organization on npm
- [ ] Commits follow conventional format
- [ ] Ready to push and release!

## Example Workflow

```bash
# Day 1: Work on features
git checkout -b feat/docker-support
# ... make changes ...
git commit -m "feat(loader): add Docker TARGETARCH detection"
git commit -m "docs: update README with Docker examples"
git push origin feat/docker-support
# Create PR, get review, merge to main

# Day 2: Work on bug fixes
git checkout -b fix/windows-paths
# ... fix bugs ...
git commit -m "fix(manager): handle Windows path separators"
git push origin fix/windows-paths
# Create PR, get review, merge to main

# Day 3: Ready to release!
git checkout main
git pull

# Option 1: Using cog bump (recommended - creates commit automatically)
cog bump --patch  # Automatically syncs all versions and creates commit
git push

# Option 2: Manual version bump
# vim Cargo.toml  # 0.0.1 → 0.0.2
# ./scripts/sync-npm-version.sh 0.0.2
# git add Cargo.toml Cargo.lock npm/package.json npm/dotenvage-napi/Cargo.toml package.json
# git commit -m "chore: bump version to 0.0.2"
# git push

# ✨ Automatic release happens!
# Generated changelog will include:
# - feat(loader): add Docker TARGETARCH detection
# - docs: update README with Docker examples
# - fix(manager): handle Windows path separators
# Both crates.io and npmjs.org will be published with version 0.0.2
```

## Resources

- [Conventional Commits Specification](https://www.conventionalcommits.org/)
- [Cocogitto Documentation](https://github.com/cocogitto/cocogitto)
- [Contributing Guide](CONTRIBUTING.md)
