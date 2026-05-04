# npm Trusted Publishing (OIDC) Setup

This document explains how to configure npm Trusted Publishing with
OpenID Connect (OIDC) to enable secure, token-free publishing from
GitHub Actions.

## Current Status

✅ **Workflow Configuration**: Already correctly configured in
`.github/workflows/ci.yml`

- `id-token: write` permission is set
- `--provenance` flag is used in publish command
- No `NODE_AUTH_TOKEN` secret needed

✅ **npm Configuration**: Trusted Publisher configured on npmjs.com (2
days ago)

⚠️ **Issue**: Versions 0.1.6 and 0.1.7 failed to publish despite
configuration

## Setup Steps

### 1. Navigate to Package Settings

1. Go to: https://www.npmjs.com/package/@dotenvage/node
2. Click on the package name (if not already on the package page)
3. Click **"Package settings"** (or navigate to Settings)

### 2. Configure Trusted Publisher

1. Scroll down to the **"Trusted Publishers"** section
2. Click **"Add Trusted Publisher"** or **"Set up Trusted
   Publishing"**
3. Select **"GitHub Actions"** as the publisher type

### 3. Enter Configuration Details

**All fields are case-sensitive and must match exactly:**

- **Owner**: `dataroadinc`
- **Repository**: `dotenvage` (without the `.git` extension)
- **Workflow filename**: `ci.yml` (the exact filename in
  `.github/workflows/`)
- **Environment**: Leave empty (or create a GitHub environment named
  `npm` if you want additional protection)

### 4. Save Configuration

Click **"Save"** or **"Add Trusted Publisher"** to complete the setup.

## Verification

### Check Trusted Publisher Configuration

1. Go to: https://www.npmjs.com/package/@dotenvage/node
2. Navigate to **Package settings** → **Trusted Publishers**
3. Verify the configuration matches exactly:
   - **Owner**: `dataroadinc` (case-sensitive)
   - **Repository**: `dotenvage` (case-sensitive, no `.git`)
   - **Workflow filename**: `ci.yml` (case-sensitive, exact match)
   - **Environment**: (should be empty or match GitHub environment)

### Verify Workflow Configuration

The workflow file `.github/workflows/ci.yml` should have:

```yaml
publish-npm:
  permissions:
    contents: read
    id-token: write # Required for OIDC
  steps:
    - name: Publish to npmjs.org
      run: pnpm publish --access public --no-git-checks --provenance
```

### Test Publishing

After configuration, the next time the workflow runs (on version
bump), npm publishing should work automatically without any tokens.

To verify it's working:

1. Check GitHub Actions logs for the `publish-npm` job
2. Look for OIDC authentication messages
3. The `--provenance` flag will add supply chain attestations
4. No `NODE_AUTH_TOKEN` secret is needed or should be used

## Troubleshooting

If publishing still fails after configuration:

1. **Double-check all fields match exactly** (case-sensitive):

   - Owner: `dataroadinc`
   - Repository: `dotenvage`
   - Workflow: `ci.yml`

2. **Verify workflow has correct permissions**:

   - Check `.github/workflows/ci.yml` - should have `id-token: write`
     in `publish-npm` job permissions

3. **Ensure npm CLI version supports OIDC**:

   - npm CLI 11.5.1+ is required
   - GitHub Actions uses a recent version, but you can verify in
     workflow logs

4. **Check npm package access**:

   - Ensure you have publish access to `@dotenvage` scope
   - If using an organization, ensure you're a member with publish
     permissions

5. **Review GitHub Actions logs**:

   - Check the `publish-npm` job logs for specific error messages
   - Look for OIDC/authentication errors
   - Common errors:
     - "Workflow not found" → Workflow filename mismatch
     - "Repository not found" → Owner/repository name mismatch
     - "Permission denied" → Missing `id-token: write` permission
     - "Authentication failed" → Trusted Publisher not configured or
       misconfigured

6. **Verify workflow runs on the correct trigger**:

   - The `publish-npm` job runs after `build-and-upload-binaries`
     completes
   - It should run on tag creation (from the `release` job)
   - Check that the workflow file path is `.github/workflows/ci.yml`
     (not `CI.yml` or `ci.yaml`)

7. **Check if pnpm version supports OIDC**:
   - pnpm should use npm's OIDC support
   - Verify pnpm version in workflow (currently using
     pnpm/action-setup@v6)
   - Ensure npm CLI version in the runner supports OIDC (npm 11.5.1+)

## Why OIDC?

**Benefits:**

- ✅ No long-lived tokens to manage
- ✅ Enhanced security (tokens are short-lived and scoped)
- ✅ Supply chain attestations with `--provenance`
- ✅ Better audit trail

**Migration from Token-based Auth:**

- If you previously used `NPM_TOKEN`, you can remove it from GitHub
  Secrets
- The workflow no longer uses `NODE_AUTH_TOKEN` environment variable
- All authentication happens automatically via OIDC

## References

- [npm Trusted Publishers Documentation](https://docs.npmjs.com/trusted-publishers)
- [GitHub Actions OIDC Documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
