# Reusable GitHub Actions

This repository now uses shared actions from
[dataroadinc/github-actions](https://github.com/legra-ai/github-actions).

## Migration Notice

All local actions have been migrated to use the shared actions
repository. Workflows now reference:

```yaml
uses: dataroadinc/github-actions/.github/actions/action-name@main
```

## Available Shared Actions

See the
[shared actions repository](https://github.com/legra-ai/github-actions)
for complete documentation of all available actions.

### Actions Used in This Repository

- `setup-cocogitto` - Install Cocogitto for version management
- `generate-changelog` - Generate changelog from conventional commits

## Usage

```yaml
- name: Setup Cocogitto
  uses: dataroadinc/github-actions/.github/actions/setup-cocogitto@main

- name: Generate changelog
  uses: dataroadinc/github-actions/.github/actions/generate-changelog@main
  with:
    release-tag: v0.1.0
```

## Versioning

All shared actions support versioning via inputs and environment
variables. See the
[shared actions documentation](https://github.com/legra-ai/github-actions)
for details.
