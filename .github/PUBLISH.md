# Publishing

`.github/workflows/ci.yml` is the only release pipeline. Main pushes, explicit
dispatches and daily scheduled runs enter the same pipeline; tags do not start
a separate publisher.

## Version and source identity

The shared `prepare-cargo-release` action considers every commit since the last
release: fixes and dependency changes produce a patch, features a minor, and
declared breaking changes a major. Documentation, style and CI-only commits do
not independently release. An explicitly higher manifest version is respected.

When needed, `cargo version-info` updates Rust manifests and lockfiles and runs
the configured companion-version hook for npm, Python and the root package.
GitHub records one verified version commit, guarded by the expected main SHA.
All downstream checks, builds and publishers check out that exact revision.
The version commit's bot push does not start another release pipeline.

## Validation and publication

Rust formatting, Clippy and tests, npm tests, Python tests and platform builds
must succeed before creating the immutable version tag and draft GitHub release.
All registry versions remain synchronized. CLI artifacts attach to the release;
Rust, npm and Python packages publish to their registries. The GitHub release
becomes public only after all publishers succeed.

Publication is not an atomic transaction across registries. A partially completed
release is retried at its original tagged revision before preparing a newer one.
Crates.io retries verify the published package's source revision; conflicting
tags or crate revisions fail. Existing npm versions and Python wheels use their
publishers' existing duplicate handling. Never move a tag to bypass a failure.

## Credentials and recovery

- `CRATES_IO_TOKEN` must authorize publishing dotenvage.
- npm and PyPI trusted publishers must authorize this repository and `ci.yml`.
- The `pypi` environment is used for publication and must not require a human
  approval if unattended release is required.
- Version preparation and release jobs need contents write permission;
  publication also needs id-token write permission for trusted publishing.

Daily scheduled runs and manual `gh workflow run ci.yml --ref main` use the same
recovery path. Never invoke a second publisher to repair a failed release.
Monitor Actions failures and credential expiry; failing validation blocks release.

Dependency updates use the same pipeline. See
[Dependency maintenance](DEPENDABOT_AUTOMATION.md).
