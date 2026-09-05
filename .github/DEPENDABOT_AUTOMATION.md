# Dependency maintenance

Dependabot checks Cargo, npm, uv and GitHub Actions daily. Compatible updates
and security updates are grouped separately; major updates receive their own PRs.
Security updates must also be enabled in the repository's security settings.

`dependabot-merge.yml` handles completion of the full `CI/CD` workflow. It uses
the shared `merge-tested-dependabot` action without checking out PR code. Only
same-repository Dependabot PRs targeting main, whose current head SHA is the
successfully tested SHA, can be squash-merged. Major updates use the same gate:
there is no unconditional approval or manual version-size exception.

After merging, the handler explicitly dispatches `ci.yml` on main. This is
necessary because pushes made with `GITHUB_TOKEN` do not trigger another push
workflow. The handler needs contents, pull-requests and actions write permission;
the PR test jobs do not receive registry credentials.

Main CI owns version preparation and publication for every releasable change,
not just dependency updates. See [Publishing](PUBLISH.md). Daily main CI also
retries unfinished releases. Failed tests prevent merging; publication failures
leave the release incomplete and visible in Actions. Automation does not make
failing or incompatible dependency changes safe to merge.

Use the Actions and Dependabot dashboards to investigate failed runs. Do not
restore a separate dependency-only publisher or bypass the full CI gate.
