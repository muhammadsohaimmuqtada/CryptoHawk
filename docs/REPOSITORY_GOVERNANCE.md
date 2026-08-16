# Repository Governance

CryptoHawk release integrity depends on repository controls as well as application code.

## Required `main` branch policy

The `main` branch must be protected with the following repository settings:

- Require a pull request before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging, or use GitHub merge-queue semantics that test the final merge candidate.
- Require these checks:
  - `backend`
  - `frontend`
  - `release-qualification`
  - `postgres-dr`
  - `postgres-load-soak`
  - `postgres-failure-injection`
  - `container-build`
- Do not allow force pushes.
- Do not allow branch deletion.
- Apply the rule to administrators where the repository plan/settings allow it.
- Prefer squash merges for feature PRs so each merged change has one auditable product-level commit.

The repository treats exact-head CI as a merge invariant even when GitHub-side protection is unavailable. GitHub-side protection should still be enabled because policy must not depend on operator memory.

## CI supply-chain policy

First-party GitHub Actions are pinned to exact commit SHAs. Human-readable release versions are retained as comments in the workflow.

When updating an action:

1. inspect the official `actions/*` release;
2. resolve the exact tag to a commit SHA;
3. update the workflow SHA and version comment together;
4. require the complete CryptoHawk CI and container-build matrix on the resulting PR.

Do not replace a commit pin with a floating branch or unverified third-party action.

## Dependency updates

Dependabot is configured for Python, npm and GitHub Actions. Dependency PRs must pass the same security, reliability, container and release-qualification matrix as application changes.

Security-sensitive dependency updates should be reviewed for behavioral changes in cryptography, SSH/TLS, SQL/database, authentication and telemetry boundaries rather than merged solely because the dependency audit is green.

## Release branches and tags

`0.9.x` denotes controlled commercial-pilot candidates. Do not tag `1.0.0` or use generally-available language until the GA evidence in `docs/RELEASE_QUALIFICATION.md` is complete.

Tags/releases must point to commits already merged to protected `main` and must not be created from an unmerged feature branch.

## Secrets

Repository secrets are only for CI/deployment credentials that cannot be represented ephemerally. Tests should generate temporary cryptographic material at runtime where practical.

Never commit customer credentials, connector tokens, production database URLs, encryption keys, target repositories, private container images, scan databases or generated evidence bundles.
