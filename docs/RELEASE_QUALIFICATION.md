# CryptoHawk 0.9 Release Qualification

CryptoHawk 0.9 is the commercial-pilot release line. A commit qualifies only when the repository gates below pass on the exact candidate SHA.

## Automated release gates

The repository workflows must pass all of these jobs:

1. `backend`
   - Ruff
   - full pytest suite with branch coverage collection
   - Python dependency audit
2. `frontend`
   - reproducible `npm ci`
   - high-severity npm dependency audit
   - TypeScript + Vite production build
3. `release-qualification`
   - PostgreSQL 17
   - `CRYPTOHAWK_ENVIRONMENT=production`
   - Alembic migration from an empty database
   - strict policy activation
   - real source discovery and deterministic assessment
   - remediation creation and evidence-backed verification
   - current-state executive/engineering reporting
   - current-state CycloneDX CBOM
   - exact policy provenance across both scans
   - configured evidence retention expires old history while preserving the newest proof
   - full workspace purge succeeds against the production foreign-key graph
4. `postgres-dr`
   - custom-format backup and checksum
   - clean restore
   - restored application invariants
   - rejection of non-empty restore targets
   - rejection of corrupted archives
5. `postgres-load-soak`
   - multi-tenant sustained queue churn
   - retry accounting
   - concurrency/fairness invariants
   - zero leaked capacity
6. `postgres-failure-injection`
   - abandoned worker lease recovery
   - final-attempt expiry
   - transient collector/network retry
   - real PostgreSQL stop/restart and stale-connection recovery
7. `container-build`
   - production Compose configuration renders with required variables
   - backend and frontend container images build from clean inputs
   - backend image runs as the non-root `cryptohawk` user
   - web image runs as the non-root `nginx` user on an unprivileged port
   - nginx configuration validates at runtime
   - backend image exposes the expected CryptoHawk release version
   - package version must match a `v*` release tag when the workflow is tag-triggered
   - a backend wheel, deterministic web archive and source archive are produced
   - CycloneDX JSON SBOMs are generated from both built runtime images
   - every portable release artifact is covered by a SHA-256 checksum manifest
   - the exact bundle is uploaded as a workflow artifact for review
8. `codeql-python` and `codeql-javascript-typescript`
   - GitHub CodeQL security-extended analysis runs on backend and frontend code
   - the action is pinned to the reviewed v4.37.7 release commit

No required job may be skipped or converted to allow-failure for a release candidate.

A green CodeQL job means analysis completed successfully; it does not mean the alert set is empty. Open CodeQL alerts must be reviewed during the manual release review and either fixed or explicitly dispositioned before a pilot release is tagged.

## Build provenance attestations

On a protected `main` push or a `v*` tag push, the successful `container-build` job is followed by `release-provenance`. This job downloads the exact artifact bundle produced by the build job, re-verifies `SHA256SUMS`, and creates a signed GitHub artifact attestation for every subject in that checksum manifest.

The attestation uses GitHub OIDC and Sigstore-backed signing through the pinned `actions/attest` action. Write-capable `id-token`, `attestations`, and `artifact-metadata` permissions exist only on the post-build provenance job; pull-request build jobs retain read-only repository permissions.

For a downloaded artifact from this public repository, verify provenance with GitHub CLI before distribution:

```bash
gh attestation verify <artifact-path> --repo muhammadsohaimmuqtada/CryptoHawk
sha256sum -c SHA256SUMS
```

The provenance covers the portable release bundle and its SBOMs. The current 0.9 workflow does not publish container images to a registry; therefore it does not claim registry-level image provenance. If CryptoHawk later publishes GHCR or another registry image as a supported distribution channel, the pushed image digest must receive its own registry-verifiable attestation before GA.

## Production configuration gate

`CRYPTOHAWK_ENVIRONMENT=production` is intentionally fail-closed. The process refuses to start with SQLite, automatic ORM schema creation, legacy global APIs, unsafe CORS configuration, or missing/invalid connector encryption keys.

This gate is tested separately and also exercised by the PostgreSQL release-qualification job.

## Evidence expected from the release-smoke job

The smoke path is the product promise in executable form:

```text
Discover → Normalize → Assess → Prioritize → Migrate → Prove
```

A release must demonstrate:

- a managed source asset discovers RSA/SHA-1 evidence;
- the Strict Modern policy evaluates the exposure;
- the finding retains the exact immutable policy rules hash;
- migration work is created from the stable finding identity;
- a later clean scan resolves the original observation;
- remediation cannot become Verified except through that later scan;
- active reports contain no resolved exposure;
- the current-state CBOM contains no resolved exposure;
- scan history retains identical policy provenance for both scans;
- timed retention removes eligible historical evidence without deleting the newest verification proof;
- workspace deletion removes the tenant cleanly on PostgreSQL after the proof is complete.

## Manual release review

Before labeling a commit as a pilot release:

- confirm all CI, container-build and CodeQL jobs correspond to the candidate SHA;
- review Python/npm dependency-audit output rather than only job status;
- review the CodeQL alert set and resolve or explicitly disposition every release-relevant alert;
- review migration changes and downgrade/restore strategy;
- verify no secrets, runtime databases or target artifacts are committed;
- confirm backend/web images run non-root and were built by the candidate SHA;
- download the release bundle and verify `SHA256SUMS`;
- verify each distributed artifact's GitHub attestation before publishing it outside the workflow;
- inspect both CycloneDX runtime-image SBOMs for the candidate build;
- confirm README/status language says commercial-pilot candidate, not GA;
- confirm `docs/MARKET_READINESS.md` still distinguishes repository P0 completion from real-world pilot evidence;
- confirm production deployment configuration uses the runbook in `docs/PRODUCTION_DEPLOYMENT.md`.

## Remaining evidence before GA

Repository qualification is necessary but not sufficient for broad enterprise GA. Before a `1.0` / generally available claim, collect:

- representative real customer/design-partner pilot evidence across multiple collector classes;
- an independent application/security review or penetration test with findings closed;
- deployment-specific HA/DR validation where HA is promised;
- documented commercial privacy/legal obligations for the intended deployment model;
- SSO/SAML/OIDC if required by target enterprise customers;
- registry-level signed provenance if container images become a supported published distribution channel;
- customer support, incident-response and SLA operating procedures.

Until those are complete, the correct claim is **CryptoHawk 0.9 — commercial-pilot candidate**.
