# CryptoHawk 0.9 Release Qualification

CryptoHawk 0.9 is the commercial-pilot release line. A commit qualifies only when the repository gates below pass on the exact candidate SHA.

## Automated release gates

The CI workflow must pass all of these jobs:

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

No job may be skipped or converted to allow-failure for a release candidate.

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
- scan history retains identical policy provenance for both scans.

## Manual release review

Before labeling a commit as a pilot release:

- confirm all CI jobs correspond to the candidate SHA;
- review dependency-audit output rather than only job status;
- review migration changes and downgrade/restore strategy;
- verify no secrets, runtime databases or target artifacts are committed;
- confirm README/status language says commercial-pilot candidate, not GA;
- confirm `docs/MARKET_READINESS.md` still distinguishes repository P0 completion from real-world pilot evidence;
- confirm production deployment configuration uses the runbook in `docs/PRODUCTION_DEPLOYMENT.md`.

## Remaining evidence before GA

Repository qualification is necessary but not sufficient for broad enterprise GA. Before a `1.0` / generally available claim, collect:

- representative real customer/design-partner pilot evidence across multiple collector classes;
- an independent application/security review or penetration test with findings closed;
- deployment-specific HA/DR validation where HA is promised;
- documented retention/deletion/privacy obligations for the intended commercial model;
- SSO/SAML/OIDC if required by target enterprise customers;
- signed/reproducible release and container-image provenance appropriate to the distribution channel;
- customer support, incident-response and SLA operating procedures.

Until those are complete, the correct claim is **CryptoHawk 0.9 — commercial-pilot candidate**.
