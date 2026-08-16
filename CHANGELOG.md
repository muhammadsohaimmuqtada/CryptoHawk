# Changelog

All notable CryptoHawk release-line changes are recorded here.

## 0.9.0 — Commercial pilot candidate

### Added

- Multi-workspace authentication, membership RBAC, hashed sessions/API keys and append-only audit events.
- Source, repository, TLS/X.509, certificate-estate, SSH and OCI/Docker image cryptography collectors.
- Safe public-target network policy, repository acquisition controls and encrypted GitHub/GitLab connector credentials.
- Deterministic cryptographic/PQC risk assessment and NIST PQC migration guidance.
- Durable scan queue, quotas, tenant-fair concurrency, retries, cancellation, schedules and drift history.
- Versioned organization cryptographic policy packs with immutable scan provenance.
- Evidence-backed migration/remediation workflow with rescan-only verification.
- Executive/engineering reports, hardened CSV exports and current-state CycloneDX 1.7 CBOM.
- Structured logs, Prometheus metrics, OpenTelemetry tracing, liveness/readiness probes.
- PostgreSQL backup/restore, load/soak and worker/network/database failure-injection CI gates.
- Workspace onboarding, inventory, scan history, migration, policy and reporting operator surfaces.
- Fail-closed production configuration validation and a PostgreSQL end-to-end release-qualification gate.
- Production Compose overlay and deployment/rollback runbooks.

### Security and reliability

- Connector secrets use AES-256-GCM with versioned keys and authenticated tenant/credential context.
- Repository collection is HTTPS-only, host-allowlisted, redirect-disabled, protocol-restricted and bounded.
- Container scanning is static, path-confined and non-executing with OCI digest verification and layer whiteout semantics.
- First-party GitHub Actions are pinned to reviewed release commit SHAs.
- Dependency audits run for Python and frontend production dependencies.

### Release status

0.9.0 is qualified for controlled commercial/design-partner pilots. It is not a generally available 1.0 release. Representative external pilot evidence and an independent security review remain required before GA language is used.
