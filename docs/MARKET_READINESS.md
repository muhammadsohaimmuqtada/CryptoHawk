# CryptoHawk Market Readiness Gate

CryptoHawk is not declared market ready because the repository looks polished. It is market ready only when a security team can onboard an environment, continuously discover cryptographic exposure, trust tenant isolation and evidence, act on prioritized migration guidance, and operate the platform reliably.

## Commercial pilot gate

All P0 items must be complete and covered by CI before CryptoHawk is described as ready for a serious commercial pilot.

### P0 — product backbone

- [x] Deterministic cryptographic discovery and risk assessment
- [x] TLS/X.509 and source-code collectors
- [x] Persistent findings and CycloneDX 1.7 CBOM export
- [x] Outbound target policy for public SaaS operation
- [x] Workspaces, managed assets, tenant-scoped findings, and scan-job state
- [x] Durable worker queue with leases, retries, cancellation, and crash recovery
- [ ] Scheduled scans and drift detection
- [ ] Repository-native collector with commit identity and incremental scanning
- [ ] Certificate-estate and SSH collectors
- [ ] Container/image collector

### P0 — security boundary

- [x] Authentication and API-key support
- [x] Workspace membership and RBAC enforced at service/data layers
- [ ] Audit log for security-sensitive and administrative actions
- [ ] Rate limits, request quotas, and scan concurrency controls
- [ ] Secret handling policy and encrypted connector credentials
- [ ] Database migrations with tested upgrade/rollback path
- [ ] Security headers, hardened production configuration, and dependency scanning

### P0 — reliability and evidence

- [ ] Idempotent collector runs and deduplicated observations
- [ ] Evidence history and scan provenance retained across rescans
- [ ] Structured application logs, metrics, traces, and health/readiness probes
- [ ] PostgreSQL backup/restore procedure tested
- [ ] Load and soak tests for realistic asset volumes
- [ ] Failure injection for worker/network/database interruptions

### P0 — operator experience

- [ ] Workspace-aware onboarding and asset inventory UI
- [ ] Scan history, failure diagnostics, and rerun controls
- [ ] Migration queue with owner, status, due date, and evidence of remediation
- [ ] Policy packs and organization-specific crypto baselines
- [ ] Exportable executive and engineering reports

## Serious-impact gate

CryptoHawk can be described as making serious practical impact when a pilot environment can demonstrate all of the following with real assets:

1. Discover cryptography across multiple asset classes without manual inventory entry.
2. Preserve evidence and asset identity across repeated scans.
3. Separate organizations/workspaces with tested authorization boundaries.
4. Prioritize high-value migration work using business context, not algorithm names alone.
5. Produce portable CBOM output and remediation evidence that another system can consume.
6. Detect meaningful cryptographic drift between scans.
7. Operate continuously for a sustained pilot without data loss or operator intervention.

Until these gates are satisfied, README/release language must describe CryptoHawk as pre-market or pilot-stage rather than production-ready.
