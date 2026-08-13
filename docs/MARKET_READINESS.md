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
- [x] Scheduled scans and drift detection
- [x] Repository-native collector with commit identity and incremental scanning
- [x] Certificate-estate and SSH collectors
- [x] Container/image collector

Repository scanning supports safe HTTPS Git acquisition, encrypted GitHub/GitLab credentials, full-to-incremental rescans, commit provenance, and drift/history reconciliation. Certificate-estate scanning inventories leaf X.509 key material and signature hashes even when trust validation would fail; SSH scanning negotiates transport only far enough to collect the server host key and does not authenticate or execute commands.

Container-image discovery supports OCI image-layout and Docker image archives. It verifies OCI sha256 content descriptors, supports gzip/uncompressed/zstd layer changesets, applies explicit and opaque whiteouts before scanning the effective filesystem, never extracts image content onto the worker host, strips source snippets from image evidence, and confines managed image locators to a configured read-only archive ingress root.

### P0 — security boundary

- [x] Authentication and API-key support
- [x] Workspace membership and RBAC enforced at service/data layers
- [x] Audit log for security-sensitive and administrative actions
- [x] Rate limits, request quotas, and scan concurrency controls
- [x] Secret handling policy and encrypted connector credentials
- [x] Database migrations with tested upgrade/rollback path
- [x] Security headers, hardened production configuration, and dependency scanning

Connector credential handling is documented in `docs/SECRET_HANDLING.md` and is covered by CI tests for encrypted-at-rest storage, authenticated decryption, tenant isolation, key rotation, RBAC, API redaction, and audit redaction.

### P0 — reliability and evidence

- [x] Idempotent collector runs and deduplicated observations
- [x] Evidence history and scan provenance retained across rescans
- [x] Structured application logs, metrics, traces, and health/readiness probes
- [ ] PostgreSQL backup/restore procedure tested
- [ ] Load and soak tests for realistic asset volumes
- [ ] Failure injection for worker/network/database interruptions

Application telemetry uses structured JSON logs with request/trace/job correlation and token redaction, low-cardinality Prometheus metrics without tenant identifiers, OpenTelemetry spans with W3C trace-context continuation and optional OTLP/HTTP export, and separate liveness/readiness probes. API readiness verifies database connectivity and Docker Compose gates the web tier on API readiness.

Continuous scanning uses deterministic schedule occurrence IDs and per-scan observation IDs so scheduler crashes and worker retries do not create duplicate work or evidence. Successful scans retain scanner/policy provenance, observation occurrences, first/last-seen state, evidence hashes, and drift events.

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
