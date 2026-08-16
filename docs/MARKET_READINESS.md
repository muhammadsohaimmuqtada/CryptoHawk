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
- [x] PostgreSQL backup/restore procedure tested
- [x] Load and soak tests for realistic asset volumes
- [x] Failure injection for worker/network/database interruptions

Application telemetry uses structured JSON logs with request/trace/job correlation and token redaction, low-cardinality Prometheus metrics without tenant identifiers, OpenTelemetry spans with W3C trace-context continuation and optional OTLP/HTTP export, and separate liveness/readiness probes. API readiness verifies database connectivity and Docker Compose gates the web tier on API readiness.

PostgreSQL disaster recovery uses checksum-protected custom-format backups, refuses non-empty restore targets, restores in a fail-fast single transaction, and is exercised in CI against PostgreSQL 17. The recovery drill verifies restored authentication, workspace/assets, encrypted connector credentials, successful scan evidence/history, schedules, durable queue state, audit events, quota runtime, remediation state, and Alembic revision before the gate passes. The operator procedure is documented in `docs/POSTGRES_DISASTER_RECOVERY.md`.

The PostgreSQL load/soak gate creates a multi-tenant estate and drives sustained durable queue churn through quota-aware claims, heartbeats, transient retries and terminal completion. The CI baseline covers 4 workspaces, 160 managed assets and 800 scan jobs with bounded execution, while validating tenant progress, retry-attempt accounting, stale-lease absence and zero leaked scan capacity. Queue candidate selection is explicitly tested with a saturated tenant backlog deeper than the global candidate window so one tenant cannot hide another tenant that still has capacity.

Failure-injection CI exercises four durability boundaries against PostgreSQL 17: abandoned worker lease recovery, final-attempt lease expiry, transient collector/network failure through the real worker retry path, and a real database stop/restart while a worker owns an active lease. The gate requires replacement-worker recovery, exact retry accounting, SQLAlchemy stale-connection recovery, and zero leaked workspace capacity. The scenarios and limits are documented in `docs/FAILURE_INJECTION.md`.

Continuous scanning uses deterministic schedule occurrence IDs and per-scan observation IDs so scheduler crashes and worker retries do not create duplicate work or evidence. Successful scans retain scanner/policy provenance, observation occurrences, first/last-seen state, evidence hashes, and drift events.

### P0 — operator experience

- [x] Workspace-aware onboarding and asset inventory UI
- [x] Scan history, failure diagnostics, and rerun controls
- [x] Migration queue with owner, status, due date, and evidence of remediation
- [x] Policy packs and organization-specific crypto baselines
- [ ] Exportable executive and engineering reports

The authenticated operator surface supports first-run owner bootstrap, workspace creation and switching, guided registration for the five currently executable managed collectors (TLS, certificate estate, SSH, repository and container image), durable first-scan submission, workspace-scoped asset search/filtering, latest scan state and explicit reruns. Repository onboarding uses the repository-native API so commit identity and drift semantics are preserved; inventory-only asset kinds are not misrepresented as executable collectors. The frontend uses local/system typography and does not depend on third-party font delivery.

The operations history console reads the existing tenant-scoped durable job feed and joins it to managed-asset identity. Operators can filter by execution status, search by asset/locator/job identifier, inspect requested/started/finished timestamps and duration, findings counts and retained failure messages, and explicitly queue a new durable run from terminal jobs. It deliberately reuses the established authorization, quota and queue-submission APIs rather than introducing a parallel control path.

The migration queue promotes a retained managed-asset finding into accountable remediation work keyed to the stable continuous-scanning observation fingerprint. Analysts can assign ownership, priority, due date, migration target, notes and controlled workflow state; accepted risk requires a recorded rationale. `verified` is evidence-only and cannot be set manually: the newest successful scan of the same asset must be newer than the source evidence and must prove that the original cryptographic fingerprint is absent. Failed verification retains the latest risk/evidence details and returns the item to active work. Migration ownership, workflow state, source finding snapshot and fingerprint are also covered by the PostgreSQL backup/restore drill.

Cryptographic policy is a versioned compliance overlay and does not replace or lower CryptoHawk's deterministic core risk score. Workspaces receive immutable built-in baselines and may create immutable custom versions, then explicitly activate one exact version. Managed scans resolve the active policy once per execution and retain policy ID, version and rules hash with findings plus bounded policy provenance in scan history, including zero-finding scans. Policy controls cover key-size floors, TLS minimums, prohibited families, quantum-vulnerable exposure, internet exposure, long-lived/HNDL data, unknown algorithms and evidence-confidence thresholds. Viewer/admin RBAC, tenant isolation, version races, immutable built-ins and PostgreSQL disaster recovery are covered by CI.

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
