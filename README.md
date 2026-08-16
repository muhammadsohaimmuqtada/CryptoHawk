# CryptoHawk

**Cryptographic Exposure Management and Post-Quantum Cryptography Readiness Platform**

CryptoHawk discovers where cryptography is actually used across repositories, container images and live services; turns observations into an evidence-backed inventory; scores classical and quantum exposure deterministically; applies versioned organization policy; tracks drift and migration ownership; verifies remediation through rescans; and exports engineering, executive and CycloneDX 1.7 evidence.

> **Status: CryptoHawk 0.9 — commercial-pilot candidate.** All repository P0 implementation gates are complete and the exact release path is exercised in CI on PostgreSQL. CryptoHawk is not yet presented as generally available enterprise software: a representative real-world pilot and independent security review remain required before a `1.0` / GA claim. See `docs/MARKET_READINESS.md` and `docs/RELEASE_QUALIFICATION.md`.

## Operating model

Organizations cannot migrate cryptography they cannot see. CryptoHawk is built around one deterministic control loop:

`Discover → Normalize → Assess → Prioritize → Migrate → Prove`

The core decision engine does not depend on an LLM. Findings retain source/evidence identity, confidence, risk score, quantum status, policy result and explicit migration guidance so decisions can be reproduced later.

## What is implemented

### Discovery and evidence

- Source-code cryptographic primitive discovery across common languages and configuration files
- Repository-native HTTPS Git discovery with commit identity, full-to-incremental rescans and provenance
- OCI image-layout and Docker image archive discovery with verified OCI digests and effective-filesystem reconstruction
- Uncompressed, gzip and zstd image-layer support with explicit and opaque whiteout handling
- Live TLS endpoint inspection with negotiated protocol, cipher and X.509 evidence
- Certificate-estate discovery for public-key material, signature hashes, validity, subject/issuer, SANs and fingerprints
- SSH host-key discovery without authentication or remote command execution
- Public-target network policy with DNS pinning; RFC1918/private targets require explicit self-hosted opt-in
- Persistent first/last-seen state, observation occurrence history, evidence hashes and cryptographic drift events

### Risk, PQC and policy

- Deterministic exposure scoring using weakness, quantum risk, internet exposure, data lifetime and business criticality
- Parameter-aware RSA/AES handling
- PQC classification for ML-KEM, ML-DSA and SLH-DSA
- Migration guidance for RSA, DSA, ECDSA, Ed25519/Ed448, ECDH and DH usage
- Immutable built-in policy packs plus versioned custom organization baselines
- Policy controls for key-size floors, TLS minimums, prohibited families, PQ exposure, HNDL/data lifetime, unknown algorithms and evidence confidence
- Exact policy ID/version/rules hash retained with findings and scan history
- Organization policy is an overlay and cannot lower or rewrite CryptoHawk's core risk score

### Migration and proof

- Evidence-backed migration queue with owner, priority, due date, target algorithm and notes
- Controlled remediation states and accepted-risk rationale
- Stable observation fingerprints across rescans
- `Verified` is evidence-only: a newer successful scan must prove the original exposure fingerprint is absent
- Failed verification preserves current evidence and returns work to an active remediation state

### Multi-tenant platform and security

- Authenticated workspaces, memberships and Viewer/Analyst/Admin/Owner RBAC
- High-entropy session/API tokens stored only as hashes
- scrypt password hashing
- Workspace-scoped API keys with bounded roles
- Append-only audit trail for security-sensitive/admin mutations
- DB-backed request quotas, scan-submission limits and workspace concurrency controls
- Tenant-fair durable queue with leases, heartbeat, retry/backoff, cancellation and expired-lease recovery
- AES-256-GCM encrypted connector credentials with versioned environment keyring, authenticated decryption and rotation support
- Safe Git acquisition with explicit host allowlist, redirect/file/ext-protocol blocking, bounded acquisition and ephemeral `GIT_ASKPASS`
- Security headers, redaction and legacy global API disabled by default
- Production runtime fails closed on SQLite, ORM schema auto-create, legacy global API, unsafe CORS or invalid/missing connector encryption keys

### Continuous operation

- Scheduled scans with deterministic occurrence identities
- Idempotent evidence persistence and duplicate-safe retry behavior
- Structured JSON logs with request/trace/job/worker correlation and credential/token redaction
- Low-cardinality Prometheus metrics without tenant identifiers
- OpenTelemetry spans with W3C trace-context continuation and optional OTLP/HTTP export
- Process liveness and database-backed readiness probes
- PostgreSQL 17 backup/restore drill, checksum/tamper rejection and non-empty-target refusal
- PostgreSQL multi-tenant 800-job load/soak gate
- Failure injection for abandoned leases, final-attempt expiry, transient collector/network failures and real database stop/restart

### Operator experience and exports

- Workspace onboarding and guided inventory registration
- Scan history, failure diagnostics and rerun controls
- Migration/remediation operations console
- Policy-baseline management console
- Executive posture reporting
- Engineering evidence reporting
- Formula-injection-safe CSV exports
- Self-contained print-ready executive HTML
- Current-state CycloneDX **1.7** Cryptography Bill of Materials (CBOM)
- Current-state reporting and CBOM consistently exclude resolved exposures

## Architecture

```text
Source / Git / OCI-Docker / TLS / X.509 / SSH
                        │
                        ▼
                 Discovery adapters
                        │
                        ▼
              Normalized CryptoObservation
                        │
                Evidence + confidence
                        │
                        ▼
               Deterministic Risk Engine
                        │
              Versioned Policy Overlay
                        │
                        ▼
             Persistent Active/History State
              │          │          │
              │          │          ├── Drift
              │          ├── Migration queue → Rescan verification
              └── REST/API + Operator UI
                         │
              Executive / Engineering / CBOM
                         │
             Logs / Metrics / OpenTelemetry
```

## Quick start

### Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
cryptohawk serve --host 0.0.0.0 --port 8000
```

In another shell:

```bash
cd frontend
npm ci
npm run dev
```

Open `http://localhost:5173`.

### Development Docker stack

```bash
docker compose up --build
```

Open `http://localhost:3000`.

The base Compose file intentionally contains development credentials/settings. **Do not use it alone for a production/pilot deployment.**

### Controlled production/pilot deployment

Use the production overlay and the runbook in `docs/PRODUCTION_DEPLOYMENT.md`:

```bash
export CRYPTOHAWK_POSTGRES_PASSWORD='<strong-random-password>'
export CRYPTOHAWK_DATABASE_URL='postgresql+psycopg://cryptohawk:<encoded-password>@db:5432/cryptohawk'
export CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS='1:<generated-key>'
export CRYPTOHAWK_CORS_ORIGINS='https://cryptohawk.example.com'

docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  up -d --build
```

Production mode requires PostgreSQL and Alembic migrations and rejects unsafe runtime configuration before the application starts.

## CLI

```bash
# Local source discovery
cryptohawk scan-source ./my-application

# Static OCI/Docker archive discovery
cryptohawk scan-image ./payments-image.tar

# Live public endpoint discovery
cryptohawk scan-tls example.com
cryptohawk scan-certificate example.com
cryptohawk scan-ssh bastion.example.com

# Legacy local inventory export
cryptohawk export-cbom --output cryptohawk-cbom.json
```

Managed repository/image/endpoint assets can be queued to durable workers or scheduled continuously. Managed container assets use a locator such as `image-archive:payments-image.tar`; workers resolve it only beneath `CRYPTOHAWK_CONTAINER_ARCHIVE_ROOT`.

For Docker archives containing multiple images, use the asset tag `image_ref`. For OCI archives containing multiple tagged/platform manifests, use `oci_ref`; the default platform selector is `linux/amd64` and is configurable.

## API

The primary authenticated API is workspace-scoped under `/api/v1/workspaces/{workspace_id}`. It covers:

- workspaces, members and API keys
- managed assets and repositories
- scan jobs, schedules, history and drift
- active cryptographic state and findings
- encrypted connector credentials
- audit events and quotas
- migration/remediation items and evidence verification
- versioned cryptographic policy packs
- executive and engineering reporting
- current-state CycloneDX CBOM

Legacy global endpoints are disabled by default. Interactive OpenAPI documentation is available at `/docs` while the API is running.

### Operational endpoints

- `GET /health/live` — process liveness only
- `GET /health/ready` — live database readiness; HTTP 503 on dependency failure
- `GET /metrics` — Prometheus exposition when enabled

Every API response receives `X-Request-ID`; traced requests also receive `X-Trace-ID`. Incoming W3C `traceparent` headers are continued. Prometheus uses route templates rather than raw workspace/resource paths so tenant IDs do not become metric labels.

## Release qualification

Every pilot candidate is required to pass the exact-head CI matrix:

- backend Ruff + full pytest + pip-audit
- frontend reproducible install + npm audit + TypeScript/Vite build
- PostgreSQL production-mode end-to-end `Discover → Assess → Migrate → Prove` smoke
- PostgreSQL disaster recovery
- PostgreSQL load/soak
- PostgreSQL worker/network/database failure injection

First-party GitHub Actions are pinned to exact release commit SHAs. See `docs/RELEASE_QUALIFICATION.md` and `docs/REPOSITORY_GOVERNANCE.md`.

## Standards direction

CryptoHawk is built around public standards rather than a proprietary cryptography inventory format:

- NIST FIPS 203 — ML-KEM
- NIST FIPS 204 — ML-DSA
- NIST FIPS 205 — SLH-DSA
- CycloneDX 1.7 Cryptography Bill of Materials / cryptographic asset model
- OCI Image Format
- OpenTelemetry / W3C trace context
- Prometheus exposition

CryptoHawk-specific risk and policy metadata is emitted as namespaced CycloneDX properties so the CBOM remains portable while preserving operational context.

## Collector safety

Network collectors block non-global targets by default and connect to the exact validated DNS answer to avoid a second resolution between policy evaluation and connection. Dedicated self-hosted workers may deliberately set `CRYPTOHAWK_ALLOW_PRIVATE_TARGETS=true` for authorized internal assets. Do not enable that on a shared/public worker.

Certificate-estate collection inventories the presented leaf certificate without requiring trust validation so expired/self-issued/untrusted certificates remain discoverable. SSH collection negotiates only far enough to retrieve the server host key; it does not authenticate or execute commands.

Container-image scanning never executes target images and never extracts layer contents onto the worker filesystem. It verifies OCI SHA-256 descriptors, applies layer deletion semantics, enforces archive/layer/file/entry/scan-byte limits and strips source snippets from image-derived evidence.

## Roadmap to 1.0 / GA

The repository implementation P0 is complete. Remaining GA work is evidence and enterprise hardening rather than unfinished core functionality:

- representative real customer/design-partner pilot across multiple asset classes
- independent security review / penetration test and closure of findings
- SSO/OIDC/SAML where required by target customers
- deployment-specific HA/DR and availability commitments
- contractual retention/deletion/privacy controls
- signed/reproducible release and container-image provenance for the chosen distribution channel
- support, incident-response and SLA operating processes

CryptoHawk should remain labeled **0.9 commercial-pilot candidate** until those gates justify a 1.0 claim.

## Security

CryptoHawk is a defensive inventory and migration product. Scan only systems you own or are authorized to assess. Secrets, private keys, runtime databases, container-image ingress and generated scanner data are excluded from the repository.

See `SECURITY.md`, `docs/SECRET_HANDLING.md`, `docs/POSTGRES_DISASTER_RECOVERY.md` and `docs/PRODUCTION_DEPLOYMENT.md`.

## License

Apache-2.0
