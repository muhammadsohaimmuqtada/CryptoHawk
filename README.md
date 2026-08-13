# CryptoHawk

**Cryptographic Exposure Management and Post-Quantum Cryptography Readiness Platform**

CryptoHawk discovers cryptography across source repositories, container images and live services, turns observations into an evidence-backed inventory, scores cryptographic and quantum exposure deterministically, recommends migration targets, tracks drift, and exports a CycloneDX 1.7 Cryptography Bill of Materials (CBOM).

> Status: **pre-market engineering build** — authenticated multi-workspace inventory, encrypted connector credentials, durable workers, scheduled scans, drift history, repository-native incremental discovery, OCI/Docker image archive discovery, TLS/X.509 inspection, certificate-estate discovery, SSH host-key discovery, deterministic risk assessment, CBOM export, structured telemetry, REST API, CLI, React command center, Docker deployment and CI are implemented. CryptoHawk is not yet declared production-ready; see `docs/MARKET_READINESS.md`.

## Why CryptoHawk exists

Organizations cannot migrate cryptography they cannot see. CryptoHawk is built around a simple operating model:

`Discover → Normalize → Assess → Prioritize → Migrate → Prove`

The core decision engine is deterministic. Findings carry source evidence, confidence, policy reasons, risk score, quantum status and an explicit migration path instead of relying on opaque AI verdicts.

## Current capabilities

- Source-code cryptographic primitive discovery across common languages and configuration files
- Repository-native Git discovery with commit identity, full-to-incremental rescans and provenance
- OCI image-layout and Docker image archive discovery with verified OCI digests and effective-filesystem reconstruction
- Container layer support for uncompressed, gzip and zstd changesets with explicit and opaque whiteout handling
- Encrypted GitHub/GitLab connector credentials with workspace-scoped access controls
- Live TLS endpoint inspection with negotiated protocol, cipher and X.509 evidence
- Certificate-estate discovery for leaf public-key material, signature hashes, validity, subject/issuer, SANs and fingerprints
- SSH host-key discovery without authentication or remote command execution
- Public-target network guard with DNS pinning; private targets require explicit self-hosted opt-in
- Parameter-aware rules for RSA and AES key sizes
- PQC classification for ML-KEM, ML-DSA and SLH-DSA
- Migration recommendations for RSA, DSA, ECDSA, Ed25519/Ed448, ECDH and DH usage
- Persistent inventory via SQLite locally or PostgreSQL in deployment
- Authenticated workspaces, membership/RBAC, API keys, audit events, quotas and scan concurrency controls
- Durable scan queue with leases, retries, cancellation and crash reconciliation
- Scheduled scans, evidence history and cryptographic drift detection
- Structured JSON application logs with request, trace and scan-job correlation plus credential/token redaction
- Prometheus request/scan/worker/scheduler/readiness metrics with low-cardinality labels and no tenant identifiers
- OpenTelemetry spans with W3C trace-context continuation and optional OTLP/HTTP export
- Process liveness and database-backed readiness probes; Compose gates the web tier on API readiness
- Risk-prioritized REST API and React command center
- CycloneDX **1.7** CBOM export using `cryptographic-asset` components
- CLI for source, image, TLS, certificate and SSH scanning, API serving, workers, scheduler and CBOM export
- Docker Compose stack with PostgreSQL, API, worker, scheduler, read-only image ingress and web UI
- CI for linting, backend tests, dependency audits and frontend production build

## Architecture

```text
Source / Git repositories / OCI-Docker images / TLS / X.509 / SSH
                          │
                          ▼
                   Discovery adapters
                          │
                          ▼
                 Normalized CryptoObservation
                          │
                          ├──── Evidence + confidence + provenance
                          ▼
                 Deterministic Risk Engine
                          │
                          ├──── Quantum status
                          ├──── Exposure score
                          ├──── Migration target
                          ▼
                   Persistent Inventory
                          │
                          ├──── History + drift
                          ├──── REST API
                          ├──── React Dashboard
                          └──── CycloneDX 1.7 CBOM
                          │
                          └──── JSON logs / Prometheus / OpenTelemetry
```

## Quick start

### Local backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
cryptohawk serve --host 0.0.0.0 --port 8000
```

### Dashboard

```bash
cd frontend
npm ci
npm run dev
```

Open `http://localhost:5173`.

### Full stack

```bash
docker compose up --build
```

Open `http://localhost:3000`.

## CLI

```bash
# Scan a local source tree
cryptohawk scan-source ./my-application

# Scan an OCI layout tar or `docker save` archive
cryptohawk scan-image ./payments-image.tar

# Inspect negotiated TLS cryptography
cryptohawk scan-tls example.com

# Inventory the exposed X.509 certificate
cryptohawk scan-certificate example.com

# Inventory an SSH server host key without authentication
cryptohawk scan-ssh bastion.example.com

# Export current inventory
cryptohawk export-cbom --output cryptohawk-cbom.json
```

Repository and managed asset scans can be executed synchronously, queued to durable workers, or scheduled continuously. Managed container assets use a locator such as `image-archive:payments-image.tar`; workers resolve that relative path only inside `CRYPTOHAWK_CONTAINER_ARCHIVE_ROOT`. In Docker Compose the host-side ingress defaults to `./container-images` and is mounted read-only into the API and worker containers.

For archives containing multiple Docker images, set the managed asset tag `image_ref` to the desired `RepoTag`. For OCI archives containing multiple tagged/platform manifests, use `oci_ref`; the default platform selector is `linux/amd64` and is configurable.

## API

The primary API is workspace-scoped under `/api/v1/workspaces/{workspace_id}` and covers managed assets, repositories, scan jobs, schedules, findings, drift events, crypto state, credentials, audit events and CBOM export. Legacy global endpoints are disabled by default.

Interactive OpenAPI documentation is available at `/docs` while the API is running.

### Operational endpoints

- `GET /health/live` — process liveness only; it does not depend on the database.
- `GET /health/ready` — readiness check with a live database query; returns HTTP 503 when the database is unavailable.
- `GET /metrics` — Prometheus exposition when `CRYPTOHAWK_METRICS_ENABLED=true`.

Every API response receives `X-Request-ID`; traced requests also receive `X-Trace-ID`. Incoming W3C `traceparent` headers are continued rather than replaced. Prometheus labels use route templates rather than raw workspace/resource paths so tenant IDs do not become metric labels.

Set `CRYPTOHAWK_OTEL_TRACES_ENDPOINT` to an OTLP/HTTP traces endpoint such as `http://otel-collector:4318/v1/traces` to export spans. Leaving it empty preserves local trace correlation without requiring an external collector.

## Standards direction

CryptoHawk is designed around public standards rather than a proprietary inventory format:

- NIST FIPS 203 — ML-KEM
- NIST FIPS 204 — ML-DSA
- NIST FIPS 205 — SLH-DSA
- CycloneDX 1.7 Cryptography Bill of Materials / cryptographic asset model
- OCI Image Format for image manifests, content descriptors and filesystem layer changesets
- OpenTelemetry for distributed tracing and OTLP export
- Prometheus exposition for operational metrics

CryptoHawk-specific risk metadata is emitted as namespaced CycloneDX properties so the CBOM stays portable while retaining operational context.

## Roadmap

The next major reliability slices are PostgreSQL backup/restore validation, load/soak testing and failure injection for worker/network/database interruptions. Product work then moves into stronger asset onboarding/operator workflows, migration ownership/status tracking, policy packs, exportable reports, native registry ingestion and enterprise SSO/OIDC.

### Collector safety

Network collectors block non-global targets by default and connect to the exact validated DNS answer, avoiding a second resolution between policy evaluation and connection. For a self-hosted enterprise collector that must inspect RFC1918/internal assets, set `CRYPTOHAWK_ALLOW_PRIVATE_TARGETS=true` deliberately at the deployment boundary. Do not enable that option on a shared public SaaS worker.

Certificate-estate collection intentionally inventories the presented certificate without performing trust validation so expired, self-issued or otherwise untrusted certificates can still be discovered. SSH collection performs transport negotiation only far enough to retrieve the server host key; it does not authenticate and does not execute remote commands.

Container-image scanning never extracts layer contents to the worker filesystem. It verifies OCI sha256 blobs, applies image-layer deletion semantics before discovery, enforces archive/layer/file/entry/scan-byte limits, and removes source snippets from image-derived evidence to reduce accidental secret disclosure. Managed image paths are confined to a dedicated archive root.

## Security

CryptoHawk is a defensive inventory and migration product. Do not scan systems you do not own or have authorization to assess. Secrets, private keys, runtime databases, container image ingress and generated scanner data are excluded by the repository `.gitignore`.

## License

Apache-2.0
