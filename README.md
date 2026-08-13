# CryptoHawk

**Cryptographic Exposure Management and Post-Quantum Cryptography Readiness Platform**

CryptoHawk discovers cryptography across source repositories and live services, turns observations into an evidence-backed inventory, scores cryptographic and quantum exposure deterministically, recommends migration targets, tracks drift, and exports a CycloneDX 1.7 Cryptography Bill of Materials (CBOM).

> Status: **pre-market engineering build** — authenticated multi-workspace inventory, encrypted connector credentials, durable workers, scheduled scans, drift history, repository-native incremental discovery, TLS/X.509 inspection, certificate-estate discovery, SSH host-key discovery, deterministic risk assessment, CBOM export, REST API, CLI, React command center, Docker deployment and CI are implemented. CryptoHawk is not yet declared production-ready; see `docs/MARKET_READINESS.md`.

## Why CryptoHawk exists

Organizations cannot migrate cryptography they cannot see. CryptoHawk is built around a simple operating model:

`Discover → Normalize → Assess → Prioritize → Migrate → Prove`

The core decision engine is deterministic. Findings carry source evidence, confidence, policy reasons, risk score, quantum status and an explicit migration path instead of relying on opaque AI verdicts.

## Current capabilities

- Source-code cryptographic primitive discovery across common languages and configuration files
- Repository-native Git discovery with commit identity, full-to-incremental rescans and provenance
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
- Risk-prioritized REST API and React command center
- CycloneDX **1.7** CBOM export using `cryptographic-asset` components
- CLI for source, TLS, certificate and SSH scanning, API serving, workers, scheduler and CBOM export
- Docker Compose stack with PostgreSQL, API, worker, scheduler and web UI
- CI for linting, backend tests, dependency audits and frontend production build

## Architecture

```text
Source / Git repositories / TLS / X.509 / SSH
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

# Inspect negotiated TLS cryptography
cryptohawk scan-tls example.com

# Inventory the exposed X.509 certificate
cryptohawk scan-certificate example.com

# Inventory an SSH server host key without authentication
cryptohawk scan-ssh bastion.example.com

# Export current inventory
cryptohawk export-cbom --output cryptohawk-cbom.json
```

Repository assets are registered through the authenticated workspace API and can be executed synchronously, queued to durable workers, or scheduled continuously.

## API

The primary API is workspace-scoped under `/api/v1/workspaces/{workspace_id}` and covers managed assets, repositories, scan jobs, schedules, findings, drift events, crypto state, credentials, audit events and CBOM export. Legacy global endpoints are disabled by default.

Interactive OpenAPI documentation is available at `/docs` while the API is running.

## Standards direction

CryptoHawk is designed around public standards rather than a proprietary inventory format:

- NIST FIPS 203 — ML-KEM
- NIST FIPS 204 — ML-DSA
- NIST FIPS 205 — SLH-DSA
- CycloneDX 1.7 Cryptography Bill of Materials / cryptographic asset model

CryptoHawk-specific risk metadata is emitted as namespaced CycloneDX properties so the CBOM stays portable while retaining operational context.

## Roadmap

The next major slices are container/image cryptography discovery, structured observability and readiness probes, PostgreSQL backup/restore validation, load/soak and failure-injection testing, stronger asset onboarding/operator workflows, migration ownership/status tracking, policy packs, exportable reports and enterprise SSO/OIDC.

### Network scan safety

Network collectors block non-global targets by default and connect to the exact validated DNS answer, avoiding a second resolution between policy evaluation and connection. For a self-hosted enterprise collector that must inspect RFC1918/internal assets, set `CRYPTOHAWK_ALLOW_PRIVATE_TARGETS=true` deliberately at the deployment boundary. Do not enable that option on a shared public SaaS worker.

Certificate-estate collection intentionally inventories the presented certificate without performing trust validation so expired, self-issued or otherwise untrusted certificates can still be discovered. SSH collection performs transport negotiation only far enough to retrieve the server host key; it does not authenticate and does not execute remote commands.

## Security

CryptoHawk is a defensive inventory and migration product. Do not scan systems you do not own or have authorization to assess. Secrets, private keys, runtime databases and generated scanner data are excluded by the repository `.gitignore`.

## License

Apache-2.0
