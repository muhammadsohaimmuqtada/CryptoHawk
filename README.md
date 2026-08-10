# CryptoHawk

**Cryptographic Exposure Management and Post-Quantum Cryptography Readiness Platform**

CryptoHawk discovers cryptography across code and live services, turns observations into an evidence-backed inventory, scores cryptographic and quantum exposure deterministically, recommends migration targets, and exports a CycloneDX 1.7 Cryptography Bill of Materials (CBOM).

> Status: **v0.1 foundation** — source discovery, TLS/X.509 inspection, risk engine, persistent inventory, CBOM export, REST API, CLI, React command center, Docker deployment and CI are implemented.

## Why CryptoHawk exists

Organizations cannot migrate cryptography they cannot see. CryptoHawk is built around a simple operating model:

`Discover → Normalize → Assess → Prioritize → Migrate → Prove`

The core decision engine is deterministic. Findings carry source evidence, confidence, policy reasons, risk score, quantum status and an explicit migration path instead of relying on opaque AI verdicts.

## Current capabilities

- Source-code cryptographic primitive discovery across common languages and configuration files
- Live TLS endpoint inspection with negotiated protocol, cipher and X.509 public-key evidence
- Public-target network guard with DNS pinning; private targets require explicit self-hosted opt-in
- Parameter-aware rules for RSA and AES key sizes
- PQC classification for ML-KEM, ML-DSA and SLH-DSA
- Migration recommendations for quantum-vulnerable RSA, ECDSA, ECDH and DH usage
- Persistent inventory via SQLite locally or PostgreSQL in deployment
- Risk-prioritized REST API and React command center
- CycloneDX **1.7** CBOM export using `cryptographic-asset` components
- CLI for source scanning, TLS scanning, API serving and CBOM export
- Docker Compose stack with PostgreSQL, API and web UI
- CI for linting, tests, coverage and frontend production build

## Architecture

```text
Source / TLS / X.509
        │
        ▼
 Discovery adapters
        │
        ▼
Normalized CryptoObservation
        │
        ├──── Evidence + confidence
        ▼
Deterministic Risk Engine
        │
        ├──── Quantum status
        ├──── Exposure score
        ├──── Migration target
        ▼
Persistent Inventory
        │
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
npm install
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
# Scan a repository or source tree
cryptohawk scan-source ./my-application

# Inspect a TLS endpoint
cryptohawk scan-tls example.com

# Export current inventory
cryptohawk export-cbom --output cryptohawk-cbom.json
```

## API

- `GET /health`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/findings`
- `POST /api/v1/scan/source`
- `POST /api/v1/scan/tls`
- `GET /api/v1/cbom`
- `DELETE /api/v1/findings`

Interactive OpenAPI documentation is available at `/docs` while the API is running.

## Standards direction

CryptoHawk is designed around public standards rather than a proprietary inventory format:

- NIST FIPS 203 — ML-KEM
- NIST FIPS 204 — ML-DSA
- NIST FIPS 205 — SLH-DSA
- CycloneDX 1.7 Cryptography Bill of Materials / cryptographic asset model

CryptoHawk-specific risk metadata is emitted as namespaced CycloneDX properties so the CBOM stays portable while retaining operational context.

## Roadmap

The next product slices are repository-native scanning, container/image analysis, SSH and certificate-estate discovery, cloud/Kubernetes collectors, richer crypto dependency graphs, organization/workspace tenancy, policy packs, continuous scans, drift detection, signed evidence bundles and enterprise SSO/RBAC.

### Network scan safety

The API blocks non-global TLS targets by default and connects to the exact validated DNS answer, avoiding a second resolution between policy evaluation and connection. For a self-hosted enterprise collector that must inspect RFC1918/internal assets, set `CRYPTOHAWK_ALLOW_PRIVATE_TARGETS=true` deliberately at the deployment boundary. Do not enable that option on a shared public SaaS worker.

## Security

CryptoHawk is a defensive inventory and migration product. Do not scan systems you do not own or have authorization to assess. Secrets, private keys, runtime databases and generated scanner data are excluded by the repository `.gitignore`.

## License

Apache-2.0
