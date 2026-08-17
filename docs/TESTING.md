# CryptoHawk Tester Workflow

This is the fastest way to evaluate CryptoHawk as a product on a fresh machine without building a customer environment first.

## What this proves

The evaluation stack proves that a tester can start the deployed product, authenticate through the web/API path, open a populated workspace, inspect cryptographic findings, generate reports, export a CycloneDX 1.7 CBOM, and export the pilot evidence ZIP.

It does **not** prove enterprise GA readiness. The seeded assets are synthetic and cannot replace a real customer pilot, independent security assessment, or deployment-specific HA validation.

## Requirements

- Docker with Docker Compose v2
- GNU Make
- local ports `3000` and `8000` available

The evaluation stack binds those ports to `127.0.0.1` only and uses its own `cryptohawk-evaluation-db` volume. It does not reuse the normal development or production database.

## Start a clean evaluation

```bash
make evaluation-up
```

That command:

1. builds the backend and web images;
2. starts PostgreSQL and runs Alembic migrations;
3. starts the API, worker, and scheduler;
4. creates a synthetic evaluation workspace through the real authenticated API;
5. registers two representative source assets;
6. runs real source discovery to produce classical and PQC-related findings;
7. starts the compiled web application;
8. runs an automated deployed-stack smoke test through the web proxy.

Open:

`http://localhost:3000`

Evaluation credentials:

- Email: `tester@cryptohawk.local`
- Password: `CryptoHawk-Eval-Only-2026!`

These credentials are intentionally public and are valid only for the isolated local evaluation stack. Do not reuse them in any other deployment.

## What a tester should exercise

After login, verify that the `CryptoHawk Evaluation` workspace contains `Payments Service` and `Identity Service`, then review the active findings and their risk/PQC classifications. Exercise scan history, policy, remediation, reporting, and CBOM views. Export the pilot evidence bundle and confirm the archive contains the executive/engineering evidence plus its SHA-256 manifest.

The synthetic source fixtures intentionally contain examples such as SHA-1, RSA-2048, AES-128, ECDSA, ECDH, and ML-KEM so the tester can see both migration pressure and post-quantum direction without relying on internet access.

## Re-run the smoke test

```bash
make evaluation-smoke
```

The smoke test verifies:

- API readiness;
- authentication through the web reverse proxy;
- evaluation workspace discovery;
- seeded asset and finding counts;
- executive report consistency;
- CycloneDX 1.7 CBOM generation;
- pilot evidence ZIP export;
- compiled frontend serving.

The same deployed evaluation smoke test runs in GitHub Actions on every pull request and every push to `main`.

## Reset completely

```bash
make evaluation-down
make evaluation-up
```

`evaluation-down` removes the evaluation containers and the isolated evaluation database volume. Use this whenever you want to reproduce the experience from a clean state.

## Real pilot testing

Once the local evaluation path is satisfactory, move to `docs/PILOT_RUNBOOK.md`. A real pilot must use authorized representative customer assets and must not treat synthetic evaluation data as market-readiness evidence.
