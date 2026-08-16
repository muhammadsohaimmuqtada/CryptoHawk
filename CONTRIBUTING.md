# Contributing to CryptoHawk

CryptoHawk is security infrastructure. Changes are expected to preserve deterministic evidence, tenant isolation and release reproducibility rather than merely pass a happy-path demo.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

cd frontend
npm ci
```

Run backend quality gates from the repository root:

```bash
ruff check src tests migrations scripts
pytest --cov=cryptohawk --cov-report=term-missing
pip-audit
```

Run frontend gates from `frontend/`:

```bash
npm audit --audit-level=high
npm run build
```

## Change discipline

- Work from current `main` on a focused branch.
- Do not bypass service/data-layer workspace authorization with UI-only checks.
- Do not use an LLM for deterministic risk, policy or evidence decisions.
- Do not infer cryptographic usage solely from dependency presence.
- Preserve evidence/provenance identity across retries and rescans.
- Never weaken public-target/private-target policy for convenience.
- Do not execute target repositories or container images during discovery.
- Do not put connector credentials in command arguments, repository URLs, logs, audit metadata or reports.
- Schema changes require an Alembic migration and migration-parity tests.
- Business-critical state must be considered for PostgreSQL disaster-recovery coverage.
- New worker/queue behavior must preserve tenant fairness, retry accounting and capacity reconciliation.

## Pull requests

A pull request is mergeable only when all required checks pass on the exact current head SHA. Do not merge based on an older green run after the branch has moved.

Release-line changes additionally follow `docs/RELEASE_QUALIFICATION.md` and `docs/REPOSITORY_GOVERNANCE.md`.

Prefer tests that demonstrate invariants rather than snapshotting implementation details. If a test exposes a real product defect, fix the product; do not weaken the assertion or CI gate.

## Security changes

Security-sensitive changes should include explicit regression coverage for the boundary they modify. High-risk areas include authentication/RBAC, tenant isolation, secret handling, outbound networking, Git acquisition, archive parsing, report escaping, queue ownership and evidence integrity.

Do not publish an unpatched vulnerability in a public issue. Follow `SECURITY.md`.

## Production configuration

Development defaults are intentionally convenient and are not production defaults. `CRYPTOHAWK_ENVIRONMENT=production` is fail-closed; see `docs/PRODUCTION_DEPLOYMENT.md`.

## Release claims

The `0.9.x` line is a commercial-pilot candidate. Do not change product language to `1.0`, GA, enterprise-ready or equivalent until the external evidence gates in `docs/RELEASE_QUALIFICATION.md` are complete.
