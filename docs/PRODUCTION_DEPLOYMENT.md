# CryptoHawk Production Deployment Runbook

This runbook describes the supported release-candidate deployment posture for CryptoHawk 0.9.x. It is intended for controlled commercial pilots and security-team deployments. It is not a claim of multi-region HA or enterprise GA.

## Production invariants

Set `CRYPTOHAWK_ENVIRONMENT=production`. CryptoHawk then fails closed during process import unless all of these invariants hold:

- PostgreSQL is used; SQLite is rejected.
- `CRYPTOHAWK_AUTO_CREATE_SCHEMA=false`; Alembic owns schema changes.
- `CRYPTOHAWK_ALLOW_LEGACY_GLOBAL_API=false`.
- Connector encryption keys are present, valid AES-256 key material, and include the configured active version.
- CORS is either empty for same-origin deployment or contains only explicit HTTPS origins. Wildcards, HTTP, loopback origins, credentials, query/fragment data, and path-bearing origins are rejected.

`CRYPTOHAWK_ALLOW_PRIVATE_TARGETS=true` is not globally forbidden because dedicated self-hosted collectors may need RFC1918 access. Never enable it on a shared/public worker.

## Required secrets

Generate connector encryption material outside the repository and secret manager logs:

```bash
python -c 'from cryptohawk.security.secrets import VersionedAesGcmCipher; print(VersionedAesGcmCipher.generate_key())'
```

Store it as a versioned secret, for example:

```text
CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS=1:<generated-base64url-key>
CRYPTOHAWK_CONNECTOR_ENCRYPTION_ACTIVE_VERSION=1
```

Do not remove an old key version until all stored connector credentials have been rotated to a newer active version. See `docs/SECRET_HANDLING.md`.

PostgreSQL credentials and the resulting SQLAlchemy URL must also come from a deployment secret store. If a password contains URL-reserved characters, percent-encode it in `CRYPTOHAWK_DATABASE_URL`.

## Single-host pilot deployment

The repository Docker Compose stack is suitable for controlled single-host pilots, not HA. Use the production overlay rather than the development defaults:

```bash
export CRYPTOHAWK_POSTGRES_PASSWORD='<strong-random-password>'
export CRYPTOHAWK_DATABASE_URL='postgresql+psycopg://cryptohawk:<encoded-password>@db:5432/cryptohawk'
export CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS='1:<generated-key>'
export CRYPTOHAWK_CONNECTOR_ENCRYPTION_ACTIVE_VERSION='1'
export CRYPTOHAWK_CORS_ORIGINS='https://cryptohawk.example.com'

docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  up -d --build
```

Terminate TLS in a hardened reverse proxy/load balancer and expose the web/API only through HTTPS. The Compose-published ports are convenient for pilot hosts and should be restricted by host firewall or bound behind the proxy in a hardened deployment.

For same-origin routing where the reverse proxy serves the UI and API from one origin, `CRYPTOHAWK_CORS_ORIGINS` may be empty.

## Startup order

1. Start PostgreSQL and wait for `pg_isready`.
2. Run `alembic upgrade head` exactly once as a migration job.
3. Start the API.
4. Wait for `GET /health/ready` to return HTTP 200.
5. Start workers and scheduler.
6. Start/expose the web tier.
7. Confirm metrics/log/tracing delivery.

The production Compose overlay preserves this order through service dependencies.

## Preflight checks

Before admitting pilot data:

```bash
cryptohawk --help
alembic current
```

Then verify:

- `/health/live` returns 200.
- `/health/ready` returns 200 and changes to 503 when PostgreSQL is unavailable.
- `/metrics` is reachable only from the intended monitoring network when enabled.
- First-user bootstrap is completed once and subsequent bootstrap attempts are rejected.
- A Viewer cannot mutate workspace state.
- An Analyst cannot perform Admin/Owner actions.
- A test repository credential is encrypted at rest and not returned through the API.
- A controlled scan produces evidence, history and policy provenance.
- A current-state report and CycloneDX CBOM can be exported.

## Database operations

Backups and restores are described in `docs/POSTGRES_DISASTER_RECOVERY.md` and are continuously exercised against PostgreSQL 17 in CI.

Minimum operational practice for a pilot:

- automated encrypted backups on a defined cadence;
- backup copies outside the application host;
- retention policy appropriate to customer agreements;
- periodic restore drill into a clean database;
- alerting on failed backup jobs;
- database disk/connection/replication monitoring when managed PostgreSQL is used.

## Observability

Use structured JSON logs and ingest them into the deployment logging system. Preserve `request_id`, `trace_id`, scan-job and worker correlation fields.

Scrape Prometheus metrics from the configured metrics endpoint. Do not expose it publicly.

Set `CRYPTOHAWK_OTEL_TRACES_ENDPOINT` to an OTLP/HTTP collector when distributed tracing is required. The application continues local trace correlation if no external collector is configured.

## Repository and network collectors

Public SaaS-style workers must leave `CRYPTOHAWK_ALLOW_PRIVATE_TARGETS=false`.

For internal/private target collection, run a dedicated self-hosted worker in the customer-controlled network and explicitly set `CRYPTOHAWK_ALLOW_PRIVATE_TARGETS=true` there. Do not reuse the same worker for unrelated tenants.

Repository acquisition remains HTTPS-only, redirect-disabled, protocol-restricted and allowlisted. Connector credentials must be stored through CryptoHawk's encrypted credential subsystem rather than embedded in repository URLs.

Container archive ingress must be mounted read-only and should be a dedicated directory controlled by the operator. CryptoHawk does not execute target images.

## Upgrade procedure

1. Take and validate a fresh PostgreSQL backup.
2. Record the currently deployed CryptoHawk image/commit and Alembic revision.
3. Stage the new build and run the exact release CI suite.
4. Stop new scan submissions if the migration is expected to be long-running.
5. Run `alembic upgrade head` as the migration job.
6. Deploy API, workers and scheduler from the same release revision.
7. Wait for readiness.
8. Run a representative scan and report export.
9. Resume normal scheduling.

Never run mixed worker/API schema generations longer than the documented compatibility window for a release. CryptoHawk 0.9.x assumes coordinated pilot upgrades.

## Rollback procedure

Application rollback and database rollback are separate decisions.

If the new application fails before a schema migration, redeploy the previous application revision.

If a migration was applied:

1. Stop API, workers and scheduler.
2. Prefer restoring the validated pre-upgrade backup when data written under the new schema does not need to be retained.
3. If the migration has a tested downgrade and the release notes explicitly authorize it, run the documented Alembic downgrade instead.
4. Deploy the previous application revision.
5. Verify `/health/ready`, authentication, a controlled scan, evidence history and report export before reopening the service.

Do not improvise database downgrades in a customer environment.

## Release claim boundary

A green repository gate means CryptoHawk is qualified as a **commercial-pilot candidate**. General-availability claims additionally require representative customer pilot evidence and an independent security review/pentest. Enterprise features such as SSO/SAML, HA/DR topology, contractual retention controls and support/SLA processes remain separate GA workstreams.
