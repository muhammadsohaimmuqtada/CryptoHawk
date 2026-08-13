# PostgreSQL Backup and Disaster Recovery

CryptoHawk production data must be recoverable independently of application containers. This procedure uses PostgreSQL custom-format logical backups so the archive can be inspected with `pg_restore`, restored selectively when necessary, and restored into a pristine database for verification.

## Recovery contract

A backup is considered usable only when all of the following are true:

1. `pg_dump` completes successfully using the PostgreSQL major version deployed for the database.
2. `pg_restore --list` can parse the resulting custom archive.
3. The SHA-256 sidecar matches the archive before restore.
4. Restore targets are empty; the restore script refuses to overwrite an existing CryptoHawk database.
5. `pg_restore` completes in a single transaction with error-stop behavior.
6. The restored database has the same Alembic revision as the source backup.
7. CryptoHawk can read representative workspace, authentication, scan, finding, history, queue, audit and quota state.
8. Connector credentials can still be authenticated and decrypted with the retained connector-encryption key material.

CI exercises this contract on PostgreSQL 17 for every pull request.

## What must be backed up together

The database archive is necessary but not sufficient for a recoverable deployment. Preserve, in separate protected storage:

- the `.dump` archive and its `.sha256` sidecar;
- every connector-encryption key version still referenced by stored credentials;
- deployment configuration needed to reconstruct PostgreSQL and CryptoHawk;
- externally managed TLS/OIDC/SSO material when those features are enabled.

Do **not** store connector-encryption keys beside database backups. Losing an encryption key can make otherwise intact encrypted connector credentials unrecoverable. Treat backups as sensitive because findings, asset metadata, audit history, identity records and encrypted credential material are present in the database.

## Create a backup

Use PostgreSQL client tools from the same major release as the server. Set a native PostgreSQL connection URI; do not use the SQLAlchemy `postgresql+psycopg://` form with `pg_dump`.

```bash
export CRYPTOHAWK_POSTGRES_URL='postgresql://USER:PASSWORD@DB_HOST:5432/cryptohawk'

bash scripts/postgres_backup.sh \
  /secure/backups/cryptohawk-$(date -u +%Y%m%dT%H%M%SZ).dump
```

The script:

- creates a custom-format archive with `--no-owner --no-privileges`;
- validates that `pg_restore` can parse the temporary archive;
- publishes the archive atomically only after validation;
- creates a portable SHA-256 sidecar;
- uses restrictive file permissions.

A successful command prints only the backup path, not database credentials.

## Restore into a pristine database

Create a new empty database. Restoring into a new database is intentional: the CryptoHawk restore command refuses non-empty targets rather than silently deleting current data.

```bash
createdb \
  --maintenance-db='postgresql://ADMIN:PASSWORD@DB_HOST:5432/postgres' \
  --template=template0 \
  cryptohawk_restored

export CRYPTOHAWK_POSTGRES_URL='postgresql://USER:PASSWORD@DB_HOST:5432/cryptohawk_restored'

bash scripts/postgres_restore.sh \
  /secure/backups/cryptohawk-20260813T000000Z.dump
```

The restore script verifies the checksum and archive manifest first, checks that the target contains no user tables, and then invokes `pg_restore` with:

```text
--no-owner --no-privileges --single-transaction --exit-on-error
```

Do not run Alembic migrations against the empty target before restoring. The database schema and `alembic_version` row are part of the backup.

## Post-restore validation

Before promoting a restored database, verify at minimum:

```bash
export CRYPTOHAWK_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@DB_HOST:5432/cryptohawk_restored'
alembic current
```

Then start an API instance against the restored database and confirm:

```bash
curl --fail http://127.0.0.1:8000/health/ready
```

For a formal recovery drill, also verify authentication, tenant isolation, representative findings/CBOM, scan history, schedules, queue operations, audit retrieval and connector credential decryption. CI performs these checks with `scripts/postgres_dr_fixture.py` against seeded non-production data.

## Promotion procedure

1. Stop or fence all writers to the failed/source database.
2. Record the incident timestamp and the backup selected for recovery.
3. Restore into a new pristine database and complete validation.
4. Point a staging CryptoHawk API/worker/scheduler set at the restored database.
5. Confirm readiness and functional invariants before changing production database routing.
6. Keep the failed database and restore artifacts immutable until the incident is closed.
7. After promotion, run `alembic current` and compare it with the application release expected by the deployment.
8. Resume workers/scheduler only after API readiness and data validation pass.

## Retention and recovery objectives

CryptoHawk does not claim a universal RPO or RTO. Those depend on backup cadence, database size, storage throughput, deployment topology and organizational requirements. Operators should establish their own targets and prove them with scheduled restore drills. A backup that has never been restored should not be treated as verified recovery capability.

## CI recovery drill

The `postgres-dr` CI job performs the following against PostgreSQL 17:

1. migrate a fresh source database to Alembic head;
2. seed representative CryptoHawk state, including an encrypted connector credential;
3. create and validate a custom backup;
4. create a pristine restore database from `template0`;
5. restore in a single transaction;
6. authenticate restored session/API credentials and decrypt the connector credential;
7. verify workspace/asset, successful scan history, scoped finding, schedule, queued job, audit event, quota state and Alembic revision;
8. prove the restored queue can still be claimed;
9. prove a second restore into the non-empty database is rejected;
10. prove a tampered archive is rejected by checksum validation;
11. remove the ephemeral fixture manifest and backup after the job.

This CI drill proves logical backup/restore compatibility for the application schema. It does not replace infrastructure-level tests for storage loss, regional failover or managed-database point-in-time recovery.
