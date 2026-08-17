# CryptoHawk Data Retention and Workspace Deletion

CryptoHawk provides two complementary data-lifecycle controls for controlled deployments:

1. an explicit destructive workspace purge; and
2. an opt-in workspace retention policy for automatic historical evidence and audit expiry.

These are technical controls. They do not by themselves define a customer's contractual retention policy, legal basis, backup schedule, legal holds, privacy notice, or regulatory obligations.

## Workspace purge

The authenticated API exposes:

```text
DELETE /api/v1/workspaces/{workspace_id}
```

The request body must contain the exact workspace slug:

```json
{"confirm_slug":"acme-security"}
```

Deletion is allowed only when all of the following are true:

- the caller is authenticated through a user session, not an API key;
- the caller has the `owner` role in the target workspace;
- `confirm_slug` exactly matches the workspace slug;
- the workspace has no scan job currently in the `running` state.

A queued job does not block deletion. Queued work is locked and removed as part of the same database transaction so a PostgreSQL worker cannot claim new work for the workspace while the purge is in progress. A running scan must finish or be cancelled before deletion is attempted again.

## Data removed by workspace purge

A successful workspace purge removes the tenant's live application state in one transaction, including:

- workspace record and memberships;
- managed assets and repository configurations;
- scan jobs, durable queue entries, schedules and scheduled executions;
- active observation state, occurrence history, snapshots and drift events;
- workspace finding scopes and findings that no longer have any scope;
- repository scan provenance;
- encrypted connector credentials;
- workspace API keys and workspace/API-key rate-limit buckets;
- remediation/migration items and verification evidence;
- cryptographic policy packs, immutable policy versions and active assignment;
- workspace retention-policy configuration;
- workspace runtime/concurrency state;
- workspace-scoped audit events.

The deletion graph is explicit rather than relying only on database cascades. This keeps behavior deterministic in both production PostgreSQL and local SQLite environments and makes new workspace-owned tables visible during code review.

## Configurable historical retention

Retention is **disabled by default**. Enabling it is an explicit owner decision.

The API exposes:

```text
GET  /api/v1/workspaces/{workspace_id}/retention-policy
POST /api/v1/workspaces/{workspace_id}/retention-policy
POST /api/v1/workspaces/{workspace_id}/retention-policy/run
```

A configured policy contains:

- `enabled`;
- `evidence_retention_days` — 7 to 3650 days;
- `audit_retention_days` — 7 to 3650 days;
- `sweep_interval_hours` — 1 to 168 hours;
- last-run and updater provenance.

Viewers can read the policy. Only an `owner` user session can change it or force an immediate sweep. API keys cannot change retention policy.

When the durable CryptoHawk scheduler is running, it also executes due retention policies. Multiple scheduler processes use row locking so a workspace policy is not intentionally swept concurrently.

### Evidence-aware safety rules

Timed retention is not a blind age-based delete. CryptoHawk protects evidence that is still operationally required even when it is older than the configured cutoff.

The sweep always protects:

- the newest scan snapshot for each asset;
- the newest repository scan provenance for each repository asset, preserving incremental-collection continuity;
- the last scan job for every currently active cryptographic observation;
- source and verification scan jobs required by unfinished remediation work.

After those protections are calculated, eligible old data can be removed, including:

- observation occurrences;
- cryptographic drift events;
- old scan snapshots;
- old scheduled-execution records;
- superseded repository scan provenance;
- resolved/stale findings that are no longer referenced by retained observations or remediation;
- terminal scan jobs that are no longer referenced by findings or remediation;
- workspace audit events older than the audit cutoff.

`observation_states` are retained because they carry compact continuous-state identity required to distinguish current cryptographic posture and future drift. Current findings/evidence and unfinished remediation provenance therefore survive normal age-based cleanup.

## Data intentionally retained after full workspace purge

A workspace purge does **not** delete global user identities or user login sessions. A user may belong to more than one workspace, so deleting one tenant must not remove access to an unrelated tenant.

After a successful purge, the HTTP audit middleware records one workspace-less deletion tombstone. It retains the authenticated user identity, request identity, route and outcome, but does not recreate a workspace-scoped audit row after the tenant transaction has committed.

If account-level deletion is required by a deployment's privacy policy, it must be handled as a separate lifecycle operation after confirming that the user has no remaining workspace or legal-retention obligations.

## Backups and external copies

Deleting or aging data from the live database does not rewrite historical PostgreSQL backups, snapshots, object-store copies, exported CBOMs/reports, SIEM copies, or other externally retained artifacts.

Operators must define and enforce backup expiration and deletion schedules that match their contractual and regulatory requirements. CryptoHawk's disaster-recovery procedure validates recoverability; it is not a backup-retention policy.

## Operational policy still required

Deployment owners must still explicitly decide:

- the retention periods appropriate for scan evidence and audit records;
- how long database backups and exported reports are retained;
- whether legal/security holds override normal deletion;
- when account-level identity deletion is permitted;
- whether a customer contract or regulation requires longer evidence retention than the configured minimum.

Broad GA should pair these technical controls with the deployment's commercial privacy/retention policy and legal review where applicable.

## Verification expectations

Release tests for lifecycle controls must prove that:

- a non-owner cannot delete the workspace or mutate retention policy;
- an API key cannot perform workspace deletion or retention-policy changes;
- an incorrect workspace-deletion confirmation slug is rejected;
- running scans block full workspace deletion;
- queued work and tenant evidence are removed transactionally during full purge;
- encrypted credentials, policy history, remediation state and audit data are removed during full purge;
- a neighboring workspace remains intact;
- global user identity/session state remains intact;
- the successful workspace-deletion audit is workspace-less and does not recreate tenant data;
- timed retention removes eligible old history but preserves latest/current evidence;
- scheduler cadence prevents unnecessary repeated sweeps;
- production PostgreSQL migrations and retention execution are release-qualified.
