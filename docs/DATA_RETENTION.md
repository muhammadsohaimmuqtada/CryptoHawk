# CryptoHawk Data Retention and Workspace Deletion

CryptoHawk 0.9 provides an explicit, destructive workspace purge for controlled pilot deployments. This is a technical data-lifecycle control; it does not by itself define the contractual retention policy, legal basis, backup schedule, or privacy obligations of a particular deployment.

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

## Data removed

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
- workspace runtime/concurrency state;
- workspace-scoped audit events.

The deletion graph is explicit rather than relying only on database cascades. This keeps the behavior deterministic in both production PostgreSQL and local SQLite environments and makes new workspace-owned tables visible during code review.

## Data intentionally retained

A workspace purge does **not** delete global user identities or user login sessions. A user may belong to more than one workspace, so deleting one tenant must not remove access to an unrelated tenant.

After a successful purge, the HTTP audit middleware records one workspace-less deletion tombstone. It retains the authenticated user identity, request identity, route and outcome, but does not recreate a workspace-scoped audit row after the tenant transaction has committed.

If account-level deletion is required by a deployment's privacy policy, it must be handled as a separate lifecycle operation after confirming that the user has no remaining workspace or legal-retention obligations.

## Backups and external copies

Deleting a workspace from the live database does not rewrite historical PostgreSQL backups, snapshots, object-store copies, exported CBOMs/reports, SIEM copies, or other externally retained artifacts.

Operators must define and enforce backup expiration and deletion schedules that match their contractual and regulatory requirements. CryptoHawk's disaster-recovery procedure validates recoverability; it is not a backup-retention policy.

## Retention policy

CryptoHawk does not automatically purge historical evidence on a timer in the 0.9 pilot line. Evidence retention requirements vary by customer, incident-response policy and regulatory regime, so pilot operators must explicitly decide:

- how long active and historical scan evidence is retained;
- how long workspace audit records are retained;
- how long database backups and exported reports are retained;
- whether legal/security holds override normal deletion;
- when account-level identity deletion is permitted.

Broad GA should pair these technical controls with a documented commercial retention/privacy policy and, where required, configurable time-based retention.

## Verification expectations

Release tests for workspace purge must prove that:

- a non-owner cannot delete the workspace;
- an API key cannot perform workspace deletion even when it has a high workspace role;
- an incorrect confirmation slug is rejected;
- running scans block deletion;
- queued work and tenant evidence are removed transactionally;
- encrypted credentials, policy history, remediation state and audit data are removed;
- a neighboring workspace remains intact;
- global user identity/session state remains intact;
- the successful deletion audit is workspace-less and does not recreate tenant data.
