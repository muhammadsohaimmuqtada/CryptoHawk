from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import delete, exists, func, select

from cryptohawk.domain.inventory import ScanStatus
from cryptohawk.storage.audit import AuditEventRecord
from cryptohawk.storage.auth import ApiKeyRecord, WorkspaceMembershipRecord
from cryptohawk.storage.continuous import (
    DriftEventRecord,
    ObservationOccurrenceRecord,
    ObservationStateRecord,
    ScanScheduleRecord,
    ScanSnapshotRecord,
    ScheduledExecutionRecord,
)
from cryptohawk.storage.credentials import ConnectorCredentialRecord
from cryptohawk.storage.database import FindingRecord, FindingScopeRecord
from cryptohawk.storage.inventory import (
    InventoryRepository,
    ManagedAssetRecord,
    ScanJobRecord,
    WorkspaceRecord,
)
from cryptohawk.storage.policy import (
    CryptoPolicyPackRecord,
    CryptoPolicyVersionRecord,
    WorkspacePolicyAssignmentRecord,
)
from cryptohawk.storage.queue import ScanQueueRecord
from cryptohawk.storage.quotas import RateLimitBucketRecord, WorkspaceRuntimeRecord
from cryptohawk.storage.remediation import MigrationItemRecord
from cryptohawk.storage.repositories import (
    RepositoryConfigurationRecord,
    RepositoryScanRunRecord,
)


class WorkspacePurgeBlocked(RuntimeError):
    """Raised when a workspace cannot be purged safely."""


@dataclass(frozen=True)
class WorkspacePurgeResult:
    workspace_id: str
    workspace_slug: str
    deleted_rows: dict[str, int]


class WorkspaceRetentionRepository:
    """Destructive workspace lifecycle operations.

    Workspace purge deliberately uses explicit deletes instead of relying only on
    database cascades. Production PostgreSQL has foreign-key cascades, while local
    SQLite test/development databases may not have foreign-key enforcement enabled.
    Keeping the deletion graph explicit makes the privacy boundary deterministic in
    both environments and makes new workspace-owned tables visible during review.
    """

    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def purge_workspace(self, workspace_id: str) -> WorkspacePurgeResult:
        if not workspace_id:
            raise ValueError("workspace_id is required")

        with self.SessionLocal() as session:
            workspace = session.scalar(
                select(WorkspaceRecord)
                .where(WorkspaceRecord.id == workspace_id)
                .with_for_update()
            )
            if workspace is None:
                raise LookupError("workspace not found")

            running = session.scalar(
                select(func.count())
                .select_from(ScanJobRecord)
                .where(
                    ScanJobRecord.workspace_id == workspace_id,
                    ScanJobRecord.status == ScanStatus.RUNNING.value,
                )
            )
            if running:
                raise WorkspacePurgeBlocked(
                    "workspace has running scans; wait for them to finish or cancel them first"
                )

            job_ids = select(ScanJobRecord.id).where(
                ScanJobRecord.workspace_id == workspace_id
            )
            # Lock queued work before deleting it so PostgreSQL workers using
            # SKIP LOCKED cannot claim new work for this tenant mid-purge.
            session.scalars(
                select(ScanQueueRecord)
                .where(ScanQueueRecord.job_id.in_(job_ids))
                .with_for_update()
            ).all()

            finding_ids = list(
                session.scalars(
                    select(FindingScopeRecord.finding_id).where(
                        FindingScopeRecord.workspace_id == workspace_id
                    )
                ).all()
            )
            api_key_ids = list(
                session.scalars(
                    select(ApiKeyRecord.id).where(ApiKeyRecord.workspace_id == workspace_id)
                ).all()
            )

            deleted: dict[str, int] = {}

            def remove(model, *criteria) -> None:
                result = session.execute(delete(model).where(*criteria))
                deleted[model.__tablename__] = deleted.get(model.__tablename__, 0) + int(
                    result.rowcount or 0
                )

            # RESTRICT/SET NULL relationships must be removed before jobs/policies.
            remove(MigrationItemRecord, MigrationItemRecord.workspace_id == workspace_id)
            remove(
                WorkspacePolicyAssignmentRecord,
                WorkspacePolicyAssignmentRecord.workspace_id == workspace_id,
            )

            # Scan-derived evidence and repository provenance.
            remove(
                RepositoryScanRunRecord,
                RepositoryScanRunRecord.workspace_id == workspace_id,
            )
            remove(DriftEventRecord, DriftEventRecord.workspace_id == workspace_id)
            remove(
                ObservationOccurrenceRecord,
                ObservationOccurrenceRecord.workspace_id == workspace_id,
            )
            remove(ScanSnapshotRecord, ScanSnapshotRecord.workspace_id == workspace_id)
            remove(
                ScheduledExecutionRecord,
                ScheduledExecutionRecord.workspace_id == workspace_id,
            )
            remove(ScanQueueRecord, ScanQueueRecord.job_id.in_(job_ids))
            remove(ScanScheduleRecord, ScanScheduleRecord.workspace_id == workspace_id)
            remove(
                ObservationStateRecord,
                ObservationStateRecord.workspace_id == workspace_id,
            )

            # Asset configuration and encrypted connector material.
            remove(
                RepositoryConfigurationRecord,
                RepositoryConfigurationRecord.workspace_id == workspace_id,
            )
            remove(
                ConnectorCredentialRecord,
                ConnectorCredentialRecord.workspace_id == workspace_id,
            )

            # Immutable policy history belongs to the tenant and is purged with it.
            remove(
                CryptoPolicyVersionRecord,
                CryptoPolicyVersionRecord.workspace_id == workspace_id,
            )
            remove(
                CryptoPolicyPackRecord,
                CryptoPolicyPackRecord.workspace_id == workspace_id,
            )

            # Findings are globally stored but currently have a single workspace
            # scope. Keep the orphan check so this remains safe if sharing semantics
            # are expanded in the future.
            remove(FindingScopeRecord, FindingScopeRecord.workspace_id == workspace_id)
            for offset in range(0, len(finding_ids), 500):
                chunk = finding_ids[offset : offset + 500]
                if not chunk:
                    continue
                result = session.execute(
                    delete(FindingRecord).where(
                        FindingRecord.id.in_(chunk),
                        ~exists().where(
                            FindingScopeRecord.finding_id == FindingRecord.id
                        ),
                    )
                )
                deleted[FindingRecord.__tablename__] = deleted.get(
                    FindingRecord.__tablename__, 0
                ) + int(result.rowcount or 0)

            # Workspace authentication/runtime state. User identities and user
            # sessions are global and intentionally survive a workspace purge.
            remove(ApiKeyRecord, ApiKeyRecord.workspace_id == workspace_id)
            remove(
                WorkspaceRuntimeRecord,
                WorkspaceRuntimeRecord.workspace_id == workspace_id,
            )
            remove(
                WorkspaceMembershipRecord,
                WorkspaceMembershipRecord.workspace_id == workspace_id,
            )

            # Remove ephemeral rate-limit buckets that directly identify this
            # workspace or API keys owned by it.
            rate_scope_keys = [f"workspace:{workspace_id}"]
            rate_scope_keys.extend(f"principal:api-key:{key_id}" for key_id in api_key_ids)
            remove(
                RateLimitBucketRecord,
                RateLimitBucketRecord.scope_key.in_(rate_scope_keys),
            )

            # Audit records are workspace data. The API middleware writes one new
            # workspace-less tombstone after the successful HTTP response.
            remove(AuditEventRecord, AuditEventRecord.workspace_id == workspace_id)

            # Parents last. Explicit child deletion keeps SQLite and PostgreSQL
            # behavior aligned and avoids RESTRICT-order surprises.
            remove(ScanJobRecord, ScanJobRecord.workspace_id == workspace_id)
            remove(ManagedAssetRecord, ManagedAssetRecord.workspace_id == workspace_id)
            remove(WorkspaceRecord, WorkspaceRecord.id == workspace_id)

            session.commit()
            return WorkspacePurgeResult(
                workspace_id=workspace_id,
                workspace_slug=workspace.slug,
                deleted_rows=deleted,
            )


__all__ = [
    "WorkspacePurgeBlocked",
    "WorkspacePurgeResult",
    "WorkspaceRetentionRepository",
]
