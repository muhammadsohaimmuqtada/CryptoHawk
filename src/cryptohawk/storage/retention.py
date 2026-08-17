from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    and_,
    delete,
    exists,
    func,
    select,
)
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.inventory import ScanStatus
from cryptohawk.domain.remediation import RemediationStatus
from cryptohawk.domain.retention import RetentionSweepResult, WorkspaceRetentionPolicy
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
from cryptohawk.storage.database import Base, FindingRecord, FindingScopeRecord
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
from cryptohawk.storage.time import as_utc


class WorkspaceRetentionPolicyRecord(Base):
    __tablename__ = "workspace_retention_policies"
    __table_args__ = (
        CheckConstraint(
            "evidence_retention_days >= 7 AND evidence_retention_days <= 3650",
            name="ck_retention_evidence_days",
        ),
        CheckConstraint(
            "audit_retention_days >= 7 AND audit_retention_days <= 3650",
            name="ck_retention_audit_days",
        ),
        CheckConstraint(
            "sweep_interval_hours >= 1 AND sweep_interval_hours <= 168",
            name="ck_retention_sweep_hours",
        ),
    )

    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        primary_key=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    evidence_retention_days: Mapped[int] = mapped_column(Integer, default=180)
    audit_retention_days: Mapped[int] = mapped_column(Integer, default=365)
    sweep_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    updated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class WorkspacePurgeBlocked(RuntimeError):
    """Raised when a workspace cannot be purged safely."""


@dataclass(frozen=True)
class WorkspacePurgeResult:
    workspace_id: str
    workspace_slug: str
    deleted_rows: dict[str, int]


def _utc(value: datetime | None = None) -> datetime:
    normalized = as_utc(value or datetime.now(UTC))
    if normalized is None:
        raise ValueError("datetime value is required")
    return normalized


_NONTERMINAL_REMEDIATION = (
    RemediationStatus.OPEN.value,
    RemediationStatus.PLANNED.value,
    RemediationStatus.IN_PROGRESS.value,
    RemediationStatus.BLOCKED.value,
    RemediationStatus.READY_FOR_VERIFICATION.value,
)
_TERMINAL_SCAN_STATUSES = (
    ScanStatus.SUCCEEDED.value,
    ScanStatus.FAILED.value,
    ScanStatus.CANCELED.value,
)


class WorkspaceRetentionRepository:
    """Workspace lifecycle and bounded-history retention operations.

    Full workspace purge uses explicit deletes rather than relying only on database
    cascades so PostgreSQL and local SQLite behave consistently. Timed retention is
    deliberately evidence-aware: the newest scan/repository provenance for each
    asset, active-observation provenance, and evidence required by unfinished
    remediation work are protected from age-based deletion.
    """

    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    @staticmethod
    def _policy(row: WorkspaceRetentionPolicyRecord) -> WorkspaceRetentionPolicy:
        return WorkspaceRetentionPolicy(
            workspace_id=row.workspace_id,
            enabled=row.enabled,
            evidence_retention_days=row.evidence_retention_days,
            audit_retention_days=row.audit_retention_days,
            sweep_interval_hours=row.sweep_interval_hours,
            last_run_at=row.last_run_at,
            updated_by=row.updated_by,
            updated_at=row.updated_at,
        )

    def get_policy(self, workspace_id: str) -> WorkspaceRetentionPolicy:
        if self.inventory.get_workspace(workspace_id) is None:
            raise LookupError("workspace not found")
        with self.SessionLocal() as session:
            row = session.get(WorkspaceRetentionPolicyRecord, workspace_id)
            if row is not None:
                return self._policy(row)
        return WorkspaceRetentionPolicy(workspace_id=workspace_id)

    def set_policy(
        self,
        *,
        workspace_id: str,
        enabled: bool,
        evidence_retention_days: int,
        audit_retention_days: int,
        sweep_interval_hours: int,
        updated_by: str,
        now: datetime | None = None,
    ) -> WorkspaceRetentionPolicy:
        if self.inventory.get_workspace(workspace_id) is None:
            raise LookupError("workspace not found")
        if not updated_by.strip():
            raise ValueError("updated_by is required")
        validated = WorkspaceRetentionPolicy(
            workspace_id=workspace_id,
            enabled=enabled,
            evidence_retention_days=evidence_retention_days,
            audit_retention_days=audit_retention_days,
            sweep_interval_hours=sweep_interval_hours,
        )
        current = _utc(now)
        with self.SessionLocal() as session:
            row = session.get(WorkspaceRetentionPolicyRecord, workspace_id)
            if row is None:
                row = WorkspaceRetentionPolicyRecord(
                    workspace_id=workspace_id,
                    enabled=validated.enabled,
                    evidence_retention_days=validated.evidence_retention_days,
                    audit_retention_days=validated.audit_retention_days,
                    sweep_interval_hours=validated.sweep_interval_hours,
                    last_run_at=None,
                    updated_by=updated_by.strip()[:200],
                    updated_at=current,
                )
                session.add(row)
            else:
                row.enabled = validated.enabled
                row.evidence_retention_days = validated.evidence_retention_days
                row.audit_retention_days = validated.audit_retention_days
                row.sweep_interval_hours = validated.sweep_interval_hours
                row.updated_by = updated_by.strip()[:200]
                row.updated_at = current
            session.commit()
            session.refresh(row)
            return self._policy(row)

    @staticmethod
    def _is_due(row: WorkspaceRetentionPolicyRecord, current: datetime) -> bool:
        if not row.enabled:
            return False
        last_run = as_utc(row.last_run_at)
        return last_run is None or last_run + timedelta(hours=row.sweep_interval_hours) <= current

    def run_due_retention(
        self,
        *,
        now: datetime | None = None,
        limit: int = 100,
    ) -> list[RetentionSweepResult]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        current = _utc(now)
        with self.SessionLocal() as session:
            workspace_ids = list(
                session.scalars(
                    select(WorkspaceRetentionPolicyRecord.workspace_id)
                    .where(WorkspaceRetentionPolicyRecord.enabled.is_(True))
                    .order_by(
                        WorkspaceRetentionPolicyRecord.last_run_at.is_not(None),
                        WorkspaceRetentionPolicyRecord.last_run_at,
                        WorkspaceRetentionPolicyRecord.workspace_id,
                    )
                    .limit(limit)
                ).all()
            )
        results: list[RetentionSweepResult] = []
        for workspace_id in workspace_ids:
            result = self.prune_workspace_history(
                workspace_id=workspace_id,
                now=current,
                only_if_due=True,
            )
            if result is not None:
                results.append(result)
        return results

    def prune_workspace_history(
        self,
        *,
        workspace_id: str,
        now: datetime | None = None,
        only_if_due: bool = False,
    ) -> RetentionSweepResult | None:
        current = _utc(now)
        with self.SessionLocal() as session:
            statement = (
                select(WorkspaceRetentionPolicyRecord)
                .where(WorkspaceRetentionPolicyRecord.workspace_id == workspace_id)
                .with_for_update(skip_locked=only_if_due)
            )
            policy = session.scalar(statement)
            if policy is None:
                if only_if_due:
                    return None
                if self.inventory.get_workspace(workspace_id) is None:
                    raise LookupError("workspace not found")
                raise ValueError("workspace retention policy has not been configured")
            if not policy.enabled:
                raise ValueError("workspace retention policy is disabled")
            if only_if_due and not self._is_due(policy, current):
                return None

            evidence_cutoff = current - timedelta(days=policy.evidence_retention_days)
            audit_cutoff = current - timedelta(days=policy.audit_retention_days)

            protected_jobs: set[str] = set(
                session.scalars(
                    select(ObservationStateRecord.last_job_id).where(
                        ObservationStateRecord.workspace_id == workspace_id,
                        ObservationStateRecord.active.is_(True),
                    )
                ).all()
            )

            latest_snapshot_times = (
                select(
                    ScanSnapshotRecord.asset_id.label("asset_id"),
                    func.max(ScanSnapshotRecord.completed_at).label("completed_at"),
                )
                .where(ScanSnapshotRecord.workspace_id == workspace_id)
                .group_by(ScanSnapshotRecord.asset_id)
                .subquery()
            )
            protected_jobs.update(
                session.scalars(
                    select(ScanSnapshotRecord.job_id).join(
                        latest_snapshot_times,
                        and_(
                            ScanSnapshotRecord.asset_id == latest_snapshot_times.c.asset_id,
                            ScanSnapshotRecord.completed_at
                            == latest_snapshot_times.c.completed_at,
                        ),
                    )
                ).all()
            )

            latest_repo_times = (
                select(
                    RepositoryScanRunRecord.asset_id.label("asset_id"),
                    func.max(RepositoryScanRunRecord.collected_at).label("collected_at"),
                )
                .where(RepositoryScanRunRecord.workspace_id == workspace_id)
                .group_by(RepositoryScanRunRecord.asset_id)
                .subquery()
            )
            protected_jobs.update(
                session.scalars(
                    select(RepositoryScanRunRecord.scan_job_id).join(
                        latest_repo_times,
                        and_(
                            RepositoryScanRunRecord.asset_id == latest_repo_times.c.asset_id,
                            RepositoryScanRunRecord.collected_at
                            == latest_repo_times.c.collected_at,
                        ),
                    )
                ).all()
            )

            remediation_rows = session.execute(
                select(
                    MigrationItemRecord.source_scan_job_id,
                    MigrationItemRecord.verification_job_id,
                ).where(
                    MigrationItemRecord.workspace_id == workspace_id,
                    MigrationItemRecord.status.in_(_NONTERMINAL_REMEDIATION),
                )
            ).all()
            for source_job_id, verification_job_id in remediation_rows:
                protected_jobs.add(source_job_id)
                if verification_job_id:
                    protected_jobs.add(verification_job_id)

            deleted: dict[str, int] = {}

            def remove(model, *criteria) -> None:
                result = session.execute(delete(model).where(*criteria))
                deleted[model.__tablename__] = deleted.get(model.__tablename__, 0) + int(
                    result.rowcount or 0
                )

            def unprotected(column):
                return ~column.in_(protected_jobs) if protected_jobs else True

            remove(
                ObservationOccurrenceRecord,
                ObservationOccurrenceRecord.workspace_id == workspace_id,
                ObservationOccurrenceRecord.observed_at < evidence_cutoff,
                unprotected(ObservationOccurrenceRecord.job_id),
            )
            remove(
                DriftEventRecord,
                DriftEventRecord.workspace_id == workspace_id,
                DriftEventRecord.occurred_at < evidence_cutoff,
                unprotected(DriftEventRecord.scan_job_id),
            )
            remove(
                ScanSnapshotRecord,
                ScanSnapshotRecord.workspace_id == workspace_id,
                ScanSnapshotRecord.completed_at < evidence_cutoff,
                unprotected(ScanSnapshotRecord.job_id),
            )
            remove(
                ScheduledExecutionRecord,
                ScheduledExecutionRecord.workspace_id == workspace_id,
                ScheduledExecutionRecord.scheduled_for < evidence_cutoff,
                unprotected(ScheduledExecutionRecord.job_id),
            )
            remove(
                RepositoryScanRunRecord,
                RepositoryScanRunRecord.workspace_id == workspace_id,
                RepositoryScanRunRecord.collected_at < evidence_cutoff,
                unprotected(RepositoryScanRunRecord.scan_job_id),
            )

            stale_finding_ids = list(
                session.scalars(
                    select(FindingRecord.id)
                    .join(
                        FindingScopeRecord,
                        FindingScopeRecord.finding_id == FindingRecord.id,
                    )
                    .where(
                        FindingScopeRecord.workspace_id == workspace_id,
                        FindingRecord.discovered_at < evidence_cutoff,
                        ~exists().where(
                            ObservationOccurrenceRecord.finding_id == FindingRecord.id
                        ),
                        ~exists().where(
                            MigrationItemRecord.source_finding_id == FindingRecord.id
                        ),
                    )
                ).all()
            )
            if stale_finding_ids:
                remove(
                    FindingScopeRecord,
                    FindingScopeRecord.finding_id.in_(stale_finding_ids),
                )
                remove(FindingRecord, FindingRecord.id.in_(stale_finding_ids))

            terminal_job_ids = list(
                session.scalars(
                    select(ScanJobRecord.id).where(
                        ScanJobRecord.workspace_id == workspace_id,
                        ScanJobRecord.status.in_(_TERMINAL_SCAN_STATUSES),
                        ScanJobRecord.finished_at.is_not(None),
                        ScanJobRecord.finished_at < evidence_cutoff,
                        unprotected(ScanJobRecord.id),
                        ~exists().where(
                            FindingScopeRecord.scan_job_id == ScanJobRecord.id
                        ),
                        ~exists().where(
                            MigrationItemRecord.source_scan_job_id == ScanJobRecord.id
                        ),
                        ~exists().where(
                            MigrationItemRecord.verification_job_id == ScanJobRecord.id
                        ),
                    )
                ).all()
            )
            if terminal_job_ids:
                remove(ScanQueueRecord, ScanQueueRecord.job_id.in_(terminal_job_ids))
                remove(ScanJobRecord, ScanJobRecord.id.in_(terminal_job_ids))

            remove(
                AuditEventRecord,
                AuditEventRecord.workspace_id == workspace_id,
                AuditEventRecord.created_at < audit_cutoff,
            )

            policy.last_run_at = current
            session.commit()
            return RetentionSweepResult(
                workspace_id=workspace_id,
                evidence_cutoff=evidence_cutoff,
                audit_cutoff=audit_cutoff,
                deleted_rows=deleted,
                protected_evidence_jobs=len(protected_jobs),
                ran_at=current,
            )

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

            remove(MigrationItemRecord, MigrationItemRecord.workspace_id == workspace_id)
            remove(
                WorkspacePolicyAssignmentRecord,
                WorkspacePolicyAssignmentRecord.workspace_id == workspace_id,
            )
            remove(
                WorkspaceRetentionPolicyRecord,
                WorkspaceRetentionPolicyRecord.workspace_id == workspace_id,
            )

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

            remove(
                RepositoryConfigurationRecord,
                RepositoryConfigurationRecord.workspace_id == workspace_id,
            )
            remove(
                ConnectorCredentialRecord,
                ConnectorCredentialRecord.workspace_id == workspace_id,
            )

            remove(
                CryptoPolicyVersionRecord,
                CryptoPolicyVersionRecord.workspace_id == workspace_id,
            )
            remove(
                CryptoPolicyPackRecord,
                CryptoPolicyPackRecord.workspace_id == workspace_id,
            )

            remove(FindingScopeRecord, FindingScopeRecord.workspace_id == workspace_id)
            for offset in range(0, len(finding_ids), 500):
                chunk = finding_ids[offset : offset + 500]
                if not chunk:
                    continue
                result = session.execute(
                    delete(FindingRecord).where(
                        FindingRecord.id.in_(chunk),
                        ~exists().where(FindingScopeRecord.finding_id == FindingRecord.id),
                    )
                )
                deleted[FindingRecord.__tablename__] = deleted.get(
                    FindingRecord.__tablename__, 0
                ) + int(result.rowcount or 0)

            remove(ApiKeyRecord, ApiKeyRecord.workspace_id == workspace_id)
            remove(
                WorkspaceRuntimeRecord,
                WorkspaceRuntimeRecord.workspace_id == workspace_id,
            )
            remove(
                WorkspaceMembershipRecord,
                WorkspaceMembershipRecord.workspace_id == workspace_id,
            )

            rate_scope_keys = [f"workspace:{workspace_id}"]
            rate_scope_keys.extend(f"principal:api-key:{key_id}" for key_id in api_key_ids)
            remove(
                RateLimitBucketRecord,
                RateLimitBucketRecord.scope_key.in_(rate_scope_keys),
            )

            remove(AuditEventRecord, AuditEventRecord.workspace_id == workspace_id)

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
    "WorkspaceRetentionPolicyRecord",
    "WorkspaceRetentionRepository",
]
