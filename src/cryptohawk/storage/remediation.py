from __future__ import annotations

import json
from datetime import UTC, date, datetime
from uuid import uuid4

from sqlalchemy import Date, DateTime, ForeignKey, String, Text, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.inventory import ScanStatus
from cryptohawk.domain.models import Finding, Severity
from cryptohawk.domain.remediation import (
    MigrationItem,
    RemediationPriority,
    RemediationStatus,
    RemediationVerification,
)
from cryptohawk.storage.continuous import ObservationOccurrenceRecord, ScanSnapshotRecord
from cryptohawk.storage.database import Base, FindingRecord, FindingScopeRecord
from cryptohawk.storage.inventory import InventoryRepository, ScanJobRecord
from cryptohawk.storage.time import as_utc


class MigrationItemRecord(Base):
    __tablename__ = "migration_items"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "asset_id",
            "observation_fingerprint",
            name="uq_migration_item_workspace_asset_fingerprint",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True
    )
    observation_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    source_finding_id: Mapped[str] = mapped_column(String(64), index=True)
    source_scan_job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_jobs.id", ondelete="RESTRICT"), index=True
    )
    title: Mapped[str] = mapped_column(String(300))
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    priority: Mapped[str] = mapped_column(String(20), index=True)
    target_algorithm: Mapped[str | None] = mapped_column(String(200), nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    acceptance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_job_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    source_finding_json: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(200), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


_ALLOWED_TRANSITIONS: dict[RemediationStatus, frozenset[RemediationStatus]] = {
    RemediationStatus.OPEN: frozenset(
        {
            RemediationStatus.PLANNED,
            RemediationStatus.IN_PROGRESS,
            RemediationStatus.ACCEPTED_RISK,
        }
    ),
    RemediationStatus.PLANNED: frozenset(
        {
            RemediationStatus.IN_PROGRESS,
            RemediationStatus.BLOCKED,
            RemediationStatus.ACCEPTED_RISK,
        }
    ),
    RemediationStatus.IN_PROGRESS: frozenset(
        {
            RemediationStatus.BLOCKED,
            RemediationStatus.READY_FOR_VERIFICATION,
            RemediationStatus.ACCEPTED_RISK,
        }
    ),
    RemediationStatus.BLOCKED: frozenset(
        {RemediationStatus.IN_PROGRESS, RemediationStatus.ACCEPTED_RISK}
    ),
    RemediationStatus.READY_FOR_VERIFICATION: frozenset(
        {RemediationStatus.IN_PROGRESS, RemediationStatus.BLOCKED}
    ),
    RemediationStatus.VERIFIED: frozenset({RemediationStatus.OPEN}),
    RemediationStatus.ACCEPTED_RISK: frozenset(
        {RemediationStatus.OPEN, RemediationStatus.PLANNED}
    ),
}


def _now(value: datetime | None = None) -> datetime:
    return as_utc(value or datetime.now(UTC)) or datetime.now(UTC)


def _priority_from_severity(severity: Severity) -> RemediationPriority:
    if severity == Severity.CRITICAL:
        return RemediationPriority.CRITICAL
    if severity == Severity.HIGH:
        return RemediationPriority.HIGH
    if severity == Severity.MEDIUM:
        return RemediationPriority.MEDIUM
    return RemediationPriority.LOW


class RemediationRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def create_from_finding(
        self,
        *,
        workspace_id: str,
        finding_id: str,
        created_by: str,
        owner: str | None = None,
        priority: RemediationPriority | None = None,
        target_algorithm: str | None = None,
        due_date: date | None = None,
        notes: str | None = None,
        now: datetime | None = None,
    ) -> MigrationItem:
        if not created_by.strip():
            raise ValueError("created_by is required")
        current = _now(now)
        with self.SessionLocal() as session:
            row = session.execute(
                select(FindingRecord, FindingScopeRecord)
                .join(FindingScopeRecord, FindingScopeRecord.finding_id == FindingRecord.id)
                .where(
                    FindingRecord.id == finding_id,
                    FindingScopeRecord.workspace_id == workspace_id,
                )
            ).first()
            if row is None:
                raise LookupError("finding not found in workspace")
            finding_record, scope = row
            occurrence = session.scalar(
                select(ObservationOccurrenceRecord)
                .where(
                    ObservationOccurrenceRecord.workspace_id == workspace_id,
                    ObservationOccurrenceRecord.asset_id == scope.managed_asset_id,
                    ObservationOccurrenceRecord.finding_id == finding_id,
                )
                .order_by(ObservationOccurrenceRecord.observed_at.desc())
            )
            if occurrence is None:
                raise ValueError(
                    "finding has no continuous provenance; rescan the managed asset "
                    "before creating migration work"
                )

            finding = Finding.model_validate_json(finding_record.payload)
            selected_priority = priority or _priority_from_severity(finding.risk.severity)
            selected_target = target_algorithm or finding.risk.migration_target
            title = (
                f"Migrate {finding.observation.algorithm} on "
                f"{finding.observation.asset_name}"
            )[:300]
            record = MigrationItemRecord(
                id=str(uuid4()),
                workspace_id=workspace_id,
                asset_id=scope.managed_asset_id,
                observation_fingerprint=occurrence.fingerprint,
                source_finding_id=finding_id,
                source_scan_job_id=occurrence.job_id,
                title=title,
                owner=owner.strip()[:200] if owner and owner.strip() else None,
                status=RemediationStatus.OPEN.value,
                priority=selected_priority.value,
                target_algorithm=selected_target[:200] if selected_target else None,
                due_date=due_date,
                notes=notes.strip() if notes and notes.strip() else None,
                acceptance_reason=None,
                verification_job_id=None,
                verified_at=None,
                verification_evidence_json="{}",
                source_finding_json=finding.model_dump_json(),
                created_by=created_by.strip()[:200],
                created_at=current,
                updated_at=current,
            )
            session.add(record)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError(
                    "migration work already exists for this cryptographic exposure"
                ) from exc
            session.refresh(record)
            return self._item(record)

    def list_items(
        self,
        *,
        workspace_id: str,
        status: RemediationStatus | None = None,
        owner: str | None = None,
        limit: int = 500,
    ) -> list[MigrationItem]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self.SessionLocal() as session:
            statement = select(MigrationItemRecord).where(
                MigrationItemRecord.workspace_id == workspace_id
            )
            if status is not None:
                statement = statement.where(MigrationItemRecord.status == status.value)
            if owner:
                statement = statement.where(MigrationItemRecord.owner == owner)
            rows = session.scalars(
                statement.order_by(
                    MigrationItemRecord.due_date.is_(None),
                    MigrationItemRecord.due_date,
                    MigrationItemRecord.created_at.desc(),
                ).limit(limit)
            ).all()
            return [self._item(row) for row in rows]

    def get_item(self, *, workspace_id: str, item_id: str) -> MigrationItem | None:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(MigrationItemRecord).where(
                    MigrationItemRecord.workspace_id == workspace_id,
                    MigrationItemRecord.id == item_id,
                )
            )
            return self._item(row) if row else None

    def update_item(
        self,
        *,
        workspace_id: str,
        item_id: str,
        changes: dict[str, object],
        now: datetime | None = None,
    ) -> MigrationItem:
        current = _now(now)
        allowed = {
            "owner",
            "status",
            "priority",
            "target_algorithm",
            "due_date",
            "notes",
            "acceptance_reason",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"unsupported remediation fields: {', '.join(sorted(unknown))}")

        with self.SessionLocal() as session:
            row = session.scalar(
                select(MigrationItemRecord).where(
                    MigrationItemRecord.workspace_id == workspace_id,
                    MigrationItemRecord.id == item_id,
                )
            )
            if row is None:
                raise LookupError("migration item not found in workspace")

            if "status" in changes and changes["status"] is not None:
                target = RemediationStatus(str(changes["status"]))
                current_status = RemediationStatus(row.status)
                if (
                    target != current_status
                    and target not in _ALLOWED_TRANSITIONS[current_status]
                ):
                    raise ValueError(
                        "invalid remediation transition: "
                        f"{current_status.value} -> {target.value}"
                    )
                if target == RemediationStatus.VERIFIED:
                    raise ValueError(
                        "verified status can only be reached through rescan verification"
                    )
                row.status = target.value
                if target == RemediationStatus.ACCEPTED_RISK:
                    reason = changes.get("acceptance_reason", row.acceptance_reason)
                    if not isinstance(reason, str) or len(reason.strip()) < 5:
                        raise ValueError("accepted risk requires an acceptance reason")
                    row.acceptance_reason = reason.strip()
                else:
                    row.acceptance_reason = None
                row.verified_at = None

            if "owner" in changes:
                value = changes["owner"]
                row.owner = str(value).strip()[:200] if value else None
            if "priority" in changes and changes["priority"] is not None:
                row.priority = RemediationPriority(str(changes["priority"])).value
            if "target_algorithm" in changes:
                value = changes["target_algorithm"]
                row.target_algorithm = str(value).strip()[:200] if value else None
            if "due_date" in changes:
                value = changes["due_date"]
                if value is not None and not isinstance(value, date):
                    raise ValueError("due_date must be a date")
                row.due_date = value
            if "notes" in changes:
                value = changes["notes"]
                row.notes = str(value).strip() if value else None
            if (
                "acceptance_reason" in changes
                and row.status == RemediationStatus.ACCEPTED_RISK.value
            ):
                value = changes["acceptance_reason"]
                if not isinstance(value, str) or len(value.strip()) < 5:
                    raise ValueError("accepted risk requires an acceptance reason")
                row.acceptance_reason = value.strip()

            row.updated_at = current
            session.commit()
            session.refresh(row)
            return self._item(row)

    def verify(
        self,
        *,
        workspace_id: str,
        item_id: str,
        verification_job_id: str,
        now: datetime | None = None,
    ) -> RemediationVerification:
        current = _now(now)
        with self.SessionLocal() as session:
            row = session.scalar(
                select(MigrationItemRecord).where(
                    MigrationItemRecord.workspace_id == workspace_id,
                    MigrationItemRecord.id == item_id,
                )
            )
            if row is None:
                raise LookupError("migration item not found in workspace")
            if row.status != RemediationStatus.READY_FOR_VERIFICATION.value:
                raise ValueError("migration item must be ready-for-verification")

            job = session.scalar(
                select(ScanJobRecord).where(
                    ScanJobRecord.id == verification_job_id,
                    ScanJobRecord.workspace_id == workspace_id,
                    ScanJobRecord.asset_id == row.asset_id,
                    ScanJobRecord.status == ScanStatus.SUCCEEDED.value,
                )
            )
            if job is None:
                raise ValueError(
                    "verification requires a successful scan of the same managed asset"
                )

            snapshot = session.get(ScanSnapshotRecord, verification_job_id)
            if snapshot is None:
                raise ValueError("verification scan has no retained evidence snapshot")
            latest_snapshot = session.scalar(
                select(ScanSnapshotRecord)
                .where(
                    ScanSnapshotRecord.workspace_id == workspace_id,
                    ScanSnapshotRecord.asset_id == row.asset_id,
                )
                .order_by(
                    ScanSnapshotRecord.completed_at.desc(),
                    ScanSnapshotRecord.job_id.desc(),
                )
            )
            if latest_snapshot is None or latest_snapshot.job_id != verification_job_id:
                raise ValueError(
                    "verification must use the latest successful evidence snapshot"
                )
            source_snapshot = session.get(ScanSnapshotRecord, row.source_scan_job_id)
            if (
                source_snapshot is not None
                and snapshot.completed_at <= source_snapshot.completed_at
            ):
                raise ValueError("verification scan must be newer than the source finding")

            occurrence = session.scalar(
                select(ObservationOccurrenceRecord).where(
                    ObservationOccurrenceRecord.job_id == verification_job_id,
                    ObservationOccurrenceRecord.fingerprint
                    == row.observation_fingerprint,
                )
            )
            resolved = occurrence is None
            evidence: dict[str, object] = {
                "outcome": "resolved" if resolved else "still-present",
                "verification_job_id": verification_job_id,
                "verification_completed_at": snapshot.completed_at.isoformat(),
                "source_scan_job_id": row.source_scan_job_id,
                "observation_fingerprint": row.observation_fingerprint,
            }
            if occurrence is not None:
                evidence.update(
                    {
                        "risk_score": occurrence.risk_score,
                        "severity": occurrence.severity,
                        "evidence_hash": occurrence.evidence_hash,
                    }
                )

            row.verification_job_id = verification_job_id
            row.verification_evidence_json = json.dumps(evidence, sort_keys=True)
            row.updated_at = current
            if resolved:
                row.status = RemediationStatus.VERIFIED.value
                row.verified_at = current
            else:
                row.status = RemediationStatus.IN_PROGRESS.value
                row.verified_at = None
            session.commit()
            session.refresh(row)
            item = self._item(row)
            return RemediationVerification(
                item=item,
                verified=resolved,
                outcome="resolved" if resolved else "still-present",
            )

    @staticmethod
    def _item(row: MigrationItemRecord) -> MigrationItem:
        return MigrationItem(
            id=row.id,
            workspace_id=row.workspace_id,
            asset_id=row.asset_id,
            observation_fingerprint=row.observation_fingerprint,
            source_finding_id=row.source_finding_id,
            source_scan_job_id=row.source_scan_job_id,
            title=row.title,
            owner=row.owner,
            status=RemediationStatus(row.status),
            priority=RemediationPriority(row.priority),
            target_algorithm=row.target_algorithm,
            due_date=row.due_date,
            notes=row.notes,
            acceptance_reason=row.acceptance_reason,
            verification_job_id=row.verification_job_id,
            verified_at=as_utc(row.verified_at),
            verification_evidence=json.loads(row.verification_evidence_json or "{}"),
            source_finding=Finding.model_validate_json(row.source_finding_json),
            created_by=row.created_by,
            created_at=as_utc(row.created_at) or row.created_at,
            updated_at=as_utc(row.updated_at) or row.updated_at,
        )
