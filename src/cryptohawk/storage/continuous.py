from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk import __version__
from cryptohawk.domain.continuous import (
    DriftEvent,
    DriftEventType,
    ObservationState,
    ScanOrigin,
    ScanSchedule,
    ScanSnapshot,
)
from cryptohawk.domain.models import Finding
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.time import as_utc

POLICY_VERSION = "risk-engine-v1"


def _utc(value: datetime | None = None) -> datetime:
    normalized = as_utc(value or datetime.now(UTC))
    if normalized is None:
        raise ValueError("datetime value is required")
    return normalized


class ScanScheduleRecord(Base):
    __tablename__ = "scan_schedules"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "asset_id",
            name="uq_scan_schedule_workspace_asset",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True
    )
    interval_seconds: Mapped[int] = mapped_column(Integer)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(200), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ScheduledExecutionRecord(Base):
    __tablename__ = "scheduled_executions"
    __table_args__ = (
        UniqueConstraint(
            "schedule_id",
            "scheduled_for",
            name="uq_scheduled_execution_occurrence",
        ),
    )

    job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    schedule_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_schedules.id", ondelete="CASCADE"), index=True
    )
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    enqueued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ScanSnapshotRecord(Base):
    __tablename__ = "scan_snapshots"

    job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    origin: Mapped[str] = mapped_column(String(30), index=True)
    schedule_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finding_count: Mapped[int] = mapped_column(Integer)
    scanner_version: Mapped[str] = mapped_column(String(80))
    policy_version: Mapped[str] = mapped_column(String(80))
    fingerprint_set_hash: Mapped[str] = mapped_column(String(64), index=True)


class ObservationStateRecord(Base):
    __tablename__ = "observation_states"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "asset_id",
            "fingerprint",
            name="uq_observation_state_identity",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    first_job_id: Mapped[str] = mapped_column(String(64), index=True)
    last_job_id: Mapped[str] = mapped_column(String(64), index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    quantum_status: Mapped[str] = mapped_column(String(30), index=True)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    finding_payload: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ObservationOccurrenceRecord(Base):
    __tablename__ = "observation_occurrences"
    __table_args__ = (
        UniqueConstraint(
            "job_id",
            "fingerprint",
            name="uq_observation_occurrence_job_fingerprint",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    quantum_status: Mapped[str] = mapped_column(String(30), index=True)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    finding_payload: Mapped[str] = mapped_column(Text)
    scanner_version: Mapped[str] = mapped_column(String(80))
    policy_version: Mapped[str] = mapped_column(String(80))


class DriftEventRecord(Base):
    __tablename__ = "drift_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    scan_job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    previous_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    new_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    previous_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    new_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class ContinuousRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def create_schedule(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        interval_seconds: int,
        max_attempts: int = 3,
        first_run_at: datetime | None = None,
        created_by: str,
        now: datetime | None = None,
    ) -> ScanSchedule:
        if not 60 <= interval_seconds <= 2_592_000:
            raise ValueError("schedule interval must be between 60 seconds and 30 days")
        if not 1 <= max_attempts <= 20:
            raise ValueError("max_attempts must be between 1 and 20")
        if not created_by.strip():
            raise ValueError("created_by is required")
        if self.inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id) is None:
            raise LookupError("asset not found in workspace")

        current = _utc(now)
        next_run_at = _utc(first_run_at) if first_run_at is not None else current
        schedule = ScanSchedule(
            workspace_id=workspace_id,
            asset_id=asset_id,
            interval_seconds=interval_seconds,
            max_attempts=max_attempts,
            next_run_at=next_run_at,
            created_by=created_by,
            created_at=current,
            updated_at=current,
        )
        with self.SessionLocal() as session:
            session.add(
                ScanScheduleRecord(
                    id=schedule.id,
                    workspace_id=workspace_id,
                    asset_id=asset_id,
                    interval_seconds=interval_seconds,
                    max_attempts=max_attempts,
                    enabled=True,
                    next_run_at=schedule.next_run_at,
                    last_run_at=None,
                    created_by=created_by,
                    created_at=current,
                    updated_at=current,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError("asset already has a scan schedule") from exc
        return schedule

    def list_schedules(self, *, workspace_id: str) -> list[ScanSchedule]:
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(ScanScheduleRecord)
                .where(ScanScheduleRecord.workspace_id == workspace_id)
                .order_by(ScanScheduleRecord.next_run_at, ScanScheduleRecord.id)
            ).all()
            return [self._schedule(row) for row in rows]

    def get_schedule(self, *, workspace_id: str, schedule_id: str) -> ScanSchedule | None:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(ScanScheduleRecord).where(
                    ScanScheduleRecord.id == schedule_id,
                    ScanScheduleRecord.workspace_id == workspace_id,
                )
            )
            return self._schedule(row) if row else None

    def set_schedule_enabled(
        self,
        *,
        workspace_id: str,
        schedule_id: str,
        enabled: bool,
        resume_at: datetime | None = None,
        now: datetime | None = None,
    ) -> ScanSchedule:
        current = _utc(now)
        values: dict[str, object] = {"enabled": enabled, "updated_at": current}
        if enabled and resume_at is not None:
            values["next_run_at"] = _utc(resume_at)
        with self.SessionLocal() as session:
            result = session.execute(
                update(ScanScheduleRecord)
                .where(
                    ScanScheduleRecord.id == schedule_id,
                    ScanScheduleRecord.workspace_id == workspace_id,
                )
                .values(**values)
            )
            if result.rowcount != 1:
                session.rollback()
                raise LookupError("scan schedule not found in workspace")
            session.commit()
        schedule = self.get_schedule(workspace_id=workspace_id, schedule_id=schedule_id)
        if schedule is None:
            raise RuntimeError("scan schedule disappeared after update")
        return schedule

    def delete_schedule(self, *, workspace_id: str, schedule_id: str) -> None:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(ScanScheduleRecord).where(
                    ScanScheduleRecord.id == schedule_id,
                    ScanScheduleRecord.workspace_id == workspace_id,
                )
            )
            if row is None:
                raise LookupError("scan schedule not found in workspace")
            session.delete(row)
            session.commit()

    def list_due_schedules(
        self,
        *,
        now: datetime | None = None,
        limit: int = 100,
    ) -> list[ScanSchedule]:
        current = _utc(now)
        if not 1 <= limit <= 1000:
            raise ValueError("schedule batch limit must be between 1 and 1000")
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(ScanScheduleRecord)
                .where(
                    ScanScheduleRecord.enabled.is_(True),
                    ScanScheduleRecord.next_run_at <= current,
                )
                .order_by(ScanScheduleRecord.next_run_at, ScanScheduleRecord.id)
                .limit(limit)
            ).all()
            return [self._schedule(row) for row in rows]

    def advance_schedule(
        self,
        *,
        schedule: ScanSchedule,
        scheduled_for: datetime,
        now: datetime | None = None,
    ) -> bool:
        current = _utc(now)
        scheduled_for = _utc(scheduled_for)
        next_run = scheduled_for + timedelta(seconds=schedule.interval_seconds)
        while next_run <= current:
            next_run += timedelta(seconds=schedule.interval_seconds)
        with self.SessionLocal() as session:
            result = session.execute(
                update(ScanScheduleRecord)
                .where(
                    ScanScheduleRecord.id == schedule.id,
                    ScanScheduleRecord.workspace_id == schedule.workspace_id,
                    ScanScheduleRecord.enabled.is_(True),
                    ScanScheduleRecord.next_run_at == scheduled_for,
                )
                .values(
                    last_run_at=scheduled_for,
                    next_run_at=next_run,
                    updated_at=current,
                )
            )
            if result.rowcount != 1:
                session.rollback()
                return False
            session.commit()
            return True

    def record_scheduled_execution(
        self,
        *,
        schedule: ScanSchedule,
        job_id: str,
        scheduled_for: datetime,
        now: datetime | None = None,
    ) -> None:
        current = _utc(now)
        scheduled_for = _utc(scheduled_for)
        with self.SessionLocal() as session:
            existing = session.scalar(
                select(ScheduledExecutionRecord).where(
                    ScheduledExecutionRecord.schedule_id == schedule.id,
                    ScheduledExecutionRecord.scheduled_for == scheduled_for,
                )
            )
            if existing is not None:
                if existing.job_id != job_id:
                    raise RuntimeError("scheduled occurrence is bound to another scan job")
                return
            session.add(
                ScheduledExecutionRecord(
                    job_id=job_id,
                    schedule_id=schedule.id,
                    workspace_id=schedule.workspace_id,
                    asset_id=schedule.asset_id,
                    scheduled_for=scheduled_for,
                    enqueued_at=current,
                )
            )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = session.scalar(
                    select(ScheduledExecutionRecord).where(
                        ScheduledExecutionRecord.schedule_id == schedule.id,
                        ScheduledExecutionRecord.scheduled_for == scheduled_for,
                    )
                )
                if existing is None or existing.job_id != job_id:
                    raise

    @staticmethod
    def observation_fingerprint(finding: Finding) -> str:
        observation = finding.observation
        payload = {
            "asset_id": observation.asset_id,
            "crypto_asset_type": observation.crypto_asset_type.value,
            "algorithm": observation.algorithm.strip().casefold(),
            "family": observation.family.strip().casefold(),
            "primitive": observation.primitive.value,
            "parameter_set": observation.parameter_set,
            "key_size": observation.key_size,
            "protocol_version": observation.protocol_version,
            "source": observation.evidence.source.strip().casefold(),
            "locator": observation.evidence.locator,
            "line": observation.evidence.line,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def evidence_hash(finding: Finding) -> str:
        observation = finding.observation
        payload = {
            "evidence": observation.evidence.model_dump(mode="json"),
            "parameter_set": observation.parameter_set,
            "key_size": observation.key_size,
            "protocol_version": observation.protocol_version,
            "confidence": observation.confidence,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def prepare_findings(self, scan_job_id: str, findings: Iterable[Finding]) -> list[Finding]:
        selected: dict[str, Finding] = {}
        for finding in findings:
            fingerprint = self.observation_fingerprint(finding)
            current = selected.get(fingerprint)
            if current is None or finding.risk.score > current.risk.score:
                selected[fingerprint] = finding

        prepared: list[Finding] = []
        for fingerprint in sorted(selected):
            finding = selected[fingerprint]
            observation_id = hashlib.sha256(
                f"scan:{scan_job_id}|observation:{fingerprint}".encode()
            ).hexdigest()
            observation = finding.observation.model_copy(update={"id": observation_id})
            risk = finding.risk.model_copy(update={"observation_id": observation_id})
            prepared.append(Finding(observation=observation, risk=risk))
        return prepared

    def record_successful_scan(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        scan_job_id: str,
        findings: Iterable[Finding],
        now: datetime | None = None,
        scanner_version: str = __version__,
        policy_version: str = POLICY_VERSION,
    ) -> list[DriftEvent]:
        current = _utc(now)
        prepared = self.prepare_findings(scan_job_id, findings)
        current_by_fingerprint = {
            self.observation_fingerprint(finding): finding for finding in prepared
        }

        with self.SessionLocal() as session:
            existing_snapshot = session.get(ScanSnapshotRecord, scan_job_id)
            if existing_snapshot is not None:
                rows = session.scalars(
                    select(DriftEventRecord)
                    .where(DriftEventRecord.scan_job_id == scan_job_id)
                    .order_by(DriftEventRecord.occurred_at, DriftEventRecord.id)
                ).all()
                return [self._drift_event(row) for row in rows]

            prior_snapshot_count = session.scalar(
                select(func.count())
                .select_from(ScanSnapshotRecord)
                .where(
                    ScanSnapshotRecord.workspace_id == workspace_id,
                    ScanSnapshotRecord.asset_id == asset_id,
                )
            ) or 0
            baseline_exists = prior_snapshot_count > 0

            states = session.scalars(
                select(ObservationStateRecord).where(
                    ObservationStateRecord.workspace_id == workspace_id,
                    ObservationStateRecord.asset_id == asset_id,
                )
            ).all()
            states_by_fingerprint = {row.fingerprint: row for row in states}
            active_before = {row.fingerprint for row in states if row.active}
            events: list[DriftEvent] = []

            for fingerprint, finding in current_by_fingerprint.items():
                evidence_hash = self.evidence_hash(finding)
                state = states_by_fingerprint.get(fingerprint)
                payload = finding.model_dump_json()
                if state is None:
                    state = ObservationStateRecord(
                        id=hashlib.sha256(
                            f"{workspace_id}|{asset_id}|{fingerprint}".encode()
                        ).hexdigest(),
                        workspace_id=workspace_id,
                        asset_id=asset_id,
                        fingerprint=fingerprint,
                        active=True,
                        first_seen=current,
                        last_seen=current,
                        first_job_id=scan_job_id,
                        last_job_id=scan_job_id,
                        occurrence_count=1,
                        risk_score=finding.risk.score,
                        severity=finding.risk.severity.value,
                        quantum_status=finding.risk.quantum_status.value,
                        evidence_hash=evidence_hash,
                        finding_payload=payload,
                        updated_at=current,
                    )
                    session.add(state)
                    states_by_fingerprint[fingerprint] = state
                    if baseline_exists:
                        events.append(
                            self._new_event(
                                workspace_id=workspace_id,
                                asset_id=asset_id,
                                scan_job_id=scan_job_id,
                                fingerprint=fingerprint,
                                event_type=DriftEventType.INTRODUCED,
                                finding=finding,
                                occurred_at=current,
                            )
                        )
                else:
                    was_active = state.active
                    previous_score = state.risk_score
                    previous_severity = state.severity
                    changed = (
                        state.evidence_hash != evidence_hash
                        or state.severity != finding.risk.severity.value
                        or state.quantum_status != finding.risk.quantum_status.value
                    )
                    if baseline_exists and not was_active:
                        events.append(
                            self._new_event(
                                workspace_id=workspace_id,
                                asset_id=asset_id,
                                scan_job_id=scan_job_id,
                                fingerprint=fingerprint,
                                event_type=DriftEventType.INTRODUCED,
                                finding=finding,
                                previous_risk_score=previous_score,
                                previous_severity=previous_severity,
                                occurred_at=current,
                            )
                        )
                    if baseline_exists and was_active and changed:
                        events.append(
                            self._new_event(
                                workspace_id=workspace_id,
                                asset_id=asset_id,
                                scan_job_id=scan_job_id,
                                fingerprint=fingerprint,
                                event_type=DriftEventType.CHANGED,
                                finding=finding,
                                previous_risk_score=previous_score,
                                previous_severity=previous_severity,
                                occurred_at=current,
                            )
                        )
                    if baseline_exists and was_active and finding.risk.score > previous_score:
                        events.append(
                            self._new_event(
                                workspace_id=workspace_id,
                                asset_id=asset_id,
                                scan_job_id=scan_job_id,
                                fingerprint=fingerprint,
                                event_type=DriftEventType.RISK_INCREASED,
                                finding=finding,
                                previous_risk_score=previous_score,
                                previous_severity=previous_severity,
                                occurred_at=current,
                            )
                        )
                    elif baseline_exists and was_active and finding.risk.score < previous_score:
                        events.append(
                            self._new_event(
                                workspace_id=workspace_id,
                                asset_id=asset_id,
                                scan_job_id=scan_job_id,
                                fingerprint=fingerprint,
                                event_type=DriftEventType.RISK_DECREASED,
                                finding=finding,
                                previous_risk_score=previous_score,
                                previous_severity=previous_severity,
                                occurred_at=current,
                            )
                        )

                    state.active = True
                    state.last_seen = current
                    state.last_job_id = scan_job_id
                    state.occurrence_count += 1
                    state.risk_score = finding.risk.score
                    state.severity = finding.risk.severity.value
                    state.quantum_status = finding.risk.quantum_status.value
                    state.evidence_hash = evidence_hash
                    state.finding_payload = payload
                    state.updated_at = current

                session.add(
                    ObservationOccurrenceRecord(
                        id=hashlib.sha256(
                            f"{scan_job_id}|{fingerprint}".encode()
                        ).hexdigest(),
                        job_id=scan_job_id,
                        workspace_id=workspace_id,
                        asset_id=asset_id,
                        fingerprint=fingerprint,
                        finding_id=finding.observation.id,
                        observed_at=current,
                        risk_score=finding.risk.score,
                        severity=finding.risk.severity.value,
                        quantum_status=finding.risk.quantum_status.value,
                        evidence_hash=evidence_hash,
                        finding_payload=payload,
                        scanner_version=scanner_version,
                        policy_version=policy_version,
                    )
                )

            for fingerprint in sorted(active_before - set(current_by_fingerprint)):
                state = states_by_fingerprint[fingerprint]
                if baseline_exists:
                    previous_finding = Finding.model_validate_json(state.finding_payload)
                    events.append(
                        self._new_event(
                            workspace_id=workspace_id,
                            asset_id=asset_id,
                            scan_job_id=scan_job_id,
                            fingerprint=fingerprint,
                            event_type=DriftEventType.RESOLVED,
                            finding=previous_finding,
                            previous_risk_score=state.risk_score,
                            previous_severity=state.severity,
                            resolved=True,
                            occurred_at=current,
                        )
                    )
                state.active = False
                state.last_job_id = scan_job_id
                state.updated_at = current

            for event in events:
                session.add(self._drift_record(event))

            scheduled = session.get(ScheduledExecutionRecord, scan_job_id)
            origin = ScanOrigin.SCHEDULE if scheduled is not None else ScanOrigin.API
            fingerprints = sorted(current_by_fingerprint)
            fingerprint_set_hash = hashlib.sha256("|".join(fingerprints).encode()).hexdigest()
            session.add(
                ScanSnapshotRecord(
                    job_id=scan_job_id,
                    workspace_id=workspace_id,
                    asset_id=asset_id,
                    origin=origin.value,
                    schedule_id=scheduled.schedule_id if scheduled else None,
                    scheduled_for=scheduled.scheduled_for if scheduled else None,
                    completed_at=current,
                    finding_count=len(prepared),
                    scanner_version=scanner_version,
                    policy_version=policy_version,
                    fingerprint_set_hash=fingerprint_set_hash,
                )
            )
            session.commit()
            return events

    def list_scan_history(
        self,
        *,
        workspace_id: str,
        asset_id: str | None = None,
        limit: int = 100,
    ) -> list[ScanSnapshot]:
        with self.SessionLocal() as session:
            statement = select(ScanSnapshotRecord).where(
                ScanSnapshotRecord.workspace_id == workspace_id
            )
            if asset_id is not None:
                statement = statement.where(ScanSnapshotRecord.asset_id == asset_id)
            rows = session.scalars(
                statement.order_by(ScanSnapshotRecord.completed_at.desc()).limit(limit)
            ).all()
            return [self._snapshot(row) for row in rows]

    def list_drift_events(
        self,
        *,
        workspace_id: str,
        asset_id: str | None = None,
        limit: int = 200,
    ) -> list[DriftEvent]:
        with self.SessionLocal() as session:
            statement = select(DriftEventRecord).where(
                DriftEventRecord.workspace_id == workspace_id
            )
            if asset_id is not None:
                statement = statement.where(DriftEventRecord.asset_id == asset_id)
            rows = session.scalars(
                statement.order_by(DriftEventRecord.occurred_at.desc()).limit(limit)
            ).all()
            return [self._drift_event(row) for row in rows]

    def list_observation_states(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        active_only: bool = False,
    ) -> list[ObservationState]:
        with self.SessionLocal() as session:
            statement = select(ObservationStateRecord).where(
                ObservationStateRecord.workspace_id == workspace_id,
                ObservationStateRecord.asset_id == asset_id,
            )
            if active_only:
                statement = statement.where(ObservationStateRecord.active.is_(True))
            rows = session.scalars(
                statement.order_by(ObservationStateRecord.fingerprint)
            ).all()
            return [self._state(row) for row in rows]

    @staticmethod
    def scheduled_job_id(schedule_id: str, scheduled_for: datetime) -> str:
        normalized = _utc(scheduled_for)
        return hashlib.sha256(
            f"schedule:{schedule_id}|at:{normalized.isoformat()}".encode()
        ).hexdigest()

    @staticmethod
    def _new_event(
        *,
        workspace_id: str,
        asset_id: str,
        scan_job_id: str,
        fingerprint: str,
        event_type: DriftEventType,
        finding: Finding,
        occurred_at: datetime,
        previous_risk_score: int | None = None,
        previous_severity: str | None = None,
        resolved: bool = False,
    ) -> DriftEvent:
        observation = finding.observation
        return DriftEvent(
            workspace_id=workspace_id,
            asset_id=asset_id,
            scan_job_id=scan_job_id,
            fingerprint=fingerprint,
            event_type=event_type,
            previous_risk_score=previous_risk_score,
            new_risk_score=None if resolved else finding.risk.score,
            previous_severity=previous_severity,
            new_severity=None if resolved else finding.risk.severity.value,
            occurred_at=occurred_at,
            details={
                "algorithm": observation.algorithm,
                "primitive": observation.primitive.value,
                "locator": observation.evidence.locator,
                "line": observation.evidence.line,
                "quantum_status": finding.risk.quantum_status.value,
            },
        )

    @staticmethod
    def _schedule(row: ScanScheduleRecord) -> ScanSchedule:
        return ScanSchedule(
            id=row.id,
            workspace_id=row.workspace_id,
            asset_id=row.asset_id,
            interval_seconds=row.interval_seconds,
            max_attempts=row.max_attempts,
            enabled=row.enabled,
            next_run_at=_utc(row.next_run_at),
            last_run_at=as_utc(row.last_run_at),
            created_by=row.created_by,
            created_at=_utc(row.created_at),
            updated_at=_utc(row.updated_at),
        )

    @staticmethod
    def _snapshot(row: ScanSnapshotRecord) -> ScanSnapshot:
        return ScanSnapshot(
            job_id=row.job_id,
            workspace_id=row.workspace_id,
            asset_id=row.asset_id,
            origin=ScanOrigin(row.origin),
            schedule_id=row.schedule_id,
            scheduled_for=as_utc(row.scheduled_for),
            completed_at=_utc(row.completed_at),
            finding_count=row.finding_count,
            scanner_version=row.scanner_version,
            policy_version=row.policy_version,
            fingerprint_set_hash=row.fingerprint_set_hash,
        )

    @staticmethod
    def _state(row: ObservationStateRecord) -> ObservationState:
        return ObservationState(
            workspace_id=row.workspace_id,
            asset_id=row.asset_id,
            fingerprint=row.fingerprint,
            active=row.active,
            first_seen=_utc(row.first_seen),
            last_seen=_utc(row.last_seen),
            first_job_id=row.first_job_id,
            last_job_id=row.last_job_id,
            occurrence_count=row.occurrence_count,
            risk_score=row.risk_score,
            severity=row.severity,
            quantum_status=row.quantum_status,
            evidence_hash=row.evidence_hash,
        )

    @staticmethod
    def _drift_record(event: DriftEvent) -> DriftEventRecord:
        return DriftEventRecord(
            id=event.id,
            workspace_id=event.workspace_id,
            asset_id=event.asset_id,
            scan_job_id=event.scan_job_id,
            fingerprint=event.fingerprint,
            event_type=event.event_type.value,
            previous_risk_score=event.previous_risk_score,
            new_risk_score=event.new_risk_score,
            previous_severity=event.previous_severity,
            new_severity=event.new_severity,
            occurred_at=event.occurred_at,
            details_json=json.dumps(event.details, sort_keys=True),
        )

    @staticmethod
    def _drift_event(row: DriftEventRecord) -> DriftEvent:
        return DriftEvent(
            id=row.id,
            workspace_id=row.workspace_id,
            asset_id=row.asset_id,
            scan_job_id=row.scan_job_id,
            fingerprint=row.fingerprint,
            event_type=DriftEventType(row.event_type),
            previous_risk_score=row.previous_risk_score,
            new_risk_score=row.new_risk_score,
            previous_severity=row.previous_severity,
            new_severity=row.new_severity,
            occurred_at=_utc(row.occurred_at),
            details=json.loads(row.details_json),
        )
