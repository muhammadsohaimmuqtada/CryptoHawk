from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, select, update
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.inventory import ScanJob, ScanKind, ScanStatus
from cryptohawk.domain.queue import ScanLease, ScanQueueState
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository, ScanJobRecord
from cryptohawk.storage.time import as_utc


class ScanQueueRecord(Base):
    __tablename__ = "scan_queue"

    job_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    lease_owner: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class ScanQueueRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def enqueue(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        kind: ScanKind,
        max_attempts: int = 3,
        now: datetime | None = None,
    ) -> ScanJob:
        if not 1 <= max_attempts <= 20:
            raise ValueError("max_attempts must be between 1 and 20")
        now = now or datetime.now(UTC)
        job = self.inventory.create_scan_job(
            workspace_id=workspace_id,
            asset_id=asset_id,
            kind=kind,
        )
        with self.SessionLocal() as session:
            session.add(
                ScanQueueRecord(
                    job_id=job.id,
                    attempts=0,
                    max_attempts=max_attempts,
                    next_attempt_at=now,
                    cancel_requested=False,
                )
            )
            session.commit()
        return job

    def claim_next(
        self,
        *,
        worker_id: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> ScanLease | None:
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        if not 5 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 5 and 3600")
        now = now or datetime.now(UTC)
        lease_expires_at = now + timedelta(seconds=lease_seconds)

        with self.SessionLocal() as session:
            candidate_ids = session.scalars(
                select(ScanQueueRecord.job_id)
                .join(ScanJobRecord, ScanJobRecord.id == ScanQueueRecord.job_id)
                .where(
                    ScanJobRecord.status == ScanStatus.QUEUED.value,
                    ScanQueueRecord.cancel_requested.is_(False),
                    ScanQueueRecord.lease_owner.is_(None),
                    ScanQueueRecord.next_attempt_at <= now,
                    ScanQueueRecord.attempts < ScanQueueRecord.max_attempts,
                )
                .order_by(ScanJobRecord.requested_at, ScanQueueRecord.job_id)
                .limit(20)
            ).all()

            for job_id in candidate_ids:
                queue_update = session.execute(
                    update(ScanQueueRecord)
                    .where(
                        ScanQueueRecord.job_id == job_id,
                        ScanQueueRecord.lease_owner.is_(None),
                        ScanQueueRecord.cancel_requested.is_(False),
                        ScanQueueRecord.next_attempt_at <= now,
                        ScanQueueRecord.attempts < ScanQueueRecord.max_attempts,
                    )
                    .values(
                        lease_owner=worker_id,
                        lease_expires_at=lease_expires_at,
                        last_heartbeat_at=now,
                        attempts=ScanQueueRecord.attempts + 1,
                    )
                )
                if queue_update.rowcount != 1:
                    session.rollback()
                    continue

                job_update = session.execute(
                    update(ScanJobRecord)
                    .where(
                        ScanJobRecord.id == job_id,
                        ScanJobRecord.status == ScanStatus.QUEUED.value,
                    )
                    .values(status=ScanStatus.RUNNING.value, started_at=now)
                )
                if job_update.rowcount != 1:
                    session.rollback()
                    continue
                session.commit()
                return self._lease_from_job_id(job_id, worker_id)
        return None

    def heartbeat(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> ScanLease:
        if not 5 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 5 and 3600")
        now = now or datetime.now(UTC)
        lease_expires_at = now + timedelta(seconds=lease_seconds)
        with self.SessionLocal() as session:
            result = session.execute(
                update(ScanQueueRecord)
                .where(
                    ScanQueueRecord.job_id == job_id,
                    ScanQueueRecord.lease_owner == worker_id,
                    ScanQueueRecord.cancel_requested.is_(False),
                )
                .values(
                    lease_expires_at=lease_expires_at,
                    last_heartbeat_at=now,
                )
            )
            if result.rowcount != 1:
                session.rollback()
                raise RuntimeError(
                    "scan lease is not owned by worker or cancellation was requested"
                )
            session.commit()
        return self._lease_from_job_id(job_id, worker_id)

    def complete(
        self,
        *,
        job_id: str,
        worker_id: str,
        findings_count: int,
        now: datetime | None = None,
    ) -> ScanJob:
        return self._finish(
            job_id=job_id,
            worker_id=worker_id,
            status=ScanStatus.SUCCEEDED,
            findings_count=findings_count,
            error_message=None,
            now=now,
        )

    def fail(
        self,
        *,
        job_id: str,
        worker_id: str,
        error_message: str,
        retryable: bool = True,
        backoff_seconds: int = 5,
        now: datetime | None = None,
    ) -> ScanJob:
        if backoff_seconds < 0:
            raise ValueError("backoff_seconds cannot be negative")
        now = now or datetime.now(UTC)
        state = self.get_state(job_id)
        if state is None or state.lease_owner != worker_id:
            raise RuntimeError("scan lease is not owned by worker")

        if retryable and state.attempts < state.max_attempts:
            with self.SessionLocal() as session:
                job_update = session.execute(
                    update(ScanJobRecord)
                    .where(
                        ScanJobRecord.id == job_id,
                        ScanJobRecord.status == ScanStatus.RUNNING.value,
                    )
                    .values(status=ScanStatus.QUEUED.value)
                )
                queue_update = session.execute(
                    update(ScanQueueRecord)
                    .where(
                        ScanQueueRecord.job_id == job_id,
                        ScanQueueRecord.lease_owner == worker_id,
                    )
                    .values(
                        lease_owner=None,
                        lease_expires_at=None,
                        last_heartbeat_at=None,
                        next_attempt_at=now + timedelta(seconds=backoff_seconds),
                    )
                )
                if job_update.rowcount != 1 or queue_update.rowcount != 1:
                    session.rollback()
                    raise RuntimeError("scan job state changed while scheduling retry")
                session.commit()
            job = self._get_job(job_id)
            if job is None:
                raise RuntimeError("scan job disappeared after retry scheduling")
            return job

        return self._finish(
            job_id=job_id,
            worker_id=worker_id,
            status=ScanStatus.FAILED,
            findings_count=0,
            error_message=error_message,
            now=now,
        )

    def request_cancel(self, *, job_id: str, now: datetime | None = None) -> ScanJob:
        now = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            job = session.get(ScanJobRecord, job_id)
            queue = session.get(ScanQueueRecord, job_id)
            if job is None or queue is None:
                raise LookupError("queued scan job not found")
            if job.status in {
                ScanStatus.SUCCEEDED.value,
                ScanStatus.FAILED.value,
                ScanStatus.CANCELED.value,
            }:
                session.rollback()
                return self._job_from_record(job)

            queue.cancel_requested = True
            if job.status == ScanStatus.QUEUED.value:
                job.status = ScanStatus.CANCELED.value
                job.finished_at = now
                queue.lease_owner = None
                queue.lease_expires_at = None
            session.commit()
        result = self._get_job(job_id)
        if result is None:
            raise RuntimeError("scan job disappeared after cancellation")
        return result

    def should_cancel(self, *, job_id: str, worker_id: str) -> bool:
        with self.SessionLocal() as session:
            value = session.scalar(
                select(ScanQueueRecord.cancel_requested).where(
                    ScanQueueRecord.job_id == job_id,
                    ScanQueueRecord.lease_owner == worker_id,
                )
            )
            if value is None:
                raise RuntimeError("scan lease is not owned by worker")
            return bool(value)

    def acknowledge_cancel(
        self,
        *,
        job_id: str,
        worker_id: str,
        now: datetime | None = None,
    ) -> ScanJob:
        return self._finish(
            job_id=job_id,
            worker_id=worker_id,
            status=ScanStatus.CANCELED,
            findings_count=0,
            error_message=None,
            now=now,
        )

    def recover_expired_leases(self, *, now: datetime | None = None) -> tuple[int, int]:
        now = now or datetime.now(UTC)
        requeued = 0
        failed = 0
        with self.SessionLocal() as session:
            rows = session.execute(
                select(ScanQueueRecord, ScanJobRecord)
                .join(ScanJobRecord, ScanJobRecord.id == ScanQueueRecord.job_id)
                .where(
                    ScanJobRecord.status == ScanStatus.RUNNING.value,
                    ScanQueueRecord.lease_expires_at.is_not(None),
                    ScanQueueRecord.lease_expires_at <= now,
                )
            ).all()
            for queue, job in rows:
                queue.lease_owner = None
                queue.lease_expires_at = None
                queue.last_heartbeat_at = None
                if queue.cancel_requested:
                    job.status = ScanStatus.CANCELED.value
                    job.finished_at = now
                    failed += 1
                elif queue.attempts >= queue.max_attempts:
                    job.status = ScanStatus.FAILED.value
                    job.finished_at = now
                    job.error_message = "worker lease expired after final attempt"
                    failed += 1
                else:
                    job.status = ScanStatus.QUEUED.value
                    queue.next_attempt_at = now
                    requeued += 1
            session.commit()
        return requeued, failed

    def get_state(self, job_id: str) -> ScanQueueState | None:
        with self.SessionLocal() as session:
            row = session.get(ScanQueueRecord, job_id)
            return self._state_from_record(row) if row else None

    def _finish(
        self,
        *,
        job_id: str,
        worker_id: str,
        status: ScanStatus,
        findings_count: int,
        error_message: str | None,
        now: datetime | None,
    ) -> ScanJob:
        if status not in {ScanStatus.SUCCEEDED, ScanStatus.FAILED, ScanStatus.CANCELED}:
            raise ValueError("finish status must be terminal")
        now = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            job_update = session.execute(
                update(ScanJobRecord)
                .where(
                    ScanJobRecord.id == job_id,
                    ScanJobRecord.status == ScanStatus.RUNNING.value,
                )
                .values(
                    status=status.value,
                    finished_at=now,
                    findings_count=findings_count,
                    error_message=error_message[:4000] if error_message else None,
                )
            )
            queue_update = session.execute(
                update(ScanQueueRecord)
                .where(
                    ScanQueueRecord.job_id == job_id,
                    ScanQueueRecord.lease_owner == worker_id,
                )
                .values(
                    lease_owner=None,
                    lease_expires_at=None,
                    last_heartbeat_at=None,
                )
            )
            if job_update.rowcount != 1 or queue_update.rowcount != 1:
                session.rollback()
                raise RuntimeError("scan job or lease ownership changed before completion")
            session.commit()
        job = self._get_job(job_id)
        if job is None:
            raise RuntimeError("scan job disappeared after completion")
        return job

    def _lease_from_job_id(self, job_id: str, worker_id: str) -> ScanLease:
        job = self._get_job(job_id)
        state = self.get_state(job_id)
        if job is None or state is None or state.lease_owner != worker_id:
            raise RuntimeError("unable to load claimed scan lease")
        if state.lease_expires_at is None:
            raise RuntimeError("claimed scan has no lease expiration")
        return ScanLease(
            job=job,
            worker_id=worker_id,
            attempt=state.attempts,
            max_attempts=state.max_attempts,
            lease_expires_at=as_utc(state.lease_expires_at),
        )

    def _get_job(self, job_id: str) -> ScanJob | None:
        with self.SessionLocal() as session:
            row = session.get(ScanJobRecord, job_id)
            return self._job_from_record(row) if row else None

    @staticmethod
    def _job_from_record(row: ScanJobRecord) -> ScanJob:
        return ScanJob(
            id=row.id,
            workspace_id=row.workspace_id,
            asset_id=row.asset_id,
            kind=ScanKind(row.kind),
            status=ScanStatus(row.status),
            requested_at=as_utc(row.requested_at),
            started_at=as_utc(row.started_at),
            finished_at=as_utc(row.finished_at),
            findings_count=row.findings_count,
            error_message=row.error_message,
        )

    @staticmethod
    def _state_from_record(row: ScanQueueRecord) -> ScanQueueState:
        return ScanQueueState(
            job_id=row.job_id,
            attempts=row.attempts,
            max_attempts=row.max_attempts,
            lease_owner=row.lease_owner,
            lease_expires_at=as_utc(row.lease_expires_at),
            last_heartbeat_at=as_utc(row.last_heartbeat_at),
            next_attempt_at=as_utc(row.next_attempt_at),
            cancel_requested=row.cancel_requested,
        )
