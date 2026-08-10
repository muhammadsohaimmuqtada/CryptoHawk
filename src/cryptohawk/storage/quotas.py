from __future__ import annotations

import math
from datetime import UTC, datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.inventory import ScanStatus
from cryptohawk.domain.quotas import RateLimitDecision, ScanCapacity
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository, ScanJobRecord, WorkspaceRecord


class RateLimitBucketRecord(Base):
    __tablename__ = "rate_limit_buckets"

    scope_key: Mapped[str] = mapped_column(String(300), primary_key=True)
    action: Mapped[str] = mapped_column(String(100), primary_key=True)
    window_start: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class WorkspaceRuntimeRecord(Base):
    __tablename__ = "workspace_runtime"

    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        primary_key=True,
    )
    active_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class QuotaRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def consume(
        self,
        *,
        scope_key: str,
        action: str,
        limit: int,
        window_seconds: int,
        now: datetime | None = None,
    ) -> RateLimitDecision:
        if not scope_key or len(scope_key) > 300:
            raise ValueError("scope_key must contain 1-300 characters")
        if not action or len(action) > 100:
            raise ValueError("action must contain 1-100 characters")
        if limit < 1:
            raise ValueError("limit must be positive")
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")

        current = now or datetime.now(UTC)
        epoch = int(current.timestamp())
        window_start = epoch - (epoch % window_seconds)
        reset_epoch = window_start + window_seconds
        reset_at = datetime.fromtimestamp(reset_epoch, tz=UTC)
        retry_after = max(0, math.ceil((reset_at - current).total_seconds()))

        count = self._increment_or_create(
            scope_key=scope_key,
            action=action,
            window_start=window_start,
            limit=limit,
            now=current,
        )
        allowed = count <= limit
        return RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=max(0, limit - min(count, limit)),
            reset_at=reset_at,
            retry_after_seconds=0 if allowed else retry_after,
        )

    def prune_rate_limits(self, *, before: datetime) -> int:
        cutoff = int(before.timestamp())
        with self.SessionLocal() as session:
            result = session.execute(
                delete(RateLimitBucketRecord).where(
                    RateLimitBucketRecord.window_start < cutoff
                )
            )
            session.commit()
            return int(result.rowcount or 0)

    def acquire_scan_slot(
        self,
        *,
        workspace_id: str,
        limit: int,
        now: datetime | None = None,
    ) -> bool:
        if limit < 1:
            raise ValueError("scan concurrency limit must be positive")
        current = now or datetime.now(UTC)
        self._ensure_workspace_runtime(workspace_id, current)
        with self.SessionLocal() as session:
            result = session.execute(
                update(WorkspaceRuntimeRecord)
                .where(
                    WorkspaceRuntimeRecord.workspace_id == workspace_id,
                    WorkspaceRuntimeRecord.active_scans < limit,
                )
                .values(
                    active_scans=WorkspaceRuntimeRecord.active_scans + 1,
                    updated_at=current,
                )
            )
            session.commit()
            return result.rowcount == 1

    def release_scan_slot(
        self,
        *,
        workspace_id: str,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        self._ensure_workspace_runtime(workspace_id, current)
        with self.SessionLocal() as session:
            session.execute(
                update(WorkspaceRuntimeRecord)
                .where(
                    WorkspaceRuntimeRecord.workspace_id == workspace_id,
                    WorkspaceRuntimeRecord.active_scans > 0,
                )
                .values(
                    active_scans=WorkspaceRuntimeRecord.active_scans - 1,
                    updated_at=current,
                )
            )
            session.commit()

    def scan_capacity(self, *, workspace_id: str, limit: int) -> ScanCapacity:
        if limit < 1:
            raise ValueError("scan concurrency limit must be positive")
        self._ensure_workspace_runtime(workspace_id, datetime.now(UTC))
        with self.SessionLocal() as session:
            active = session.scalar(
                select(WorkspaceRuntimeRecord.active_scans).where(
                    WorkspaceRuntimeRecord.workspace_id == workspace_id
                )
            )
        active_scans = int(active or 0)
        return ScanCapacity(
            workspace_id=workspace_id,
            active_scans=active_scans,
            limit=limit,
            available=max(0, limit - active_scans),
        )

    def reconcile_scan_slots(self, *, now: datetime | None = None) -> int:
        current = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            workspace_ids = session.scalars(select(WorkspaceRecord.id)).all()
            active_rows = session.execute(
                select(ScanJobRecord.workspace_id, func.count())
                .where(ScanJobRecord.status == ScanStatus.RUNNING.value)
                .group_by(ScanJobRecord.workspace_id)
            ).all()
            active_by_workspace = {workspace_id: int(count) for workspace_id, count in active_rows}
            changed = 0
            for workspace_id in workspace_ids:
                row = session.get(WorkspaceRuntimeRecord, workspace_id)
                target = active_by_workspace.get(workspace_id, 0)
                if row is None:
                    session.add(
                        WorkspaceRuntimeRecord(
                            workspace_id=workspace_id,
                            active_scans=target,
                            updated_at=current,
                        )
                    )
                    changed += 1
                elif row.active_scans != target:
                    row.active_scans = target
                    row.updated_at = current
                    changed += 1
            session.commit()
            return changed

    def _increment_or_create(
        self,
        *,
        scope_key: str,
        action: str,
        window_start: int,
        limit: int,
        now: datetime,
    ) -> int:
        with self.SessionLocal() as session:
            result = session.execute(
                update(RateLimitBucketRecord)
                .where(
                    RateLimitBucketRecord.scope_key == scope_key,
                    RateLimitBucketRecord.action == action,
                    RateLimitBucketRecord.window_start == window_start,
                    RateLimitBucketRecord.count < limit,
                )
                .values(
                    count=RateLimitBucketRecord.count + 1,
                    updated_at=now,
                )
            )
            if result.rowcount == 1:
                session.commit()
                return self._bucket_count(scope_key, action, window_start)

            existing = session.scalar(
                select(RateLimitBucketRecord.count).where(
                    RateLimitBucketRecord.scope_key == scope_key,
                    RateLimitBucketRecord.action == action,
                    RateLimitBucketRecord.window_start == window_start,
                )
            )
            if existing is not None:
                session.rollback()
                return int(existing) + 1

            session.add(
                RateLimitBucketRecord(
                    scope_key=scope_key,
                    action=action,
                    window_start=window_start,
                    count=1,
                    updated_at=now,
                )
            )
            try:
                session.commit()
                return 1
            except IntegrityError:
                session.rollback()

        with self.SessionLocal() as session:
            result = session.execute(
                update(RateLimitBucketRecord)
                .where(
                    RateLimitBucketRecord.scope_key == scope_key,
                    RateLimitBucketRecord.action == action,
                    RateLimitBucketRecord.window_start == window_start,
                    RateLimitBucketRecord.count < limit,
                )
                .values(
                    count=RateLimitBucketRecord.count + 1,
                    updated_at=now,
                )
            )
            session.commit()
            if result.rowcount == 1:
                return self._bucket_count(scope_key, action, window_start)
            return limit + 1

    def _bucket_count(self, scope_key: str, action: str, window_start: int) -> int:
        with self.SessionLocal() as session:
            value = session.scalar(
                select(RateLimitBucketRecord.count).where(
                    RateLimitBucketRecord.scope_key == scope_key,
                    RateLimitBucketRecord.action == action,
                    RateLimitBucketRecord.window_start == window_start,
                )
            )
            return int(value or 0)

    def _ensure_workspace_runtime(self, workspace_id: str, now: datetime) -> None:
        with self.SessionLocal() as session:
            if session.get(WorkspaceRecord, workspace_id) is None:
                raise LookupError("workspace not found")
            if session.get(WorkspaceRuntimeRecord, workspace_id) is not None:
                return
            session.add(
                WorkspaceRuntimeRecord(
                    workspace_id=workspace_id,
                    active_scans=0,
                    updated_at=now,
                )
            )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
