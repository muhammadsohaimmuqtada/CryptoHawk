from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column, sessionmaker

from cryptohawk.domain.inventory import (
    ManagedAsset,
    ManagedAssetKind,
    ScanJob,
    ScanKind,
    ScanStatus,
    Workspace,
)
from cryptohawk.domain.models import ScanContext
from cryptohawk.storage.database import Base
from cryptohawk.storage.time import as_utc


class WorkspaceRecord(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ManagedAssetRecord(Base):
    __tablename__ = "managed_assets"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "kind",
            "locator",
            name="uq_managed_asset_workspace_kind_locator",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(40), index=True)
    locator: Mapped[str] = mapped_column(String(1000))
    internet_exposed: Mapped[bool] = mapped_column(Boolean)
    asset_criticality: Mapped[int] = mapped_column(Integer)
    data_lifetime_years: Mapped[int] = mapped_column(Integer)
    environment: Mapped[str] = mapped_column(String(80))
    tags_json: Mapped[str] = mapped_column(Text, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ScanJobRecord(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


_ALLOWED_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.QUEUED: frozenset({ScanStatus.RUNNING, ScanStatus.CANCELED}),
    ScanStatus.RUNNING: frozenset(
        {ScanStatus.SUCCEEDED, ScanStatus.FAILED, ScanStatus.CANCELED}
    ),
    ScanStatus.SUCCEEDED: frozenset(),
    ScanStatus.FAILED: frozenset(),
    ScanStatus.CANCELED: frozenset(),
}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if len(slug) < 2:
        slug = f"ws-{slug or 'workspace'}"
    return slug[:80]


class InventoryRepository:
    def __init__(self, database_url: str = "sqlite:///./cryptohawk.db") -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(
            database_url,
            future=True,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        self.SessionLocal = sessionmaker(self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def create_workspace(self, *, name: str, slug: str | None = None) -> Workspace:
        workspace = Workspace(name=name, slug=slug or _slugify(name))
        with self.SessionLocal() as session:
            existing = session.scalar(
                select(WorkspaceRecord).where(WorkspaceRecord.slug == workspace.slug)
            )
            if existing:
                raise ValueError(f"workspace slug already exists: {workspace.slug}")
            session.add(
                WorkspaceRecord(
                    id=workspace.id,
                    name=workspace.name,
                    slug=workspace.slug,
                    created_at=workspace.created_at,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError(f"workspace slug already exists: {workspace.slug}") from exc
        return workspace

    def list_workspaces(self) -> list[Workspace]:
        with self.SessionLocal() as session:
            rows = session.scalars(select(WorkspaceRecord).order_by(WorkspaceRecord.name)).all()
            return [self._workspace_from_record(row) for row in rows]

    def get_workspace(self, workspace_id: str) -> Workspace | None:
        with self.SessionLocal() as session:
            row = session.get(WorkspaceRecord, workspace_id)
            return self._workspace_from_record(row) if row else None

    def create_asset(
        self,
        *,
        workspace_id: str,
        name: str,
        kind: ManagedAssetKind,
        locator: str,
        context: ScanContext,
        tags: dict[str, str] | None = None,
    ) -> ManagedAsset:
        if self.get_workspace(workspace_id) is None:
            raise LookupError("workspace not found")
        existing = self.find_asset(workspace_id=workspace_id, kind=kind, locator=locator)
        if existing is not None:
            raise ValueError("asset already exists in workspace")

        asset = ManagedAsset(
            workspace_id=workspace_id,
            name=name,
            kind=kind,
            locator=locator,
            context=context,
            tags=tags or {},
        )
        with self.SessionLocal() as session:
            session.add(self._asset_record(asset))
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError("asset already exists in workspace") from exc
        return asset

    def find_asset(
        self,
        *,
        workspace_id: str,
        kind: ManagedAssetKind,
        locator: str,
    ) -> ManagedAsset | None:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(ManagedAssetRecord).where(
                    ManagedAssetRecord.workspace_id == workspace_id,
                    ManagedAssetRecord.kind == kind.value,
                    ManagedAssetRecord.locator == locator,
                )
            )
            return self._asset_from_record(row) if row else None

    def get_asset(self, *, workspace_id: str, asset_id: str) -> ManagedAsset | None:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(ManagedAssetRecord).where(
                    ManagedAssetRecord.workspace_id == workspace_id,
                    ManagedAssetRecord.id == asset_id,
                )
            )
            return self._asset_from_record(row) if row else None

    def list_assets(self, *, workspace_id: str) -> list[ManagedAsset]:
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(ManagedAssetRecord)
                .where(ManagedAssetRecord.workspace_id == workspace_id)
                .order_by(ManagedAssetRecord.name)
            ).all()
            return [self._asset_from_record(row) for row in rows]

    def create_scan_job(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        kind: ScanKind,
        job_id: str | None = None,
    ) -> ScanJob:
        if self.get_asset(workspace_id=workspace_id, asset_id=asset_id) is None:
            raise LookupError("asset not found in workspace")
        job = ScanJob(workspace_id=workspace_id, asset_id=asset_id, kind=kind)
        if job_id is not None:
            job = job.model_copy(update={"id": job_id})
        with self.SessionLocal() as session:
            existing = session.get(ScanJobRecord, job.id)
            if existing is not None:
                loaded = self._job_from_record(existing)
                if (
                    loaded.workspace_id != workspace_id
                    or loaded.asset_id != asset_id
                    or loaded.kind != kind
                ):
                    raise ValueError("scan job id is already bound to different work")
                return loaded
            session.add(self._job_record(job))
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                existing = session.get(ScanJobRecord, job.id)
                if existing is None:
                    raise
                loaded = self._job_from_record(existing)
                if (
                    loaded.workspace_id != workspace_id
                    or loaded.asset_id != asset_id
                    or loaded.kind != kind
                ):
                    raise ValueError(
                        "scan job id is already bound to different work"
                    ) from exc
                return loaded
        return job

    def transition_scan_job(
        self,
        *,
        workspace_id: str,
        job_id: str,
        expected: ScanStatus,
        target: ScanStatus,
        findings_count: int | None = None,
        error_message: str | None = None,
    ) -> ScanJob:
        if target not in _ALLOWED_TRANSITIONS[expected]:
            raise ValueError(f"invalid scan transition: {expected.value} -> {target.value}")

        now = datetime.now(UTC)
        values: dict[str, object] = {"status": target.value}
        if target == ScanStatus.RUNNING:
            values["started_at"] = now
        if target in {ScanStatus.SUCCEEDED, ScanStatus.FAILED, ScanStatus.CANCELED}:
            values["finished_at"] = now
        if findings_count is not None:
            values["findings_count"] = findings_count
        if error_message is not None:
            values["error_message"] = error_message[:4000]

        with self.SessionLocal() as session:
            result = session.execute(
                update(ScanJobRecord)
                .where(
                    ScanJobRecord.id == job_id,
                    ScanJobRecord.workspace_id == workspace_id,
                    ScanJobRecord.status == expected.value,
                )
                .values(**values)
            )
            if result.rowcount != 1:
                session.rollback()
                raise RuntimeError("scan job state changed or job is outside workspace")
            session.commit()
        job = self.get_scan_job(workspace_id=workspace_id, job_id=job_id)
        if job is None:
            raise RuntimeError("scan job disappeared after transition")
        return job

    def get_scan_job(self, *, workspace_id: str, job_id: str) -> ScanJob | None:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(ScanJobRecord).where(
                    ScanJobRecord.workspace_id == workspace_id,
                    ScanJobRecord.id == job_id,
                )
            )
            return self._job_from_record(row) if row else None

    def list_scan_jobs(self, *, workspace_id: str, limit: int = 100) -> list[ScanJob]:
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(ScanJobRecord)
                .where(ScanJobRecord.workspace_id == workspace_id)
                .order_by(ScanJobRecord.requested_at.desc())
                .limit(limit)
            ).all()
            return [self._job_from_record(row) for row in rows]

    @staticmethod
    def _workspace_from_record(row: WorkspaceRecord) -> Workspace:
        return Workspace(
            id=row.id,
            name=row.name,
            slug=row.slug,
            created_at=as_utc(row.created_at),
        )

    @staticmethod
    def _asset_record(asset: ManagedAsset) -> ManagedAssetRecord:
        return ManagedAssetRecord(
            id=asset.id,
            workspace_id=asset.workspace_id,
            name=asset.name,
            kind=asset.kind.value,
            locator=asset.locator,
            internet_exposed=asset.context.internet_exposed,
            asset_criticality=asset.context.asset_criticality,
            data_lifetime_years=asset.context.data_lifetime_years,
            environment=asset.context.environment,
            tags_json=json.dumps(asset.tags, sort_keys=True),
            enabled=asset.enabled,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
        )

    @staticmethod
    def _asset_from_record(row: ManagedAssetRecord) -> ManagedAsset:
        return ManagedAsset(
            id=row.id,
            workspace_id=row.workspace_id,
            name=row.name,
            kind=ManagedAssetKind(row.kind),
            locator=row.locator,
            context=ScanContext(
                internet_exposed=row.internet_exposed,
                asset_criticality=row.asset_criticality,
                data_lifetime_years=row.data_lifetime_years,
                environment=row.environment,
            ),
            tags=json.loads(row.tags_json),
            enabled=row.enabled,
            created_at=as_utc(row.created_at),
            updated_at=as_utc(row.updated_at),
        )

    @staticmethod
    def _job_record(job: ScanJob) -> ScanJobRecord:
        return ScanJobRecord(
            id=job.id,
            workspace_id=job.workspace_id,
            asset_id=job.asset_id,
            kind=job.kind.value,
            status=job.status.value,
            requested_at=job.requested_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            findings_count=job.findings_count,
            error_message=job.error_message,
        )

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
