from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanContext, ScanStatus
from cryptohawk.domain.repositories import (
    RepositoryAsset,
    RepositoryConfiguration,
    RepositoryProvider,
    RepositoryScanMode,
    RepositoryScanProvenance,
)
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import (
    InventoryRepository,
    ManagedAssetRecord,
    ScanJobRecord,
    WorkspaceRecord,
)
from cryptohawk.storage.time import as_utc


class RepositoryConfigurationRecord(Base):
    __tablename__ = "repository_configurations"

    asset_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("managed_assets.id", ondelete="CASCADE"), primary_key=True
    )
    workspace_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True
    )
    repository_url: Mapped[str] = mapped_column(String(1000), index=True)
    provider: Mapped[str] = mapped_column(String(30), index=True)
    ref: Mapped[str] = mapped_column(String(200))
    credential_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("connector_credentials.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class RepositoryScanRunRecord(Base):
    __tablename__ = "repository_scan_runs"

    scan_job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    repository_url: Mapped[str] = mapped_column(String(1000))
    ref: Mapped[str] = mapped_column(String(200))
    commit_sha: Mapped[str] = mapped_column(String(64), index=True)
    previous_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scan_mode: Mapped[str] = mapped_column(String(30), index=True)
    changed_paths: Mapped[int] = mapped_column(Integer)
    scanned_files: Mapped[int] = mapped_column(Integer)
    retained_observations: Mapped[int] = mapped_column(Integer)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class RepositoryAssetRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def create_repository_asset(
        self,
        *,
        workspace_id: str,
        name: str,
        repository_url: str,
        provider: RepositoryProvider,
        ref: str,
        credential_id: str | None,
        context: ScanContext,
        tags: dict[str, str] | None = None,
        now: datetime | None = None,
    ) -> RepositoryAsset:
        current = now or datetime.now(UTC)
        asset = ManagedAsset(
            workspace_id=workspace_id,
            name=name,
            kind=ManagedAssetKind.REPOSITORY,
            locator=repository_url,
            context=context,
            tags=tags or {},
            created_at=current,
            updated_at=current,
        )
        config = RepositoryConfiguration(
            asset_id=asset.id,
            workspace_id=workspace_id,
            repository_url=repository_url,
            provider=provider,
            ref=ref,
            credential_id=credential_id,
            created_at=current,
            updated_at=current,
        )
        with self.SessionLocal() as session:
            if session.get(WorkspaceRecord, workspace_id) is None:
                raise LookupError("workspace not found")
            existing = session.scalar(
                select(ManagedAssetRecord.id).where(
                    ManagedAssetRecord.workspace_id == workspace_id,
                    ManagedAssetRecord.kind == ManagedAssetKind.REPOSITORY.value,
                    ManagedAssetRecord.locator == repository_url,
                )
            )
            if existing is not None:
                raise ValueError("repository asset already exists in workspace")
            session.add(InventoryRepository._asset_record(asset))
            session.add(
                RepositoryConfigurationRecord(
                    asset_id=asset.id,
                    workspace_id=workspace_id,
                    repository_url=repository_url,
                    provider=provider.value,
                    ref=ref,
                    credential_id=credential_id,
                    created_at=current,
                    updated_at=current,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError("repository asset already exists in workspace") from exc
        return RepositoryAsset(asset=asset, repository=config)

    def get_configuration(
        self,
        *,
        workspace_id: str,
        asset_id: str,
    ) -> RepositoryConfiguration:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(RepositoryConfigurationRecord).where(
                    RepositoryConfigurationRecord.workspace_id == workspace_id,
                    RepositoryConfigurationRecord.asset_id == asset_id,
                )
            )
            if row is None:
                raise LookupError("repository configuration not found in workspace")
            return self._configuration(row)

    def get_repository_asset(
        self,
        *,
        workspace_id: str,
        asset_id: str,
    ) -> RepositoryAsset:
        asset = self.inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id)
        if asset is None or asset.kind != ManagedAssetKind.REPOSITORY:
            raise LookupError("repository asset not found in workspace")
        return RepositoryAsset(
            asset=asset,
            repository=self.get_configuration(
                workspace_id=workspace_id,
                asset_id=asset_id,
            ),
        )

    def list_repository_assets(self, *, workspace_id: str) -> list[RepositoryAsset]:
        assets = {
            asset.id: asset
            for asset in self.inventory.list_assets(workspace_id=workspace_id)
            if asset.kind == ManagedAssetKind.REPOSITORY
        }
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(RepositoryConfigurationRecord)
                .where(RepositoryConfigurationRecord.workspace_id == workspace_id)
                .order_by(RepositoryConfigurationRecord.repository_url)
            ).all()
            return [
                RepositoryAsset(asset=assets[row.asset_id], repository=self._configuration(row))
                for row in rows
                if row.asset_id in assets
            ]

    def record_scan_provenance(
        self,
        provenance: RepositoryScanProvenance,
    ) -> RepositoryScanProvenance:
        with self.SessionLocal() as session:
            existing = session.get(RepositoryScanRunRecord, provenance.scan_job_id)
            if existing is not None:
                stored = self._provenance(existing)
                if stored != provenance:
                    raise RuntimeError("repository scan provenance changed for existing scan job")
                return stored
            session.add(
                RepositoryScanRunRecord(
                    scan_job_id=provenance.scan_job_id,
                    workspace_id=provenance.workspace_id,
                    asset_id=provenance.asset_id,
                    repository_url=provenance.repository_url,
                    ref=provenance.ref,
                    commit_sha=provenance.commit_sha,
                    previous_commit_sha=provenance.previous_commit_sha,
                    scan_mode=provenance.scan_mode.value,
                    changed_paths=provenance.changed_paths,
                    scanned_files=provenance.scanned_files,
                    retained_observations=provenance.retained_observations,
                    collected_at=provenance.collected_at,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                existing = session.get(RepositoryScanRunRecord, provenance.scan_job_id)
                if existing is None:
                    raise
                stored = self._provenance(existing)
                if stored != provenance:
                    raise RuntimeError(
                        "repository scan provenance changed for existing scan job"
                    ) from exc
                return stored
        return provenance

    def last_successful_scan(
        self,
        *,
        workspace_id: str,
        asset_id: str,
    ) -> RepositoryScanProvenance | None:
        with self.SessionLocal() as session:
            row = session.scalar(
                select(RepositoryScanRunRecord)
                .join(ScanJobRecord, ScanJobRecord.id == RepositoryScanRunRecord.scan_job_id)
                .where(
                    RepositoryScanRunRecord.workspace_id == workspace_id,
                    RepositoryScanRunRecord.asset_id == asset_id,
                    ScanJobRecord.status == ScanStatus.SUCCEEDED.value,
                )
                .order_by(ScanJobRecord.finished_at.desc(), RepositoryScanRunRecord.scan_job_id)
                .limit(1)
            )
            return self._provenance(row) if row else None

    def list_scan_provenance(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        limit: int = 100,
    ) -> list[RepositoryScanProvenance]:
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(RepositoryScanRunRecord)
                .where(
                    RepositoryScanRunRecord.workspace_id == workspace_id,
                    RepositoryScanRunRecord.asset_id == asset_id,
                )
                .order_by(RepositoryScanRunRecord.collected_at.desc())
                .limit(limit)
            ).all()
            return [self._provenance(row) for row in rows]

    @staticmethod
    def _configuration(row: RepositoryConfigurationRecord) -> RepositoryConfiguration:
        return RepositoryConfiguration(
            asset_id=row.asset_id,
            workspace_id=row.workspace_id,
            repository_url=row.repository_url,
            provider=RepositoryProvider(row.provider),
            ref=row.ref,
            credential_id=row.credential_id,
            created_at=as_utc(row.created_at),
            updated_at=as_utc(row.updated_at),
        )

    @staticmethod
    def _provenance(row: RepositoryScanRunRecord) -> RepositoryScanProvenance:
        return RepositoryScanProvenance(
            scan_job_id=row.scan_job_id,
            workspace_id=row.workspace_id,
            asset_id=row.asset_id,
            repository_url=row.repository_url,
            ref=row.ref,
            commit_sha=row.commit_sha,
            previous_commit_sha=row.previous_commit_sha,
            scan_mode=RepositoryScanMode(row.scan_mode),
            changed_paths=row.changed_paths,
            scanned_files=row.scanned_files,
            retained_observations=row.retained_observations,
            collected_at=as_utc(row.collected_at),
        )
