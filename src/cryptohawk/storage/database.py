from __future__ import annotations

import json
from collections.abc import Iterable

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Text,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from cryptohawk.config import settings
from cryptohawk.domain.models import DashboardSummary, Finding, Severity


class ManagedMetaData(MetaData):
    def create_all(self, bind, tables=None, checkfirst: bool = True) -> None:
        if not settings.auto_create_schema:
            return
        super().create_all(bind, tables=tables, checkfirst=checkfirst)


class Base(DeclarativeBase):
    metadata = ManagedMetaData()


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(255), index=True)
    asset_name: Mapped[str] = mapped_column(String(500))
    family: Mapped[str] = mapped_column(String(100), index=True)
    algorithm: Mapped[str] = mapped_column(String(255))
    primitive: Mapped[str] = mapped_column(String(50))
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    quantum_status: Mapped[str] = mapped_column(String(30), index=True)
    migration_target: Mapped[str | None] = mapped_column(String(100), nullable=True)
    payload: Mapped[str] = mapped_column(Text)
    discovered_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)


class FindingScopeRecord(Base):
    __tablename__ = "finding_scopes"

    finding_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )
    workspace_id: Mapped[str] = mapped_column(String(64), index=True)
    managed_asset_id: Mapped[str] = mapped_column(String(64), index=True)
    scan_job_id: Mapped[str] = mapped_column(String(64), index=True)


class FindingRepository:
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

    def upsert_many(
        self,
        findings: Iterable[Finding],
        *,
        workspace_id: str | None = None,
        managed_asset_id: str | None = None,
        scan_job_id: str | None = None,
    ) -> int:
        scope_values = (workspace_id, managed_asset_id, scan_job_id)
        scoped = any(value is not None for value in scope_values)
        if scoped and not all(value is not None for value in scope_values):
            raise ValueError(
                "workspace_id, managed_asset_id, and scan_job_id are required together"
            )

        count = 0
        with self.SessionLocal() as session:
            for finding in findings:
                obs, risk = finding.observation, finding.risk
                record = FindingRecord(
                    id=obs.id,
                    asset_id=obs.asset_id,
                    asset_name=obs.asset_name,
                    family=obs.family,
                    algorithm=obs.algorithm,
                    primitive=obs.primitive.value,
                    key_size=obs.key_size,
                    risk_score=risk.score,
                    severity=risk.severity.value,
                    quantum_status=risk.quantum_status.value,
                    migration_target=risk.migration_target,
                    payload=finding.model_dump_json(),
                    discovered_at=obs.discovered_at,
                )
                session.merge(record)
                if scoped:
                    session.merge(
                        FindingScopeRecord(
                            finding_id=obs.id,
                            workspace_id=workspace_id,
                            managed_asset_id=managed_asset_id,
                            scan_job_id=scan_job_id,
                        )
                    )
                count += 1
            session.commit()
        return count

    def list_findings(
        self,
        *,
        limit: int = 200,
        workspace_id: str | None = None,
    ) -> list[Finding]:
        with self.SessionLocal() as session:
            statement = select(FindingRecord)
            if workspace_id is not None:
                statement = statement.join(
                    FindingScopeRecord,
                    FindingScopeRecord.finding_id == FindingRecord.id,
                ).where(FindingScopeRecord.workspace_id == workspace_id)
            rows = session.scalars(
                statement.order_by(FindingRecord.risk_score.desc()).limit(limit)
            ).all()
            return [Finding.model_validate(json.loads(row.payload)) for row in rows]

    def clear(self) -> None:
        with self.SessionLocal() as session:
            session.query(FindingScopeRecord).delete()
            session.query(FindingRecord).delete()
            session.commit()

    def summary(self, *, workspace_id: str | None = None) -> DashboardSummary:
        with self.SessionLocal() as session:
            if workspace_id is None:
                count_from = FindingRecord
                severity_statement = select(FindingRecord.severity, func.count()).group_by(
                    FindingRecord.severity
                )
                quantum_statement = select(FindingRecord.quantum_status, func.count()).group_by(
                    FindingRecord.quantum_status
                )
                total = session.scalar(select(func.count()).select_from(count_from)) or 0
            else:
                scoped_ids = (
                    select(FindingScopeRecord.finding_id)
                    .where(FindingScopeRecord.workspace_id == workspace_id)
                    .subquery()
                )
                filter_clause = FindingRecord.id.in_(select(scoped_ids.c.finding_id))
                total = session.scalar(
                    select(func.count()).select_from(FindingRecord).where(filter_clause)
                ) or 0
                severity_statement = (
                    select(FindingRecord.severity, func.count())
                    .where(filter_clause)
                    .group_by(FindingRecord.severity)
                )
                quantum_statement = (
                    select(FindingRecord.quantum_status, func.count())
                    .where(filter_clause)
                    .group_by(FindingRecord.quantum_status)
                )

            severity_counts = dict(session.execute(severity_statement).all())
            quantum_counts = dict(session.execute(quantum_statement).all())
            return DashboardSummary(
                total_findings=total,
                critical=severity_counts.get(Severity.CRITICAL.value, 0),
                high=severity_counts.get(Severity.HIGH.value, 0),
                medium=severity_counts.get(Severity.MEDIUM.value, 0),
                low=severity_counts.get(Severity.LOW.value, 0),
                quantum_vulnerable=quantum_counts.get("vulnerable", 0),
                pqc_ready=quantum_counts.get("safe", 0),
            )
