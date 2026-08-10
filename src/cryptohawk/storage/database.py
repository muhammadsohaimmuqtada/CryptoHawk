from __future__ import annotations

import json
from collections.abc import Iterable

from sqlalchemy import DateTime, Integer, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from cryptohawk.domain.models import DashboardSummary, Finding, Severity


class Base(DeclarativeBase):
    pass


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

    def upsert_many(self, findings: Iterable[Finding]) -> int:
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
                count += 1
            session.commit()
        return count

    def list_findings(self, *, limit: int = 200) -> list[Finding]:
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(FindingRecord).order_by(FindingRecord.risk_score.desc()).limit(limit)
            ).all()
            return [Finding.model_validate(json.loads(row.payload)) for row in rows]

    def clear(self) -> None:
        with self.SessionLocal() as session:
            session.query(FindingRecord).delete()
            session.commit()

    def summary(self) -> DashboardSummary:
        with self.SessionLocal() as session:
            total = session.scalar(select(func.count()).select_from(FindingRecord)) or 0
            severity_counts = dict(
                session.execute(
                    select(FindingRecord.severity, func.count()).group_by(FindingRecord.severity)
                ).all()
            )
            quantum_vulnerable = session.scalar(
                select(func.count())
                .select_from(FindingRecord)
                .where(FindingRecord.quantum_status == "vulnerable")
            ) or 0
            pqc_ready = session.scalar(
                select(func.count())
                .select_from(FindingRecord)
                .where(FindingRecord.quantum_status == "safe")
            ) or 0
            return DashboardSummary(
                total_findings=total,
                critical=severity_counts.get(Severity.CRITICAL.value, 0),
                high=severity_counts.get(Severity.HIGH.value, 0),
                medium=severity_counts.get(Severity.MEDIUM.value, 0),
                low=severity_counts.get(Severity.LOW.value, 0),
                quantum_vulnerable=quantum_vulnerable,
                pqc_ready=pqc_ready,
            )
