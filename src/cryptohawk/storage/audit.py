from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import DateTime, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.audit import AuditEvent, AuditOutcome
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.time import as_utc


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    actor_kind: Mapped[str] = mapped_column(String(40), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(200), index=True)
    resource_type: Mapped[str] = mapped_column(String(100), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), index=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AuditRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def append(self, event: AuditEvent) -> AuditEvent:
        with self.SessionLocal() as session:
            session.add(
                AuditEventRecord(
                    id=event.id,
                    workspace_id=event.workspace_id,
                    request_id=event.request_id,
                    actor_kind=event.actor_kind,
                    actor_id=event.actor_id,
                    user_id=event.user_id,
                    action=event.action,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    outcome=event.outcome.value,
                    metadata_json=json.dumps(event.metadata, sort_keys=True),
                    created_at=event.created_at,
                )
            )
            session.commit()
        return event

    def list_workspace(self, workspace_id: str, *, limit: int = 200) -> list[AuditEvent]:
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(AuditEventRecord)
                .where(AuditEventRecord.workspace_id == workspace_id)
                .order_by(AuditEventRecord.created_at.desc())
                .limit(limit)
            ).all()
            return [self._from_record(row) for row in rows]

    @staticmethod
    def _from_record(row: AuditEventRecord) -> AuditEvent:
        return AuditEvent(
            id=row.id,
            workspace_id=row.workspace_id,
            request_id=row.request_id,
            actor_kind=row.actor_kind,
            actor_id=row.actor_id,
            user_id=row.user_id,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            outcome=AuditOutcome(row.outcome),
            metadata=json.loads(row.metadata_json),
            created_at=as_utc(row.created_at),
        )
