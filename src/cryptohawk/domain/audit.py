from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from cryptohawk.domain.inventory import utcnow


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str | None = None
    request_id: str = Field(min_length=1, max_length=64)
    actor_kind: str = Field(min_length=1, max_length=40)
    actor_id: str | None = Field(default=None, max_length=200)
    user_id: str | None = Field(default=None, max_length=64)
    action: str = Field(min_length=1, max_length=200)
    resource_type: str = Field(min_length=1, max_length=100)
    resource_id: str | None = Field(default=None, max_length=1000)
    outcome: AuditOutcome
    metadata: dict[str, str | int | bool | None] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
