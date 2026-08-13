from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from cryptohawk.domain.inventory import ScanJob


class ScanJobDiagnostics(BaseModel):
    job: ScanJob
    queue_managed: bool
    phase: str
    attempts: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=20)
    attempts_remaining: int = Field(ge=0)
    next_attempt_at: datetime | None = None
    lease_expires_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    cancel_requested: bool = False
    can_cancel: bool = False
    can_rerun: bool = False
