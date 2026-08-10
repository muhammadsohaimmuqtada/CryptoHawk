from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from cryptohawk.domain.inventory import ScanJob


class ScanLease(BaseModel):
    job: ScanJob
    worker_id: str = Field(min_length=1, max_length=200)
    attempt: int = Field(ge=1)
    max_attempts: int = Field(ge=1, le=20)
    lease_expires_at: datetime


class ScanQueueState(BaseModel):
    job_id: str
    attempts: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=20)
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    next_attempt_at: datetime
    cancel_requested: bool = False
