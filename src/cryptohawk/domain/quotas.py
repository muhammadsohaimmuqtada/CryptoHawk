from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RateLimitDecision(BaseModel):
    allowed: bool
    limit: int = Field(ge=1)
    remaining: int = Field(ge=0)
    reset_at: datetime
    retry_after_seconds: int = Field(ge=0)


class ScanCapacity(BaseModel):
    workspace_id: str
    active_scans: int = Field(ge=0)
    limit: int = Field(ge=1)
    available: int = Field(ge=0)
