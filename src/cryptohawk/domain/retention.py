from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class WorkspaceRetentionPolicy(BaseModel):
    workspace_id: str
    enabled: bool = False
    evidence_retention_days: int = Field(default=180, ge=7, le=3650)
    audit_retention_days: int = Field(default=365, ge=7, le=3650)
    sweep_interval_hours: int = Field(default=24, ge=1, le=168)
    last_run_at: datetime | None = None
    updated_by: str | None = None
    updated_at: datetime | None = None


class RetentionSweepResult(BaseModel):
    workspace_id: str
    evidence_cutoff: datetime
    audit_cutoff: datetime
    deleted_rows: dict[str, int] = Field(default_factory=dict)
    protected_evidence_jobs: int = 0
    ran_at: datetime


__all__ = ["RetentionSweepResult", "WorkspaceRetentionPolicy"]
