from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ScanOrigin(StrEnum):
    API = "api"
    SCHEDULE = "schedule"


class DriftEventType(StrEnum):
    INTRODUCED = "introduced"
    CHANGED = "changed"
    RESOLVED = "resolved"
    RISK_INCREASED = "risk-increased"
    RISK_DECREASED = "risk-decreased"


class ScanSchedule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str
    asset_id: str
    interval_seconds: int = Field(ge=60, le=2_592_000)
    max_attempts: int = Field(default=3, ge=1, le=20)
    enabled: bool = True
    next_run_at: datetime
    last_run_at: datetime | None = None
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanSnapshot(BaseModel):
    job_id: str
    workspace_id: str
    asset_id: str
    origin: ScanOrigin
    schedule_id: str | None = None
    scheduled_for: datetime | None = None
    completed_at: datetime
    finding_count: int = Field(ge=0)
    scanner_version: str
    policy_version: str
    fingerprint_set_hash: str


class ObservationState(BaseModel):
    workspace_id: str
    asset_id: str
    fingerprint: str
    active: bool
    first_seen: datetime
    last_seen: datetime
    first_job_id: str
    last_job_id: str
    occurrence_count: int = Field(ge=1)
    risk_score: int = Field(ge=0, le=100)
    severity: str
    quantum_status: str
    evidence_hash: str


class DriftEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str
    asset_id: str
    scan_job_id: str
    fingerprint: str
    event_type: DriftEventType
    previous_risk_score: int | None = Field(default=None, ge=0, le=100)
    new_risk_score: int | None = Field(default=None, ge=0, le=100)
    previous_severity: str | None = None
    new_severity: str | None = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, str | int | bool | None] = Field(default_factory=dict)
