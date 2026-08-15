from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from cryptohawk.domain.models import Finding


class RemediationStatus(StrEnum):
    OPEN = "open"
    PLANNED = "planned"
    IN_PROGRESS = "in-progress"
    BLOCKED = "blocked"
    READY_FOR_VERIFICATION = "ready-for-verification"
    VERIFIED = "verified"
    ACCEPTED_RISK = "accepted-risk"


class RemediationPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MigrationItem(BaseModel):
    id: str
    workspace_id: str
    asset_id: str
    observation_fingerprint: str = Field(min_length=64, max_length=64)
    source_finding_id: str
    source_scan_job_id: str
    title: str
    owner: str | None = None
    status: RemediationStatus
    priority: RemediationPriority
    target_algorithm: str | None = None
    due_date: date | None = None
    notes: str | None = None
    acceptance_reason: str | None = None
    verification_job_id: str | None = None
    verified_at: datetime | None = None
    verification_evidence: dict[str, object] = Field(default_factory=dict)
    source_finding: Finding
    created_by: str
    created_at: datetime
    updated_at: datetime


class RemediationVerification(BaseModel):
    item: MigrationItem
    verified: bool
    outcome: str
