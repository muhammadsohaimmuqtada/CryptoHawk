from datetime import datetime

from pydantic import BaseModel, Field


class ReportPolicyRef(BaseModel):
    name: str
    version: int = Field(ge=1)
    rules_hash: str
    provenance_ref: str


class ReportMetadata(BaseModel):
    generated_at: datetime
    workspace_id: str
    workspace_name: str
    workspace_slug: str
    policy: ReportPolicyRef


class ExecutivePriority(BaseModel):
    asset_id: str
    asset_name: str
    asset_kind: str
    algorithm: str
    family: str
    risk_score: int = Field(ge=0, le=100)
    severity: str
    quantum_status: str
    policy_status: str | None = None
    migration_target: str | None = None
    remediation_status: str | None = None
    remediation_owner: str | None = None
    due_date: str | None = None


class ExecutiveSummary(BaseModel):
    assets_total: int = Field(ge=0)
    assets_enabled: int = Field(ge=0)
    active_findings: int = Field(ge=0)
    severity: dict[str, int]
    quantum: dict[str, int]
    policy: dict[str, int]
    remediation: dict[str, int]
    overdue_remediation: int = Field(ge=0)
    unowned_remediation: int = Field(ge=0)
    drift_30d: dict[str, int]


class ExecutiveReport(BaseModel):
    metadata: ReportMetadata
    summary: ExecutiveSummary
    top_priorities: list[ExecutivePriority]


class EngineeringFinding(BaseModel):
    fingerprint: str
    asset_id: str
    asset_name: str
    asset_kind: str
    locator: str
    environment: str
    internet_exposed: bool
    asset_criticality: int = Field(ge=1, le=10)
    data_lifetime_years: int = Field(ge=0, le=50)
    algorithm: str
    family: str
    primitive: str
    crypto_asset_type: str
    parameter_set: str | None = None
    key_size: int | None = None
    protocol_version: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    severity: str
    quantum_status: str
    risk_reasons: list[str]
    migration_target: str | None = None
    migration_strategy: str | None = None
    policy_name: str | None = None
    policy_version: int | None = None
    policy_status: str | None = None
    policy_controls: list[str]
    policy_reasons: list[str]
    policy_rules_hash: str | None = None
    evidence_source: str
    evidence_locator: str | None = None
    evidence_hash: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = Field(ge=1)
    remediation_id: str | None = None
    remediation_status: str | None = None
    remediation_priority: str | None = None
    remediation_owner: str | None = None
    remediation_due_date: str | None = None
    remediation_target: str | None = None


class EngineeringReport(BaseModel):
    metadata: ReportMetadata
    findings: list[EngineeringFinding]
