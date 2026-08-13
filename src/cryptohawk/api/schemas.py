from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from cryptohawk.domain.auth import User, WorkspaceMembership, WorkspaceRole
from cryptohawk.domain.credentials import ConnectorCredentialKind
from cryptohawk.domain.inventory import ManagedAssetKind, ScanJob
from cryptohawk.domain.models import Finding, ScanContext


class SourceScanRequest(BaseModel):
    source: str = Field(min_length=1, max_length=1_000_000)
    filename: str = "inline.txt"
    context: ScanContext = Field(default_factory=ScanContext)
    persist: bool = True


class TLSScanRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    port: int = Field(default=443, ge=1, le=65535)
    timeout: float = Field(default=5.0, ge=0.5, le=20.0)
    context: ScanContext = Field(default_factory=lambda: ScanContext(internet_exposed=True))
    persist: bool = True


class ScanResponse(BaseModel):
    findings: list[Finding]
    persisted: int


class BootstrapRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=1024)
    workspace_name: str = Field(min_length=1, max_length=200)
    workspace_slug: str | None = Field(
        default=None,
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class WorkspaceCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str | None = Field(
        default=None,
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )


class MemberCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=200)
    role: WorkspaceRole = WorkspaceRole.ANALYST
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class WorkspaceMemberResponse(BaseModel):
    user: User
    membership: WorkspaceMembership


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    role: WorkspaceRole = WorkspaceRole.ANALYST
    expires_days: int | None = Field(default=None, ge=1, le=3650)


class ConnectorCredentialCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: ConnectorCredentialKind
    secret: dict[str, str] = Field(min_length=1, max_length=16)


class ConnectorCredentialReplaceRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    secret: dict[str, str] = Field(min_length=1, max_length=16)


class AssetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: ManagedAssetKind
    locator: str = Field(min_length=1, max_length=1000)
    context: ScanContext = Field(default_factory=ScanContext)
    tags: dict[str, str] = Field(default_factory=dict)


class RepositoryAssetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    repository_url: str = Field(min_length=10, max_length=1000)
    ref: str = Field(default="HEAD", min_length=1, max_length=200)
    credential_id: str | None = Field(default=None, min_length=1, max_length=64)
    context: ScanContext = Field(default_factory=ScanContext)
    tags: dict[str, str] = Field(default_factory=dict)


class ManagedScanRequest(BaseModel):
    source: str | None = Field(default=None, max_length=1_000_000)
    filename: str | None = Field(default=None, max_length=1000)
    timeout: float = Field(default=5.0, ge=0.5, le=20.0)


class QueuedScanRequest(BaseModel):
    max_attempts: int = Field(default=3, ge=1, le=20)


class ScanScheduleCreateRequest(BaseModel):
    interval_minutes: int = Field(default=60, ge=1, le=43_200)
    max_attempts: int = Field(default=3, ge=1, le=20)
    start_at: datetime | None = None


class ScanExecutionResponse(BaseModel):
    job: ScanJob
    findings: list[Finding]
