from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from cryptohawk.domain.models import ScanContext


def utcnow() -> datetime:
    return datetime.now(UTC)


class ManagedAssetKind(StrEnum):
    SOURCE = "source"
    REPOSITORY = "repository"
    TLS_ENDPOINT = "tls-endpoint"
    CERTIFICATE_ENDPOINT = "certificate-endpoint"
    SSH_ENDPOINT = "ssh-endpoint"
    HOST = "host"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    CLOUD_RESOURCE = "cloud-resource"


class ScanKind(StrEnum):
    SOURCE = "source"
    REPOSITORY = "repository"
    TLS = "tls"
    CERTIFICATE = "certificate"
    SSH = "ssh"
    CONTAINER = "container"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


class Workspace(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    created_at: datetime = Field(default_factory=utcnow)


class ManagedAsset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str
    name: str = Field(min_length=1, max_length=200)
    kind: ManagedAssetKind
    locator: str = Field(min_length=1, max_length=1000)
    context: ScanContext = Field(default_factory=ScanContext)
    tags: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str
    asset_id: str
    kind: ScanKind
    status: ScanStatus = ScanStatus.QUEUED
    requested_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings_count: int = Field(default=0, ge=0)
    error_message: str | None = None
