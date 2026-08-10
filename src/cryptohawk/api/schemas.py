from __future__ import annotations

from pydantic import BaseModel, Field

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


class WorkspaceCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str | None = Field(
        default=None,
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )


class AssetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: ManagedAssetKind
    locator: str = Field(min_length=1, max_length=1000)
    context: ScanContext = Field(default_factory=ScanContext)
    tags: dict[str, str] = Field(default_factory=dict)


class ManagedScanRequest(BaseModel):
    source: str | None = Field(default=None, max_length=1_000_000)
    filename: str | None = Field(default=None, max_length=1000)
    timeout: float = Field(default=5.0, ge=0.5, le=20.0)


class QueuedScanRequest(BaseModel):
    max_attempts: int = Field(default=3, ge=1, le=20)


class ScanExecutionResponse(BaseModel):
    job: ScanJob
    findings: list[Finding]
