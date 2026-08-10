from __future__ import annotations

from pydantic import BaseModel, Field

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
