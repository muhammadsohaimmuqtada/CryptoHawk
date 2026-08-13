from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AssetType(StrEnum):
    SOURCE = "source"
    REPOSITORY = "repository"
    TLS_ENDPOINT = "tls-endpoint"
    CERTIFICATE = "certificate"
    CONTAINER = "container"
    HOST = "host"


class CryptoAssetType(StrEnum):
    ALGORITHM = "algorithm"
    PROTOCOL = "protocol"
    CERTIFICATE = "certificate"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class Primitive(StrEnum):
    SIGNATURE = "signature"
    HASH = "hash"
    PKE = "pke"
    KEY_AGREE = "key-agree"
    KEM = "kem"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    AE = "ae"
    KDF = "kdf"
    MAC = "mac"
    OTHER = "other"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class QuantumStatus(StrEnum):
    SAFE = "safe"
    TRANSITION = "transition"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    source: str
    locator: str | None = None
    line: int | None = None
    snippet: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanContext(BaseModel):
    internet_exposed: bool = False
    asset_criticality: int = Field(default=5, ge=1, le=10)
    data_lifetime_years: int = Field(default=1, ge=0, le=50)
    environment: str = "unknown"


class CryptoObservation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    asset_id: str
    asset_name: str
    asset_type: AssetType
    crypto_asset_type: CryptoAssetType = CryptoAssetType.ALGORITHM
    algorithm: str
    family: str
    primitive: Primitive
    parameter_set: str | None = None
    key_size: int | None = None
    protocol_version: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: Evidence
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RiskAssessment(BaseModel):
    observation_id: str
    score: int = Field(ge=0, le=100)
    severity: Severity
    quantum_status: QuantumStatus
    reasons: list[str]
    migration_target: str | None = None
    migration_strategy: str | None = None
    security_bits: int | None = None


class Finding(BaseModel):
    observation: CryptoObservation
    risk: RiskAssessment


class DashboardSummary(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    quantum_vulnerable: int
    pqc_ready: int
