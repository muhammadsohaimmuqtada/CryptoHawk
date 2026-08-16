from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

PolicyDisposition = Literal["pass", "review", "fail"]


class CryptoPolicyRules(BaseModel):
    minimum_rsa_bits: int = Field(default=2048, ge=1024, le=16384)
    minimum_aes_bits: int = Field(default=128, ge=128, le=256)
    minimum_tls_version: Literal["1.2", "1.3"] = "1.2"
    disallowed_families: list[str] = Field(
        default_factory=lambda: ["MD5", "SHA-1", "DES", "3DES", "RC4", "DSA"]
    )
    quantum_vulnerable_default: Literal["review", "fail"] = "review"
    internet_exposed_quantum_action: Literal["review", "fail"] = "review"
    long_lived_data_years: int = Field(default=5, ge=0, le=50)
    unknown_family_action: PolicyDisposition = "review"
    minimum_detection_confidence: float = Field(default=0.75, ge=0.0, le=1.0)

    @field_validator("minimum_aes_bits")
    @classmethod
    def validate_aes_bits(cls, value: int) -> int:
        if value not in {128, 192, 256}:
            raise ValueError("minimum_aes_bits must be 128, 192, or 256")
        return value

    @field_validator("disallowed_families")
    @classmethod
    def normalize_disallowed_families(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            token = value.strip()
            if not token:
                raise ValueError("disallowed_families cannot contain empty values")
            folded = token.casefold()
            if folded in seen:
                continue
            seen.add(folded)
            normalized.append(token)
        return normalized


class CryptoPolicyPack(BaseModel):
    id: str
    workspace_id: str
    slug: str
    name: str
    description: str
    built_in: bool
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CryptoPolicyVersion(BaseModel):
    id: str
    policy_id: str
    workspace_id: str
    version: int = Field(ge=1)
    rules: CryptoPolicyRules
    rules_hash: str = Field(min_length=64, max_length=64)
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def provenance_ref(self) -> str:
        return f"policy:{self.policy_id}@{self.version}:{self.rules_hash[:16]}"


class EffectiveCryptoPolicy(BaseModel):
    pack: CryptoPolicyPack
    version: CryptoPolicyVersion
    assigned_by: str
    assigned_at: datetime

    @property
    def provenance_ref(self) -> str:
        return self.version.provenance_ref


class CryptoPolicyPackWithVersions(BaseModel):
    pack: CryptoPolicyPack
    versions: list[CryptoPolicyVersion]
    active_version: int | None = None
