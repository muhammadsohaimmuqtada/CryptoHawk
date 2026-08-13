from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from cryptohawk.domain.inventory import ManagedAsset


class RepositoryProvider(StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"
    GENERIC = "generic"


class RepositoryScanMode(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"


class RepositoryConfiguration(BaseModel):
    asset_id: str
    workspace_id: str
    repository_url: str
    provider: RepositoryProvider
    ref: str = "HEAD"
    credential_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RepositoryAsset(BaseModel):
    asset: ManagedAsset
    repository: RepositoryConfiguration


class RepositoryScanProvenance(BaseModel):
    scan_job_id: str
    workspace_id: str
    asset_id: str
    repository_url: str
    ref: str
    commit_sha: str = Field(min_length=40, max_length=64)
    previous_commit_sha: str | None = Field(default=None, min_length=40, max_length=64)
    scan_mode: RepositoryScanMode
    changed_paths: int = Field(ge=0)
    scanned_files: int = Field(ge=0)
    retained_observations: int = Field(ge=0)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
