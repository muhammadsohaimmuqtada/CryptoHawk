from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ConnectorCredentialKind(StrEnum):
    GITHUB_TOKEN = "github-token"
    GITLAB_TOKEN = "gitlab-token"
    GENERIC_BEARER = "generic-bearer"
    REGISTRY_BASIC = "registry-basic"
    SSH_PRIVATE_KEY = "ssh-private-key"
    CLOUD_ACCESS_KEY = "cloud-access-key"


class ConnectorCredentialMetadata(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str
    name: str
    kind: ConnectorCredentialKind
    key_version: int = Field(ge=1)
    secret_fields: list[str] = Field(default_factory=list)
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_used_at: datetime | None = None


_REQUIRED_FIELDS: dict[ConnectorCredentialKind, frozenset[str]] = {
    ConnectorCredentialKind.GITHUB_TOKEN: frozenset({"token"}),
    ConnectorCredentialKind.GITLAB_TOKEN: frozenset({"token"}),
    ConnectorCredentialKind.GENERIC_BEARER: frozenset({"token"}),
    ConnectorCredentialKind.REGISTRY_BASIC: frozenset({"username", "password"}),
    ConnectorCredentialKind.SSH_PRIVATE_KEY: frozenset({"private_key"}),
    ConnectorCredentialKind.CLOUD_ACCESS_KEY: frozenset(
        {"access_key_id", "secret_access_key"}
    ),
}

_ALLOWED_FIELDS: dict[ConnectorCredentialKind, frozenset[str]] = {
    ConnectorCredentialKind.GITHUB_TOKEN: frozenset({"token"}),
    ConnectorCredentialKind.GITLAB_TOKEN: frozenset({"token"}),
    ConnectorCredentialKind.GENERIC_BEARER: frozenset({"token"}),
    ConnectorCredentialKind.REGISTRY_BASIC: frozenset({"username", "password"}),
    ConnectorCredentialKind.SSH_PRIVATE_KEY: frozenset(
        {"private_key", "passphrase", "username"}
    ),
    ConnectorCredentialKind.CLOUD_ACCESS_KEY: frozenset(
        {"access_key_id", "secret_access_key", "session_token"}
    ),
}


def validate_secret_material(
    kind: ConnectorCredentialKind,
    secret: dict[str, str],
) -> dict[str, str]:
    if not secret:
        raise ValueError("credential secret material is required")
    if len(secret) > 16:
        raise ValueError("credential secret material has too many fields")

    normalized: dict[str, str] = {}
    for raw_key, raw_value in secret.items():
        key = raw_key.strip()
        if not key:
            raise ValueError("credential secret field names cannot be empty")
        if len(key) > 100:
            raise ValueError("credential secret field names are too long")
        if not isinstance(raw_value, str):
            raise ValueError("credential secret values must be strings")
        if not raw_value:
            raise ValueError(f"credential secret field {key!r} cannot be empty")
        if len(raw_value.encode("utf-8")) > 256_000:
            raise ValueError(f"credential secret field {key!r} is too large")
        normalized[key] = raw_value

    allowed = _ALLOWED_FIELDS[kind]
    unexpected = sorted(set(normalized) - allowed)
    if unexpected:
        raise ValueError(
            f"unsupported secret fields for {kind.value}: {', '.join(unexpected)}"
        )

    missing = sorted(_REQUIRED_FIELDS[kind] - set(normalized))
    if missing:
        raise ValueError(
            f"missing required secret fields for {kind.value}: {', '.join(missing)}"
        )

    total_bytes = sum(len(value.encode("utf-8")) for value in normalized.values())
    if total_bytes > 512_000:
        raise ValueError("credential secret material is too large")
    return normalized
