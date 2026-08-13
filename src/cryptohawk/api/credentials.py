from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.api.schemas import (
    ConnectorCredentialCreateRequest,
    ConnectorCredentialReplaceRequest,
)
from cryptohawk.config import settings
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.domain.credentials import ConnectorCredentialMetadata
from cryptohawk.security.secrets import SecretConfigurationError, VersionedAesGcmCipher
from cryptohawk.storage.credentials import ConnectorCredentialRepository

router = APIRouter(
    prefix="/api/v1/workspaces/{workspace_id}/credentials",
    tags=["connector-credentials"],
)

AdminPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.ADMIN)),
]

credential_repo: ConnectorCredentialRepository | None = None


def _build_repository() -> ConnectorCredentialRepository:
    if not settings.connector_encryption_keys.strip():
        raise SecretConfigurationError("connector credential encryption is not configured")
    cipher = VersionedAesGcmCipher.from_spec(
        settings.connector_encryption_keys,
        active_version=settings.connector_encryption_active_version,
    )
    return ConnectorCredentialRepository(inventory, cipher)


def get_credential_repository() -> ConnectorCredentialRepository:
    global credential_repo
    if credential_repo is None:
        try:
            credential_repo = _build_repository()
        except SecretConfigurationError as exc:
            raise HTTPException(
                status_code=503,
                detail="connector credential storage is unavailable",
            ) from exc
    return credential_repo


def initialize_connector_credentials() -> None:
    if not settings.connector_encryption_keys.strip():
        if settings.environment.lower() == "production":
            raise RuntimeError(
                "CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS is required in production"
            )
        return
    repository = _build_repository()
    repository.create_schema()


def _actor(principal: Principal) -> str:
    return f"{principal.kind.value}:{principal.subject_id}"


@router.post(
    "",
    response_model=ConnectorCredentialMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_credential(
    workspace_id: str,
    request: ConnectorCredentialCreateRequest,
    principal: AdminPrincipal,
) -> ConnectorCredentialMetadata:
    try:
        return get_credential_repository().create(
            workspace_id=workspace_id,
            name=request.name,
            kind=request.kind,
            secret=request.secret,
            created_by=_actor(principal),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("", response_model=list[ConnectorCredentialMetadata])
def list_credentials(
    workspace_id: str,
    _principal: AdminPrincipal,
) -> list[ConnectorCredentialMetadata]:
    return get_credential_repository().list_workspace(workspace_id)


@router.post(
    "/{credential_id}/replace",
    response_model=ConnectorCredentialMetadata,
)
def replace_credential(
    workspace_id: str,
    credential_id: str,
    request: ConnectorCredentialReplaceRequest,
    _principal: AdminPrincipal,
) -> ConnectorCredentialMetadata:
    try:
        return get_credential_repository().replace(
            workspace_id=workspace_id,
            credential_id=credential_id,
            secret=request.secret,
            name=request.name,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/{credential_id}/rotate-encryption",
    response_model=ConnectorCredentialMetadata,
)
def rotate_credential_encryption(
    workspace_id: str,
    credential_id: str,
    _principal: AdminPrincipal,
) -> ConnectorCredentialMetadata:
    try:
        return get_credential_repository().rotate_encryption(
            workspace_id=workspace_id,
            credential_id=credential_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete(
    "/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_credential(
    workspace_id: str,
    credential_id: str,
    _principal: AdminPrincipal,
) -> None:
    try:
        get_credential_repository().delete(
            workspace_id=workspace_id,
            credential_id=credential_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
