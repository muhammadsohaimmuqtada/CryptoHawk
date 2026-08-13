from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.api.continuous import continuous_repo
from cryptohawk.api.schemas import RepositoryAssetCreateRequest
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.domain.credentials import ConnectorCredentialKind
from cryptohawk.domain.repositories import RepositoryAsset, RepositoryProvider, RepositoryScanProvenance
from cryptohawk.scanners.repository import RepositoryScanError
from cryptohawk.services.repository_runtime import build_repository_scanner
from cryptohawk.storage.repositories import RepositoryAssetRepository

router = APIRouter(tags=["repositories"])
repository_assets = RepositoryAssetRepository(inventory)
repository_scanner = build_repository_scanner(inventory, continuous_repo)

ViewerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.VIEWER)),
]
AdminPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.ADMIN)),
]


def _expected_credential_kind(provider: RepositoryProvider) -> ConnectorCredentialKind | None:
    if provider == RepositoryProvider.GITHUB:
        return ConnectorCredentialKind.GITHUB_TOKEN
    if provider == RepositoryProvider.GITLAB:
        return ConnectorCredentialKind.GITLAB_TOKEN
    return None


def _validate_credential(
    *,
    workspace_id: str,
    provider: RepositoryProvider,
    credential_id: str | None,
) -> None:
    if credential_id is None:
        return
    credentials = repository_scanner.credentials
    if credentials is None:
        raise HTTPException(
            status_code=503,
            detail="connector credential storage is unavailable",
        )
    expected = _expected_credential_kind(provider)
    if expected is None:
        raise HTTPException(
            status_code=422,
            detail="authenticated custom repository hosts are not supported",
        )
    try:
        metadata = credentials.get_metadata(
            workspace_id=workspace_id,
            credential_id=credential_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if metadata.kind != expected:
        raise HTTPException(
            status_code=422,
            detail=f"repository requires a {expected.value} credential",
        )


@router.post(
    "/api/v1/workspaces/{workspace_id}/repositories",
    response_model=RepositoryAsset,
    status_code=status.HTTP_201_CREATED,
)
def create_repository_asset(
    workspace_id: str,
    request: RepositoryAssetCreateRequest,
    _principal: AdminPrincipal,
) -> RepositoryAsset:
    try:
        provider = repository_scanner.validate_repository_url(request.repository_url)
        ref = repository_scanner.validate_ref(request.ref)
        _validate_credential(
            workspace_id=workspace_id,
            provider=provider,
            credential_id=request.credential_id,
        )
        return repository_assets.create_repository_asset(
            workspace_id=workspace_id,
            name=request.name,
            repository_url=request.repository_url,
            provider=provider,
            ref=ref,
            credential_id=request.credential_id,
            context=request.context,
            tags=request.tags,
        )
    except RepositoryScanError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/api/v1/workspaces/{workspace_id}/repositories",
    response_model=list[RepositoryAsset],
)
def list_repository_assets(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> list[RepositoryAsset]:
    return repository_assets.list_repository_assets(workspace_id=workspace_id)


@router.get(
    "/api/v1/workspaces/{workspace_id}/repositories/{asset_id}",
    response_model=RepositoryAsset,
)
def get_repository_asset(
    workspace_id: str,
    asset_id: str,
    _principal: ViewerPrincipal,
) -> RepositoryAsset:
    try:
        return repository_assets.get_repository_asset(
            workspace_id=workspace_id,
            asset_id=asset_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/api/v1/workspaces/{workspace_id}/repositories/{asset_id}/commits",
    response_model=list[RepositoryScanProvenance],
)
def list_repository_scan_provenance(
    workspace_id: str,
    asset_id: str,
    _principal: ViewerPrincipal,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[RepositoryScanProvenance]:
    try:
        repository_assets.get_repository_asset(
            workspace_id=workspace_id,
            asset_id=asset_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return repository_assets.list_scan_provenance(
        workspace_id=workspace_id,
        asset_id=asset_id,
        limit=limit,
    )
