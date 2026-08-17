from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.api.oidc import router as oidc_router
from cryptohawk.api.schemas import WorkspaceDeleteRequest, WorkspaceRetentionPolicyRequest
from cryptohawk.domain.auth import Principal, PrincipalKind, WorkspaceRole
from cryptohawk.domain.retention import RetentionSweepResult, WorkspaceRetentionPolicy
from cryptohawk.storage.retention import (
    WorkspacePurgeBlocked,
    WorkspaceRetentionRepository,
)

router = APIRouter()
router.include_router(oidc_router)
retention_repo = WorkspaceRetentionRepository(inventory)
ViewerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.VIEWER)),
]
OwnerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.OWNER)),
]


def _require_owner_session(principal: Principal) -> str:
    if principal.kind != PrincipalKind.SESSION or principal.user_id is None:
        raise HTTPException(
            status_code=403,
            detail="an owner user session is required for retention changes",
        )
    return principal.user_id


@router.get(
    "/api/v1/workspaces/{workspace_id}/retention-policy",
    response_model=WorkspaceRetentionPolicy,
)
def get_retention_policy(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> WorkspaceRetentionPolicy:
    try:
        return retention_repo.get_policy(workspace_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/api/v1/workspaces/{workspace_id}/retention-policy",
    response_model=WorkspaceRetentionPolicy,
)
def set_retention_policy(
    workspace_id: str,
    payload: WorkspaceRetentionPolicyRequest,
    principal: OwnerPrincipal,
) -> WorkspaceRetentionPolicy:
    user_id = _require_owner_session(principal)
    try:
        return retention_repo.set_policy(
            workspace_id=workspace_id,
            enabled=payload.enabled,
            evidence_retention_days=payload.evidence_retention_days,
            audit_retention_days=payload.audit_retention_days,
            sweep_interval_hours=payload.sweep_interval_hours,
            updated_by=user_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/api/v1/workspaces/{workspace_id}/retention-policy/run",
    response_model=RetentionSweepResult,
)
def run_retention_policy(
    workspace_id: str,
    principal: OwnerPrincipal,
) -> RetentionSweepResult:
    _require_owner_session(principal)
    try:
        result = retention_repo.prune_workspace_history(workspace_id=workspace_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=409, detail="retention policy was not run")
    return result


@router.delete(
    "/api/v1/workspaces/{workspace_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def purge_workspace(
    workspace_id: str,
    payload: WorkspaceDeleteRequest,
    http_request: Request,
    principal: OwnerPrincipal,
) -> None:
    workspace = inventory.get_workspace(workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if principal.kind != PrincipalKind.SESSION or principal.user_id is None:
        raise HTTPException(
            status_code=403,
            detail="an owner user session is required to delete a workspace",
        )
    if payload.confirm_slug != workspace.slug:
        raise HTTPException(
            status_code=409,
            detail="confirm_slug must exactly match the workspace slug",
        )

    try:
        retention_repo.purge_workspace(workspace_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except WorkspacePurgeBlocked as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    # The SecurityAuditMiddleware runs after this handler. Override workspace
    # attribution so the successful deletion is recorded as a global tombstone
    # without recreating tenant-scoped data after the purge commits.
    http_request.state.audit_workspace_id_override = None
