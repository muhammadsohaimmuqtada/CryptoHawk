from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.api.schemas import WorkspaceDeleteRequest
from cryptohawk.domain.auth import Principal, PrincipalKind, WorkspaceRole
from cryptohawk.storage.retention import (
    WorkspacePurgeBlocked,
    WorkspaceRetentionRepository,
)

router = APIRouter()
retention_repo = WorkspaceRetentionRepository(inventory)
OwnerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.OWNER)),
]


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
