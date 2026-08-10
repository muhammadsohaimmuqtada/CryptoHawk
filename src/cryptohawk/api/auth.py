from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cryptohawk.config import settings
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.inventory import InventoryRepository

inventory = InventoryRepository(settings.database_url)
auth_repo = AuthRepository(inventory)
bearer = HTTPBearer(auto_error=False)


def get_current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer authentication is required")
    try:
        principal = auth_repo.authenticate(credentials.credentials)
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    request.state.principal = principal
    return principal


def require_workspace_role(
    minimum_role: WorkspaceRole,
) -> Callable[..., Principal]:
    def dependency(
        workspace_id: str,
        principal: Annotated[Principal, Depends(get_current_principal)],
    ) -> Principal:
        try:
            auth_repo.authorize_workspace(principal, workspace_id, minimum_role)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return principal

    return dependency
