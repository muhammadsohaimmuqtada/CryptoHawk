from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cryptohawk.config import settings
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.quotas import QuotaRepository

inventory = InventoryRepository(settings.database_url)
auth_repo = AuthRepository(inventory)
bearer = HTTPBearer(auto_error=False)


def get_quota_repository() -> QuotaRepository:
    return QuotaRepository(auth_repo.inventory)


def _enforce_rate_limit(
    *,
    scope_key: str,
    action: str,
    limit: int,
    window_seconds: int,
    detail: str,
) -> None:
    decision = get_quota_repository().consume(
        scope_key=scope_key,
        action=action,
        limit=limit,
        window_seconds=window_seconds,
    )
    if decision.allowed:
        return
    raise HTTPException(
        status_code=429,
        detail=detail,
        headers={"Retry-After": str(max(1, decision.retry_after_seconds))},
    )


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
    _enforce_rate_limit(
        scope_key=f"principal:{principal.kind.value}:{principal.subject_id}",
        action="api",
        limit=settings.principal_requests_per_minute,
        window_seconds=60,
        detail="principal request quota exceeded",
    )
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
        _enforce_rate_limit(
            scope_key=f"workspace:{workspace_id}",
            action="api",
            limit=settings.workspace_requests_per_minute,
            window_seconds=60,
            detail="workspace request quota exceeded",
        )
        return principal

    return dependency
