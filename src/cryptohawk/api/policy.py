from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.domain.policy import (
    CryptoPolicyPackWithVersions,
    CryptoPolicyRules,
    CryptoPolicyVersion,
    EffectiveCryptoPolicy,
)
from cryptohawk.storage.policy import PolicyRepository

router = APIRouter(
    prefix="/api/v1/workspaces/{workspace_id}/policy-packs",
    tags=["crypto-policy"],
)

ViewerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.VIEWER)),
]
AdminPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.ADMIN)),
]

policy_repo = PolicyRepository(inventory)


def _actor(principal: Principal) -> str:
    return f"{principal.kind.value}:{principal.subject_id}"


class PolicyPackCreateRequest(BaseModel):
    slug: str = Field(
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    rules: CryptoPolicyRules
    activate: bool = False


class PolicyVersionCreateRequest(BaseModel):
    rules: CryptoPolicyRules
    activate: bool = False


@router.get("", response_model=list[CryptoPolicyPackWithVersions])
def list_policy_packs(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> list[CryptoPolicyPackWithVersions]:
    return policy_repo.list_packs(workspace_id=workspace_id)


@router.get("/effective", response_model=EffectiveCryptoPolicy)
def get_effective_policy(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> EffectiveCryptoPolicy:
    try:
        return policy_repo.effective_policy(workspace_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "",
    response_model=CryptoPolicyPackWithVersions,
    status_code=status.HTTP_201_CREATED,
)
def create_policy_pack(
    workspace_id: str,
    request: PolicyPackCreateRequest,
    principal: AdminPrincipal,
) -> CryptoPolicyPackWithVersions:
    try:
        return policy_repo.create_pack(
            workspace_id=workspace_id,
            slug=request.slug,
            name=request.name,
            description=request.description,
            rules=request.rules,
            created_by=_actor(principal),
            activate=request.activate,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{policy_id}", response_model=CryptoPolicyPackWithVersions)
def get_policy_pack(
    workspace_id: str,
    policy_id: str,
    _principal: ViewerPrincipal,
) -> CryptoPolicyPackWithVersions:
    policy = policy_repo.get_pack(workspace_id=workspace_id, policy_id=policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="policy pack not found in workspace")
    return policy


@router.post(
    "/{policy_id}/versions",
    response_model=CryptoPolicyVersion,
    status_code=status.HTTP_201_CREATED,
)
def create_policy_version(
    workspace_id: str,
    policy_id: str,
    request: PolicyVersionCreateRequest,
    principal: AdminPrincipal,
) -> CryptoPolicyVersion:
    try:
        return policy_repo.create_version(
            workspace_id=workspace_id,
            policy_id=policy_id,
            rules=request.rules,
            created_by=_actor(principal),
            activate=request.activate,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/{policy_id}/versions/{version}/activate",
    response_model=EffectiveCryptoPolicy,
)
def activate_policy_version(
    workspace_id: str,
    policy_id: str,
    version: int,
    principal: AdminPrincipal,
) -> EffectiveCryptoPolicy:
    try:
        return policy_repo.activate(
            workspace_id=workspace_id,
            policy_id=policy_id,
            version=version,
            assigned_by=_actor(principal),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
