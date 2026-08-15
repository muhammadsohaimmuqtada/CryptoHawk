from __future__ import annotations

from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.domain.remediation import (
    MigrationItem,
    RemediationPriority,
    RemediationStatus,
    RemediationVerification,
)
from cryptohawk.storage.remediation import RemediationRepository

router = APIRouter(
    prefix="/api/v1/workspaces/{workspace_id}/migration-items",
    tags=["remediation"],
)

ViewerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.VIEWER)),
]
AnalystPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.ANALYST)),
]

StatusFilter = Annotated[RemediationStatus | None, Query(alias="status")]
OwnerFilter = Annotated[str | None, Query(max_length=200)]
LimitFilter = Annotated[int, Query(ge=1, le=1000)]

remediation_repo = RemediationRepository(inventory)
_schema_ready = False


def get_remediation_repository() -> RemediationRepository:
    global _schema_ready
    if not _schema_ready:
        remediation_repo.create_schema()
        _schema_ready = True
    return remediation_repo


def _actor(principal: Principal) -> str:
    return f"{principal.kind.value}:{principal.subject_id}"


class MigrationItemCreateRequest(BaseModel):
    finding_id: str = Field(min_length=1, max_length=64)
    owner: str | None = Field(default=None, max_length=200)
    priority: RemediationPriority | None = None
    target_algorithm: str | None = Field(default=None, max_length=200)
    due_date: date | None = None
    notes: str | None = Field(default=None, max_length=8000)


class MigrationItemUpdateRequest(BaseModel):
    owner: str | None = Field(default=None, max_length=200)
    status: RemediationStatus | None = None
    priority: RemediationPriority | None = None
    target_algorithm: str | None = Field(default=None, max_length=200)
    due_date: date | None = None
    notes: str | None = Field(default=None, max_length=8000)
    acceptance_reason: str | None = Field(default=None, max_length=8000)


class MigrationVerificationRequest(BaseModel):
    verification_job_id: str = Field(min_length=1, max_length=64)


@router.post("", response_model=MigrationItem, status_code=status.HTTP_201_CREATED)
def create_migration_item(
    workspace_id: str,
    request: MigrationItemCreateRequest,
    principal: AnalystPrincipal,
) -> MigrationItem:
    if inventory.get_workspace(workspace_id) is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    try:
        return get_remediation_repository().create_from_finding(
            workspace_id=workspace_id,
            finding_id=request.finding_id,
            created_by=_actor(principal),
            owner=request.owner,
            priority=request.priority,
            target_algorithm=request.target_algorithm,
            due_date=request.due_date,
            notes=request.notes,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("", response_model=list[MigrationItem])
def list_migration_items(
    workspace_id: str,
    _principal: ViewerPrincipal,
    item_status: StatusFilter = None,
    owner: OwnerFilter = None,
    limit: LimitFilter = 500,
) -> list[MigrationItem]:
    return get_remediation_repository().list_items(
        workspace_id=workspace_id,
        status=item_status,
        owner=owner,
        limit=limit,
    )


@router.get("/{item_id}", response_model=MigrationItem)
def get_migration_item(
    workspace_id: str,
    item_id: str,
    _principal: ViewerPrincipal,
) -> MigrationItem:
    item = get_remediation_repository().get_item(workspace_id=workspace_id, item_id=item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="migration item not found in workspace")
    return item


@router.post("/{item_id}/update", response_model=MigrationItem)
def update_migration_item(
    workspace_id: str,
    item_id: str,
    request: MigrationItemUpdateRequest,
    _principal: AnalystPrincipal,
) -> MigrationItem:
    try:
        return get_remediation_repository().update_item(
            workspace_id=workspace_id,
            item_id=item_id,
            changes=request.model_dump(exclude_unset=True, mode="python"),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{item_id}/verify", response_model=RemediationVerification)
def verify_migration_item(
    workspace_id: str,
    item_id: str,
    request: MigrationVerificationRequest,
    _principal: AnalystPrincipal,
) -> RemediationVerification:
    try:
        return get_remediation_repository().verify(
            workspace_id=workspace_id,
            item_id=item_id,
            verification_job_id=request.verification_job_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
