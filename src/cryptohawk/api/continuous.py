from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.api.schemas import ScanScheduleCreateRequest
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.domain.continuous import (
    DriftEvent,
    ObservationState,
    ScanSchedule,
    ScanSnapshot,
)
from cryptohawk.domain.inventory import ManagedAssetKind
from cryptohawk.services.executor import AssetScanError, AssetScanExecutor
from cryptohawk.storage.continuous import ContinuousRepository

router = APIRouter(tags=["continuous-scanning"])
continuous_repo = ContinuousRepository(inventory)

ViewerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.VIEWER)),
]
AdminPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.ADMIN)),
]


def _actor(principal: Principal) -> str:
    return f"{principal.kind.value}:{principal.subject_id}"


def _require_asset(workspace_id: str, asset_id: str):
    asset = inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found in workspace")
    return asset


@router.post(
    "/api/v1/workspaces/{workspace_id}/assets/{asset_id}/schedule",
    response_model=ScanSchedule,
    status_code=status.HTTP_201_CREATED,
)
def create_scan_schedule(
    workspace_id: str,
    asset_id: str,
    request: ScanScheduleCreateRequest,
    principal: AdminPrincipal,
) -> ScanSchedule:
    asset = _require_asset(workspace_id, asset_id)
    if asset.kind == ManagedAssetKind.SOURCE:
        raise HTTPException(
            status_code=422,
            detail="scheduled source scans require a repository-backed source collector",
        )
    try:
        AssetScanExecutor.scan_kind(asset)
        return continuous_repo.create_schedule(
            workspace_id=workspace_id,
            asset_id=asset_id,
            interval_seconds=request.interval_minutes * 60,
            max_attempts=request.max_attempts,
            first_run_at=request.start_at,
            created_by=_actor(principal),
        )
    except AssetScanError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/api/v1/workspaces/{workspace_id}/schedules",
    response_model=list[ScanSchedule],
)
def list_scan_schedules(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> list[ScanSchedule]:
    return continuous_repo.list_schedules(workspace_id=workspace_id)


@router.post(
    "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/pause",
    response_model=ScanSchedule,
)
def pause_scan_schedule(
    workspace_id: str,
    schedule_id: str,
    _principal: AdminPrincipal,
) -> ScanSchedule:
    try:
        return continuous_repo.set_schedule_enabled(
            workspace_id=workspace_id,
            schedule_id=schedule_id,
            enabled=False,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/resume",
    response_model=ScanSchedule,
)
def resume_scan_schedule(
    workspace_id: str,
    schedule_id: str,
    _principal: AdminPrincipal,
) -> ScanSchedule:
    try:
        return continuous_repo.set_schedule_enabled(
            workspace_id=workspace_id,
            schedule_id=schedule_id,
            enabled=True,
            resume_at=datetime.now(UTC),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete(
    "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_scan_schedule(
    workspace_id: str,
    schedule_id: str,
    _principal: AdminPrincipal,
) -> None:
    try:
        continuous_repo.delete_schedule(
            workspace_id=workspace_id,
            schedule_id=schedule_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/api/v1/workspaces/{workspace_id}/drift-events",
    response_model=list[DriftEvent],
)
def list_drift_events(
    workspace_id: str,
    _principal: ViewerPrincipal,
    asset_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[DriftEvent]:
    if asset_id is not None:
        _require_asset(workspace_id, asset_id)
    return continuous_repo.list_drift_events(
        workspace_id=workspace_id,
        asset_id=asset_id,
        limit=limit,
    )


@router.get(
    "/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan-history",
    response_model=list[ScanSnapshot],
)
def list_asset_scan_history(
    workspace_id: str,
    asset_id: str,
    _principal: ViewerPrincipal,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[ScanSnapshot]:
    _require_asset(workspace_id, asset_id)
    return continuous_repo.list_scan_history(
        workspace_id=workspace_id,
        asset_id=asset_id,
        limit=limit,
    )


@router.get(
    "/api/v1/workspaces/{workspace_id}/assets/{asset_id}/crypto-state",
    response_model=list[ObservationState],
)
def list_asset_crypto_state(
    workspace_id: str,
    asset_id: str,
    _principal: ViewerPrincipal,
    active_only: bool = True,
) -> list[ObservationState]:
    _require_asset(workspace_id, asset_id)
    return continuous_repo.list_observation_states(
        workspace_id=workspace_id,
        asset_id=asset_id,
        active_only=active_only,
    )
