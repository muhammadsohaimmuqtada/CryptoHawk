from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response

from cryptohawk.api.auth import inventory, require_workspace_role
from cryptohawk.domain.auth import Principal, WorkspaceRole
from cryptohawk.domain.reporting import EngineeringReport, ExecutiveReport
from cryptohawk.services.reporting import ReportingService

router = APIRouter(
    prefix="/api/v1/workspaces/{workspace_id}/reports",
    tags=["reporting"],
)

ViewerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.VIEWER)),
]


def _reports() -> ReportingService:
    return ReportingService(inventory)


def _filename(workspace_id: str, suffix: str) -> str:
    workspace = inventory.get_workspace(workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    return f"cryptohawk-{workspace.slug}-{suffix}"


@router.get("/executive", response_model=ExecutiveReport)
def executive_report(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> ExecutiveReport:
    try:
        return _reports().executive_report(workspace_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/engineering", response_model=EngineeringReport)
def engineering_report(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> EngineeringReport:
    try:
        return _reports().engineering_report(workspace_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/executive.csv")
def executive_csv(workspace_id: str, _principal: ViewerPrincipal) -> Response:
    try:
        content = _reports().executive_csv(workspace_id)
        filename = _filename(workspace_id, "executive.csv")
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/engineering.csv")
def engineering_csv(workspace_id: str, _principal: ViewerPrincipal) -> Response:
    try:
        content = _reports().engineering_csv(workspace_id)
        filename = _filename(workspace_id, "engineering.csv")
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/executive.html")
def executive_html(workspace_id: str, _principal: ViewerPrincipal) -> Response:
    try:
        content = _reports().executive_html(workspace_id)
        filename = _filename(workspace_id, "executive.html")
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/cbom")
def current_cbom(workspace_id: str, _principal: ViewerPrincipal) -> dict:
    try:
        return _reports().current_cbom(workspace_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
