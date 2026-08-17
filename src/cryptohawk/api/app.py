from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware

from cryptohawk import __version__
from cryptohawk.api.auth import (
    auth_repo,
    get_current_principal,
    get_quota_repository,
    inventory,
    require_workspace_role,
)
from cryptohawk.api.continuous import continuous_repo
from cryptohawk.api.continuous import router as continuous_router
from cryptohawk.api.credentials import initialize_connector_credentials
from cryptohawk.api.credentials import router as credential_router
from cryptohawk.api.middleware import SecurityAuditMiddleware, audit_repo
from cryptohawk.api.retention import router as retention_router
from cryptohawk.api.schemas import (
    ApiKeyCreateRequest,
    AssetCreateRequest,
    BootstrapRequest,
    LoginRequest,
    ManagedScanRequest,
    MemberCreateRequest,
    QueuedScanRequest,
    ScanExecutionResponse,
    ScanResponse,
    SourceScanRequest,
    TLSScanRequest,
    WorkspaceCreateRequest,
    WorkspaceMemberResponse,
)
from cryptohawk.cbom.exporter import CycloneDXExporter
from cryptohawk.config import settings
from cryptohawk.domain.audit import AuditEvent
from cryptohawk.domain.auth import (
    ApiKeyMetadata,
    IssuedApiKey,
    IssuedToken,
    Principal,
    WorkspaceRole,
)
from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanJob, Workspace
from cryptohawk.domain.models import DashboardSummary, Finding
from cryptohawk.domain.quotas import ScanCapacity
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import AssetScanError, ScanJobService
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import ScanCapacityExceeded

repo = FindingRepository(settings.database_url)
quota_repo = get_quota_repository()
scan_queue = ScanQueueRepository(inventory, quota_repo)
risk_engine = RiskEngine()
source_scanner = SourceScanner()
tls_scanner = TLSScanner(allow_private_targets=settings.allow_private_targets)
exporter = CycloneDXExporter()
scan_jobs = ScanJobService(
    inventory,
    repo,
    risk_engine=risk_engine,
    source_scanner=source_scanner,
    tls_scanner=tls_scanner,
    quota=quota_repo,
    history=continuous_repo,
)

ViewerPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.VIEWER)),
]
AnalystPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.ANALYST)),
]
AdminPrincipal = Annotated[
    Principal,
    Depends(require_workspace_role(WorkspaceRole.ADMIN)),
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    inventory.create_schema()
    repo.create_schema()
    get_quota_repository().create_schema()
    scan_queue.create_schema()
    auth_repo.create_schema()
    audit_repo.create_schema()
    continuous_repo.create_schema()
    initialize_connector_credentials()
    yield


app = FastAPI(
    title="CryptoHawk API",
    version=__version__,
    description="Cryptographic exposure management and post-quantum readiness API",
    lifespan=lifespan,
)
app.include_router(continuous_router)
app.include_router(credential_router)
app.include_router(retention_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.add_middleware(SecurityAuditMiddleware)


def _legacy_guard() -> None:
    if not settings.allow_legacy_global_api:
        raise HTTPException(status_code=404, detail="legacy global API is disabled")


def _require_workspace(workspace_id: str) -> Workspace:
    workspace = inventory.get_workspace(workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    return workspace


def _require_asset(workspace_id: str, asset_id: str) -> ManagedAsset:
    asset = inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found in workspace")
    return asset


def _require_scan_job(workspace_id: str, job_id: str) -> ScanJob:
    job = inventory.get_scan_job(workspace_id=workspace_id, job_id=job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan job not found in workspace")
    return job


def _hashed_scope(*parts: str) -> str:
    material = "|".join(part.strip().lower() for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _peer_host(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


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


def _enforce_scan_submission(workspace_id: str) -> None:
    _enforce_rate_limit(
        scope_key=f"workspace:{workspace_id}",
        action="scan-submit",
        limit=settings.scan_submissions_per_minute,
        window_seconds=60,
        detail="workspace scan submission quota exceeded",
    )


@app.get("/health")
def health() -> dict[str, str | bool]:
    return {
        "status": "ok",
        "service": "cryptohawk",
        "version": __version__,
        "setup_required": not auth_repo.has_users(),
    }


@app.get("/api/v1/auth/status")
def auth_status() -> dict[str, bool]:
    return {"bootstrap_required": not auth_repo.has_users()}


@app.post(
    "/api/v1/auth/bootstrap",
    response_model=IssuedToken,
    status_code=status.HTTP_201_CREATED,
)
def bootstrap(request: BootstrapRequest, http_request: Request) -> IssuedToken:
    _enforce_rate_limit(
        scope_key=f"bootstrap:{_hashed_scope(_peer_host(http_request))}",
        action="bootstrap",
        limit=settings.bootstrap_attempts_per_hour,
        window_seconds=3600,
        detail="bootstrap attempt quota exceeded",
    )
    try:
        return auth_repo.bootstrap(
            email=request.email,
            display_name=request.display_name,
            password=request.password,
            workspace_name=request.workspace_name,
            workspace_slug=request.workspace_slug,
            session_hours=settings.session_hours,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/auth/login", response_model=IssuedToken)
def login(request: LoginRequest, http_request: Request) -> IssuedToken:
    _enforce_rate_limit(
        scope_key=f"login:{_hashed_scope(_peer_host(http_request), request.email)}",
        action="login",
        limit=settings.login_attempts_per_15_minutes,
        window_seconds=900,
        detail="login attempt quota exceeded",
    )
    try:
        return auth_repo.login(
            email=request.email,
            password=request.password,
            session_hours=settings.session_hours,
        )
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid email or password") from exc


@app.get("/api/v1/auth/me", response_model=Principal)
def me(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> Principal:
    return principal


@app.post("/api/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> None:
    auth_repo.revoke_session(principal)


@app.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary() -> DashboardSummary:
    _legacy_guard()
    return repo.summary()


@app.get("/api/v1/findings", response_model=list[Finding])
def list_findings(limit: int = Query(default=200, ge=1, le=1000)) -> list[Finding]:
    _legacy_guard()
    return repo.list_findings(limit=limit)


@app.post("/api/v1/scan/source", response_model=ScanResponse)
def scan_source(request: SourceScanRequest) -> ScanResponse:
    _legacy_guard()
    observations = source_scanner.scan_text(
        request.source,
        asset_name=request.filename,
        locator=request.filename,
    )
    findings = [risk_engine.assess(observation, request.context) for observation in observations]
    persisted = repo.upsert_many(findings) if request.persist else 0
    return ScanResponse(findings=findings, persisted=persisted)


@app.post("/api/v1/scan/tls", response_model=ScanResponse)
def scan_tls(request: TLSScanRequest) -> ScanResponse:
    _legacy_guard()
    try:
        observations = tls_scanner.scan(request.hostname, request.port, request.timeout)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"TLS scan failed: {exc}") from exc
    findings = [risk_engine.assess(observation, request.context) for observation in observations]
    persisted = repo.upsert_many(findings) if request.persist else 0
    return ScanResponse(findings=findings, persisted=persisted)


@app.get("/api/v1/cbom")
def export_cbom(limit: int = Query(default=1000, ge=1, le=5000)) -> dict:
    _legacy_guard()
    return exporter.export(repo.list_findings(limit=limit))


@app.delete("/api/v1/findings")
def clear_findings() -> dict[str, str]:
    _legacy_guard()
    repo.clear()
    return {"status": "cleared"}


@app.post(
    "/api/v1/workspaces",
    response_model=Workspace,
    status_code=status.HTTP_201_CREATED,
)
def create_workspace(
    request: WorkspaceCreateRequest,
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> Workspace:
    try:
        return auth_repo.create_workspace(
            principal=principal,
            name=request.name,
            slug=request.slug,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/workspaces", response_model=list[Workspace])
def list_workspaces(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> list[Workspace]:
    return auth_repo.list_workspaces(principal)


@app.get(
    "/api/v1/workspaces/{workspace_id}/members",
    response_model=list[WorkspaceMemberResponse],
)
def list_members(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> list[WorkspaceMemberResponse]:
    principal = _principal
    return [
        WorkspaceMemberResponse(user=user, membership=membership)
        for user, membership in auth_repo.list_members(principal, workspace_id)
    ]


@app.post(
    "/api/v1/workspaces/{workspace_id}/members",
    response_model=WorkspaceMemberResponse,
    status_code=status.HTTP_201_CREATED,
)
def provision_member(
    workspace_id: str,
    request: MemberCreateRequest,
    principal: AdminPrincipal,
) -> WorkspaceMemberResponse:
    try:
        user, membership = auth_repo.provision_member(
            principal=principal,
            workspace_id=workspace_id,
            email=request.email,
            display_name=request.display_name,
            role=request.role,
            password=request.password,
        )
        return WorkspaceMemberResponse(user=user, membership=membership)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post(
    "/api/v1/workspaces/{workspace_id}/api-keys",
    response_model=IssuedApiKey,
    status_code=status.HTTP_201_CREATED,
)
def create_api_key(
    workspace_id: str,
    request: ApiKeyCreateRequest,
    principal: AdminPrincipal,
) -> IssuedApiKey:
    try:
        return auth_repo.create_api_key(
            principal=principal,
            workspace_id=workspace_id,
            name=request.name,
            role=request.role,
            expires_days=request.expires_days,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get(
    "/api/v1/workspaces/{workspace_id}/api-keys",
    response_model=list[ApiKeyMetadata],
)
def list_api_keys(workspace_id: str, principal: AdminPrincipal) -> list[ApiKeyMetadata]:
    return auth_repo.list_api_keys(principal, workspace_id)


@app.delete(
    "/api/v1/workspaces/{workspace_id}/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_api_key(workspace_id: str, key_id: str, principal: AdminPrincipal) -> None:
    try:
        auth_repo.revoke_api_key(principal, workspace_id, key_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get(
    "/api/v1/workspaces/{workspace_id}/audit",
    response_model=list[AuditEvent],
)
def list_audit_events(
    workspace_id: str,
    _principal: AdminPrincipal,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[AuditEvent]:
    _require_workspace(workspace_id)
    return audit_repo.list_workspace(workspace_id, limit=limit)


@app.post(
    "/api/v1/workspaces/{workspace_id}/assets",
    response_model=ManagedAsset,
    status_code=status.HTTP_201_CREATED,
)
def create_asset(
    workspace_id: str,
    request: AssetCreateRequest,
    _principal: AdminPrincipal,
) -> ManagedAsset:
    _require_workspace(workspace_id)
    try:
        return inventory.create_asset(
            workspace_id=workspace_id,
            name=request.name,
            kind=request.kind,
            locator=request.locator,
            context=request.context,
            tags=request.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get(
    "/api/v1/workspaces/{workspace_id}/assets",
    response_model=list[ManagedAsset],
)
def list_assets(workspace_id: str, _principal: ViewerPrincipal) -> list[ManagedAsset]:
    _require_workspace(workspace_id)
    return inventory.list_assets(workspace_id=workspace_id)


@app.post(
    "/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan",
    response_model=ScanExecutionResponse,
)
def run_managed_scan(
    workspace_id: str,
    asset_id: str,
    request: ManagedScanRequest,
    _principal: AnalystPrincipal,
) -> ScanExecutionResponse:
    _require_workspace(workspace_id)
    _enforce_scan_submission(workspace_id)
    try:
        job, findings = scan_jobs.run(
            workspace_id=workspace_id,
            asset_id=asset_id,
            source=request.source,
            filename=request.filename,
            timeout=request.timeout,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ScanCapacityExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": "1"},
        ) from exc
    except (AssetScanError, OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ScanExecutionResponse(job=job, findings=findings)


@app.post(
    "/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan-jobs",
    response_model=ScanJob,
    status_code=status.HTTP_202_ACCEPTED,
)
def enqueue_managed_scan(
    workspace_id: str,
    asset_id: str,
    request: QueuedScanRequest,
    _principal: AnalystPrincipal,
) -> ScanJob:
    _require_workspace(workspace_id)
    _enforce_scan_submission(workspace_id)
    asset = _require_asset(workspace_id, asset_id)
    if asset.kind == ManagedAssetKind.SOURCE:
        raise HTTPException(
            status_code=422,
            detail="durable source scans require a repository-backed source collector",
        )
    try:
        kind = scan_jobs.executor.scan_kind(asset)
        return scan_queue.enqueue(
            workspace_id=workspace_id,
            asset_id=asset_id,
            kind=kind,
            max_attempts=request.max_attempts,
        )
    except AssetScanError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get(
    "/api/v1/workspaces/{workspace_id}/scan-capacity",
    response_model=ScanCapacity,
)
def get_scan_capacity(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> ScanCapacity:
    _require_workspace(workspace_id)
    return get_quota_repository().scan_capacity(
        workspace_id=workspace_id,
        limit=settings.workspace_scan_concurrency,
    )


@app.get(
    "/api/v1/workspaces/{workspace_id}/scan-jobs",
    response_model=list[ScanJob],
)
def list_scan_jobs(
    workspace_id: str,
    _principal: ViewerPrincipal,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[ScanJob]:
    _require_workspace(workspace_id)
    return inventory.list_scan_jobs(workspace_id=workspace_id, limit=limit)


@app.get(
    "/api/v1/workspaces/{workspace_id}/scan-jobs/{job_id}",
    response_model=ScanJob,
)
def get_scan_job(
    workspace_id: str,
    job_id: str,
    _principal: ViewerPrincipal,
) -> ScanJob:
    _require_workspace(workspace_id)
    return _require_scan_job(workspace_id, job_id)


@app.post(
    "/api/v1/workspaces/{workspace_id}/scan-jobs/{job_id}/cancel",
    response_model=ScanJob,
)
def cancel_scan_job(
    workspace_id: str,
    job_id: str,
    _principal: AnalystPrincipal,
) -> ScanJob:
    _require_workspace(workspace_id)
    _require_scan_job(workspace_id, job_id)
    try:
        return scan_queue.request_cancel(job_id=job_id)
    except LookupError as exc:
        raise HTTPException(
            status_code=409,
            detail="scan job is not managed by the durable queue",
        ) from exc


@app.get(
    "/api/v1/workspaces/{workspace_id}/findings",
    response_model=list[Finding],
)
def list_workspace_findings(
    workspace_id: str,
    _principal: ViewerPrincipal,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[Finding]:
    _require_workspace(workspace_id)
    return repo.list_findings(limit=limit, workspace_id=workspace_id)


@app.get(
    "/api/v1/workspaces/{workspace_id}/dashboard/summary",
    response_model=DashboardSummary,
)
def workspace_dashboard_summary(
    workspace_id: str,
    _principal: ViewerPrincipal,
) -> DashboardSummary:
    _require_workspace(workspace_id)
    return repo.summary(workspace_id=workspace_id)


@app.get("/api/v1/workspaces/{workspace_id}/cbom")
def export_workspace_cbom(
    workspace_id: str,
    _principal: ViewerPrincipal,
    limit: int = Query(default=1000, ge=1, le=5000),
) -> dict:
    _require_workspace(workspace_id)
    return exporter.export(repo.list_findings(limit=limit, workspace_id=workspace_id))
