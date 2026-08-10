from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from cryptohawk import __version__
from cryptohawk.api.schemas import (
    AssetCreateRequest,
    ManagedScanRequest,
    QueuedScanRequest,
    ScanExecutionResponse,
    ScanResponse,
    SourceScanRequest,
    TLSScanRequest,
    WorkspaceCreateRequest,
)
from cryptohawk.cbom.exporter import CycloneDXExporter
from cryptohawk.config import settings
from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanJob, Workspace
from cryptohawk.domain.models import DashboardSummary, Finding
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import AssetScanError, ScanJobService
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository

repo = FindingRepository(settings.database_url)
inventory = InventoryRepository(settings.database_url)
scan_queue = ScanQueueRepository(inventory)
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
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    inventory.create_schema()
    repo.create_schema()
    scan_queue.create_schema()
    yield


app = FastAPI(
    title="CryptoHawk API",
    version=__version__,
    description="Cryptographic exposure management and post-quantum readiness API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cryptohawk", "version": __version__}


@app.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary() -> DashboardSummary:
    return repo.summary()


@app.get("/api/v1/findings", response_model=list[Finding])
def list_findings(limit: int = Query(default=200, ge=1, le=1000)) -> list[Finding]:
    return repo.list_findings(limit=limit)


@app.post("/api/v1/scan/source", response_model=ScanResponse)
def scan_source(request: SourceScanRequest) -> ScanResponse:
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
    try:
        observations = tls_scanner.scan(request.hostname, request.port, request.timeout)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"TLS scan failed: {exc}") from exc
    findings = [risk_engine.assess(observation, request.context) for observation in observations]
    persisted = repo.upsert_many(findings) if request.persist else 0
    return ScanResponse(findings=findings, persisted=persisted)


@app.get("/api/v1/cbom")
def export_cbom(limit: int = Query(default=1000, ge=1, le=5000)) -> dict:
    return exporter.export(repo.list_findings(limit=limit))


@app.delete("/api/v1/findings")
def clear_findings() -> dict[str, str]:
    repo.clear()
    return {"status": "cleared"}


@app.post(
    "/api/v1/workspaces",
    response_model=Workspace,
    status_code=status.HTTP_201_CREATED,
)
def create_workspace(request: WorkspaceCreateRequest) -> Workspace:
    try:
        return inventory.create_workspace(name=request.name, slug=request.slug)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/workspaces", response_model=list[Workspace])
def list_workspaces() -> list[Workspace]:
    return inventory.list_workspaces()


@app.post(
    "/api/v1/workspaces/{workspace_id}/assets",
    response_model=ManagedAsset,
    status_code=status.HTTP_201_CREATED,
)
def create_asset(workspace_id: str, request: AssetCreateRequest) -> ManagedAsset:
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
def list_assets(workspace_id: str) -> list[ManagedAsset]:
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
) -> ScanExecutionResponse:
    _require_workspace(workspace_id)
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
) -> ScanJob:
    _require_workspace(workspace_id)
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
    "/api/v1/workspaces/{workspace_id}/scan-jobs",
    response_model=list[ScanJob],
)
def list_scan_jobs(
    workspace_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[ScanJob]:
    _require_workspace(workspace_id)
    return inventory.list_scan_jobs(workspace_id=workspace_id, limit=limit)


@app.get(
    "/api/v1/workspaces/{workspace_id}/scan-jobs/{job_id}",
    response_model=ScanJob,
)
def get_scan_job(workspace_id: str, job_id: str) -> ScanJob:
    _require_workspace(workspace_id)
    return _require_scan_job(workspace_id, job_id)


@app.post(
    "/api/v1/workspaces/{workspace_id}/scan-jobs/{job_id}/cancel",
    response_model=ScanJob,
)
def cancel_scan_job(workspace_id: str, job_id: str) -> ScanJob:
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
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[Finding]:
    _require_workspace(workspace_id)
    return repo.list_findings(limit=limit, workspace_id=workspace_id)


@app.get(
    "/api/v1/workspaces/{workspace_id}/dashboard/summary",
    response_model=DashboardSummary,
)
def workspace_dashboard_summary(workspace_id: str) -> DashboardSummary:
    _require_workspace(workspace_id)
    return repo.summary(workspace_id=workspace_id)


@app.get("/api/v1/workspaces/{workspace_id}/cbom")
def export_workspace_cbom(
    workspace_id: str,
    limit: int = Query(default=1000, ge=1, le=5000),
) -> dict:
    _require_workspace(workspace_id)
    return exporter.export(repo.list_findings(limit=limit, workspace_id=workspace_id))
