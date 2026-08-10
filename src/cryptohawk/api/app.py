from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from cryptohawk import __version__
from cryptohawk.api.schemas import ScanResponse, SourceScanRequest, TLSScanRequest
from cryptohawk.cbom.exporter import CycloneDXExporter
from cryptohawk.config import settings
from cryptohawk.domain.models import DashboardSummary, Finding
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.storage.database import FindingRepository

repo = FindingRepository(settings.database_url)
risk_engine = RiskEngine()
source_scanner = SourceScanner()
tls_scanner = TLSScanner(allow_private_targets=settings.allow_private_targets)
exporter = CycloneDXExporter()


@asynccontextmanager
async def lifespan(_: FastAPI):
    repo.create_schema()
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
