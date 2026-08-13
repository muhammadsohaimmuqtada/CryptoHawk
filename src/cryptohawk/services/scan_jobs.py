from __future__ import annotations

from cryptohawk.config import settings
from cryptohawk.domain.inventory import ScanJob, ScanStatus
from cryptohawk.domain.models import Finding
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.executor import (
    AssetScanError,
    AssetScanExecutor,
    RepositoryScannerProtocol,
    RiskEngineProtocol,
    SourceScannerProtocol,
    TLSScannerProtocol,
)
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.quotas import QuotaRepository


class ScanJobService:
    def __init__(
        self,
        inventory: InventoryRepository,
        findings: FindingRepository,
        *,
        executor: AssetScanExecutor | None = None,
        risk_engine: RiskEngineProtocol | None = None,
        source_scanner: SourceScannerProtocol | None = None,
        repository_scanner: RepositoryScannerProtocol | None = None,
        tls_scanner: TLSScannerProtocol | None = None,
        quota: QuotaRepository | None = None,
        history: ContinuousRepository | None = None,
    ) -> None:
        self.inventory = inventory
        self.findings = findings
        self.quota = quota
        self.history = history or ContinuousRepository(inventory)
        if repository_scanner is None:
            from cryptohawk.services.repository_runtime import build_repository_scanner

            repository_scanner = build_repository_scanner(inventory, self.history)
        self.executor = executor or AssetScanExecutor(
            risk_engine=risk_engine or RiskEngine(),
            source_scanner=source_scanner or SourceScanner(),
            repository_scanner=repository_scanner,
            tls_scanner=tls_scanner or TLSScanner(),
        )

    def run(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        source: str | None = None,
        filename: str | None = None,
        timeout: float = 5.0,
    ) -> tuple[ScanJob, list[Finding]]:
        asset = self.inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id)
        if asset is None:
            raise LookupError("asset not found in workspace")

        if self.quota is not None:
            self.quota.require_scan_slot(
                workspace_id=workspace_id,
                limit=settings.workspace_scan_concurrency,
            )

        try:
            job = self.inventory.create_scan_job(
                workspace_id=workspace_id,
                asset_id=asset_id,
                kind=self.executor.scan_kind(asset),
            )
            self.inventory.transition_scan_job(
                workspace_id=workspace_id,
                job_id=job.id,
                expected=ScanStatus.QUEUED,
                target=ScanStatus.RUNNING,
            )

            try:
                results = self.executor.execute(
                    asset,
                    source=source,
                    filename=filename,
                    timeout=timeout,
                    scan_job_id=job.id,
                )
                results = self.history.prepare_findings(job.id, results)
                self.findings.upsert_many(
                    results,
                    workspace_id=workspace_id,
                    managed_asset_id=asset.id,
                    scan_job_id=job.id,
                )
                self.history.record_successful_scan(
                    workspace_id=workspace_id,
                    asset_id=asset.id,
                    scan_job_id=job.id,
                    findings=results,
                )
                job = self.inventory.transition_scan_job(
                    workspace_id=workspace_id,
                    job_id=job.id,
                    expected=ScanStatus.RUNNING,
                    target=ScanStatus.SUCCEEDED,
                    findings_count=len(results),
                )
                return job, results
            except Exception as exc:
                self.inventory.transition_scan_job(
                    workspace_id=workspace_id,
                    job_id=job.id,
                    expected=ScanStatus.RUNNING,
                    target=ScanStatus.FAILED,
                    error_message=str(exc),
                )
                raise
        finally:
            if self.quota is not None:
                self.quota.release_scan_slot(workspace_id=workspace_id)


__all__ = ["AssetScanError", "ScanJobService"]
