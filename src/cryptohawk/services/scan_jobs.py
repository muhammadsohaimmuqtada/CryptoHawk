from __future__ import annotations

import time

from cryptohawk.config import settings
from cryptohawk.domain.inventory import ScanJob, ScanStatus
from cryptohawk.domain.models import Finding
from cryptohawk.observability import record_scan_attempt, traced_operation
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.certificates import CertificateScanner
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.ssh import SSHScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.container_runtime import build_container_scanner
from cryptohawk.services.executor import (
    AssetScanError,
    AssetScanExecutor,
    ContainerScannerProtocol,
    EndpointScannerProtocol,
    RepositoryScannerProtocol,
    RiskEngineProtocol,
    SourceScannerProtocol,
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
        container_scanner: ContainerScannerProtocol | None = None,
        tls_scanner: EndpointScannerProtocol | None = None,
        certificate_scanner: EndpointScannerProtocol | None = None,
        ssh_scanner: EndpointScannerProtocol | None = None,
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
            container_scanner=container_scanner or build_container_scanner(),
            tls_scanner=tls_scanner
            or TLSScanner(allow_private_targets=settings.allow_private_targets),
            certificate_scanner=certificate_scanner
            or CertificateScanner(allow_private_targets=settings.allow_private_targets),
            ssh_scanner=ssh_scanner
            or SSHScanner(allow_private_targets=settings.allow_private_targets),
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
        kind = self.executor.scan_kind(asset)

        if self.quota is not None:
            self.quota.require_scan_slot(
                workspace_id=workspace_id,
                limit=settings.workspace_scan_concurrency,
            )

        try:
            job = self.inventory.create_scan_job(
                workspace_id=workspace_id,
                asset_id=asset_id,
                kind=kind,
            )
            self.inventory.transition_scan_job(
                workspace_id=workspace_id,
                job_id=job.id,
                expected=ScanStatus.QUEUED,
                target=ScanStatus.RUNNING,
            )

            started = time.perf_counter()
            outcome = "failed"
            with traced_operation(
                "scan.sync.execute",
                attributes={
                    "cryptohawk.scan.kind": kind.value,
                    "cryptohawk.scan.execution": "sync",
                },
                job_id=job.id,
                component="api",
            ) as span:
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
                    outcome = "succeeded"
                    span.set_attribute("cryptohawk.scan.findings_count", len(results))
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
                    record_scan_attempt(
                        kind=kind.value,
                        execution="sync",
                        outcome=outcome,
                        duration_seconds=time.perf_counter() - started,
                    )
        finally:
            if self.quota is not None:
                self.quota.release_scan_slot(workspace_id=workspace_id)


__all__ = ["AssetScanError", "ScanJobService"]
