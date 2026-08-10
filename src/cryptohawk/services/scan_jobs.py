from __future__ import annotations

from typing import Protocol

from cryptohawk.domain.inventory import (
    ManagedAsset,
    ManagedAssetKind,
    ScanJob,
    ScanKind,
    ScanStatus,
)
from cryptohawk.domain.models import CryptoObservation, Finding
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository


class AssetScanError(RuntimeError):
    pass


class SourceScannerProtocol(Protocol):
    def scan_text(
        self,
        text: str,
        *,
        asset_name: str = "inline",
        locator: str = "inline",
    ) -> list[CryptoObservation]: ...


class TLSScannerProtocol(Protocol):
    def scan(
        self, hostname: str, port: int = 443, timeout: float = 5.0
    ) -> list[CryptoObservation]: ...


class ScanJobService:
    def __init__(
        self,
        inventory: InventoryRepository,
        findings: FindingRepository,
        *,
        risk_engine: RiskEngine | None = None,
        source_scanner: SourceScannerProtocol | None = None,
        tls_scanner: TLSScannerProtocol | None = None,
    ) -> None:
        self.inventory = inventory
        self.findings = findings
        self.risk_engine = risk_engine or RiskEngine()
        self.source_scanner = source_scanner or SourceScanner()
        self.tls_scanner = tls_scanner or TLSScanner()

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
        if not asset.enabled:
            raise AssetScanError("asset is disabled")

        scan_kind = self._scan_kind(asset)
        job = self.inventory.create_scan_job(
            workspace_id=workspace_id,
            asset_id=asset_id,
            kind=scan_kind,
        )
        self.inventory.transition_scan_job(
            workspace_id=workspace_id,
            job_id=job.id,
            expected=ScanStatus.QUEUED,
            target=ScanStatus.RUNNING,
        )

        try:
            observations = self._collect(
                asset,
                source=source,
                filename=filename,
                timeout=timeout,
            )
            normalized = [
                observation.model_copy(
                    update={"asset_id": asset.id, "asset_name": asset.name}
                )
                for observation in observations
            ]
            findings = [
                self.risk_engine.assess(observation, asset.context)
                for observation in normalized
            ]
            self.findings.upsert_many(
                findings,
                workspace_id=workspace_id,
                managed_asset_id=asset.id,
                scan_job_id=job.id,
            )
            job = self.inventory.transition_scan_job(
                workspace_id=workspace_id,
                job_id=job.id,
                expected=ScanStatus.RUNNING,
                target=ScanStatus.SUCCEEDED,
                findings_count=len(findings),
            )
            return job, findings
        except Exception as exc:
            self.inventory.transition_scan_job(
                workspace_id=workspace_id,
                job_id=job.id,
                expected=ScanStatus.RUNNING,
                target=ScanStatus.FAILED,
                error_message=str(exc),
            )
            raise

    @staticmethod
    def _scan_kind(asset: ManagedAsset) -> ScanKind:
        if asset.kind == ManagedAssetKind.SOURCE:
            return ScanKind.SOURCE
        if asset.kind == ManagedAssetKind.TLS_ENDPOINT:
            return ScanKind.TLS
        raise AssetScanError(f"collector not implemented for asset kind: {asset.kind.value}")

    def _collect(
        self,
        asset: ManagedAsset,
        *,
        source: str | None,
        filename: str | None,
        timeout: float,
    ) -> list[CryptoObservation]:
        if asset.kind == ManagedAssetKind.SOURCE:
            if not source:
                raise AssetScanError("source content is required for source assets")
            return self.source_scanner.scan_text(
                source,
                asset_name=asset.name,
                locator=filename or asset.locator,
            )

        if asset.kind == ManagedAssetKind.TLS_ENDPOINT:
            hostname, port = self._parse_tls_locator(asset.locator)
            return self.tls_scanner.scan(hostname, port, timeout)

        raise AssetScanError(f"collector not implemented for asset kind: {asset.kind.value}")

    @staticmethod
    def _parse_tls_locator(locator: str) -> tuple[str, int]:
        value = locator.strip()
        if ":" not in value:
            return value, 443
        hostname, port_text = value.rsplit(":", 1)
        if not hostname or not port_text.isdigit():
            raise AssetScanError("TLS locator must be hostname or hostname:port")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise AssetScanError("TLS locator port must be between 1 and 65535")
        return hostname, port
