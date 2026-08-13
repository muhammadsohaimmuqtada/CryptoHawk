from __future__ import annotations

from typing import Protocol

from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanKind
from cryptohawk.domain.models import CryptoObservation, Finding
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.repository import RepositoryCollection
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner


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


class RepositoryScannerProtocol(Protocol):
    def scan(self, asset: ManagedAsset, *, scan_job_id: str) -> RepositoryCollection: ...


class TLSScannerProtocol(Protocol):
    def scan(
        self, hostname: str, port: int = 443, timeout: float = 5.0
    ) -> list[CryptoObservation]: ...


class RiskEngineProtocol(Protocol):
    def assess(self, observation: CryptoObservation, context) -> Finding: ...


class AssetScanExecutor:
    def __init__(
        self,
        *,
        risk_engine: RiskEngineProtocol | None = None,
        source_scanner: SourceScannerProtocol | None = None,
        repository_scanner: RepositoryScannerProtocol | None = None,
        tls_scanner: TLSScannerProtocol | None = None,
    ) -> None:
        self.risk_engine = risk_engine or RiskEngine()
        self.source_scanner = source_scanner or SourceScanner()
        self.repository_scanner = repository_scanner
        self.tls_scanner = tls_scanner or TLSScanner()

    def execute(
        self,
        asset: ManagedAsset,
        *,
        source: str | None = None,
        filename: str | None = None,
        timeout: float = 5.0,
        scan_job_id: str | None = None,
    ) -> list[Finding]:
        if not asset.enabled:
            raise AssetScanError("asset is disabled")
        observations = self._collect(
            asset,
            source=source,
            filename=filename,
            timeout=timeout,
            scan_job_id=scan_job_id,
        )
        normalized = [
            observation.model_copy(update={"asset_id": asset.id, "asset_name": asset.name})
            for observation in observations
        ]
        return [self.risk_engine.assess(observation, asset.context) for observation in normalized]

    @staticmethod
    def scan_kind(asset: ManagedAsset) -> ScanKind:
        if asset.kind == ManagedAssetKind.SOURCE:
            return ScanKind.SOURCE
        if asset.kind == ManagedAssetKind.REPOSITORY:
            return ScanKind.REPOSITORY
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
        scan_job_id: str | None,
    ) -> list[CryptoObservation]:
        if asset.kind == ManagedAssetKind.SOURCE:
            if not source:
                raise AssetScanError("source content is required for source assets")
            return self.source_scanner.scan_text(
                source,
                asset_name=asset.name,
                locator=filename or asset.locator,
            )

        if asset.kind == ManagedAssetKind.REPOSITORY:
            if self.repository_scanner is None:
                raise AssetScanError("repository collector is not configured")
            if scan_job_id is None:
                raise AssetScanError("repository scans require a scan job identity")
            return self.repository_scanner.scan(
                asset,
                scan_job_id=scan_job_id,
            ).observations

        if asset.kind == ManagedAssetKind.TLS_ENDPOINT:
            hostname, port = self.parse_tls_locator(asset.locator)
            return self.tls_scanner.scan(hostname, port, timeout)

        raise AssetScanError(f"collector not implemented for asset kind: {asset.kind.value}")

    @staticmethod
    def parse_tls_locator(locator: str) -> tuple[str, int]:
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
