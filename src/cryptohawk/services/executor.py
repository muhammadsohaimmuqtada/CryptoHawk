from __future__ import annotations

from typing import Protocol

from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanKind
from cryptohawk.domain.models import CryptoObservation, Finding
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.certificates import CertificateScanner
from cryptohawk.scanners.repository import RepositoryCollection
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.ssh import SSHScanner
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


class EndpointScannerProtocol(Protocol):
    def scan(
        self, hostname: str, port: int, timeout: float = 5.0
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
        tls_scanner: EndpointScannerProtocol | None = None,
        certificate_scanner: EndpointScannerProtocol | None = None,
        ssh_scanner: EndpointScannerProtocol | None = None,
    ) -> None:
        self.risk_engine = risk_engine or RiskEngine()
        self.source_scanner = source_scanner or SourceScanner()
        self.repository_scanner = repository_scanner
        self.tls_scanner = tls_scanner or TLSScanner()
        self.certificate_scanner = certificate_scanner or CertificateScanner()
        self.ssh_scanner = ssh_scanner or SSHScanner()

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
        if asset.kind == ManagedAssetKind.CERTIFICATE_ENDPOINT:
            return ScanKind.CERTIFICATE
        if asset.kind == ManagedAssetKind.SSH_ENDPOINT:
            return ScanKind.SSH
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
            hostname, port = self.parse_endpoint_locator(
                asset.locator,
                default_port=443,
                label="TLS",
            )
            return self.tls_scanner.scan(hostname, port, timeout)

        if asset.kind == ManagedAssetKind.CERTIFICATE_ENDPOINT:
            hostname, port = self.parse_endpoint_locator(
                asset.locator,
                default_port=443,
                label="certificate",
            )
            return self.certificate_scanner.scan(hostname, port, timeout)

        if asset.kind == ManagedAssetKind.SSH_ENDPOINT:
            hostname, port = self.parse_endpoint_locator(
                asset.locator,
                default_port=22,
                label="SSH",
            )
            return self.ssh_scanner.scan(hostname, port, timeout)

        raise AssetScanError(f"collector not implemented for asset kind: {asset.kind.value}")

    @staticmethod
    def parse_endpoint_locator(
        locator: str,
        *,
        default_port: int,
        label: str,
    ) -> tuple[str, int]:
        value = locator.strip()
        if not value:
            raise AssetScanError(f"{label} locator is empty")
        if value.startswith("["):
            closing = value.find("]")
            if closing <= 1:
                raise AssetScanError(f"{label} locator contains an invalid IPv6 address")
            hostname = value[1:closing]
            suffix = value[closing + 1 :]
            if not suffix:
                return hostname, default_port
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                raise AssetScanError(f"{label} locator must be hostname or hostname:port")
            port = int(suffix[1:])
        elif value.count(":") == 1:
            hostname, port_text = value.rsplit(":", 1)
            if not hostname or not port_text.isdigit():
                raise AssetScanError(f"{label} locator must be hostname or hostname:port")
            port = int(port_text)
        else:
            hostname = value
            port = default_port
        if not hostname:
            raise AssetScanError(f"{label} locator hostname is empty")
        if not 1 <= port <= 65535:
            raise AssetScanError(f"{label} locator port must be between 1 and 65535")
        return hostname, port

    @staticmethod
    def parse_tls_locator(locator: str) -> tuple[str, int]:
        return AssetScanExecutor.parse_endpoint_locator(
            locator,
            default_port=443,
            label="TLS",
        )
