from __future__ import annotations

from typing import Protocol

from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanKind
from cryptohawk.domain.models import CryptoObservation, Finding
from cryptohawk.domain.policy import EffectiveCryptoPolicy
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.risk.policy import CryptoPolicyEvaluator
from cryptohawk.scanners.certificates import CertificateScanner
from cryptohawk.scanners.container_image import (
    ContainerImageCollection,
    ContainerImageScanError,
    ContainerImageScanner,
)
from cryptohawk.scanners.repository import RepositoryCollection
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.ssh import SSHScanner
from cryptohawk.scanners.tls import TLSScanner

DEFAULT_POLICY_PROVENANCE = "risk-engine-v1"


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


class ContainerScannerProtocol(Protocol):
    def scan(self, asset: ManagedAsset) -> ContainerImageCollection: ...


class EndpointScannerProtocol(Protocol):
    def scan(
        self, hostname: str, port: int, timeout: float = 5.0
    ) -> list[CryptoObservation]: ...


class RiskEngineProtocol(Protocol):
    def assess(self, observation: CryptoObservation, context) -> Finding: ...


class PolicyProviderProtocol(Protocol):
    def effective_policy(self, workspace_id: str) -> EffectiveCryptoPolicy: ...


class AssetScanExecutor:
    def __init__(
        self,
        *,
        risk_engine: RiskEngineProtocol | None = None,
        source_scanner: SourceScannerProtocol | None = None,
        repository_scanner: RepositoryScannerProtocol | None = None,
        container_scanner: ContainerScannerProtocol | None = None,
        tls_scanner: EndpointScannerProtocol | None = None,
        certificate_scanner: EndpointScannerProtocol | None = None,
        ssh_scanner: EndpointScannerProtocol | None = None,
        policy_provider: PolicyProviderProtocol | None = None,
        policy_evaluator: CryptoPolicyEvaluator | None = None,
    ) -> None:
        self.risk_engine = risk_engine or RiskEngine()
        self.source_scanner = source_scanner or SourceScanner()
        self.repository_scanner = repository_scanner
        self.container_scanner = container_scanner or ContainerImageScanner()
        self.tls_scanner = tls_scanner or TLSScanner()
        self.certificate_scanner = certificate_scanner or CertificateScanner()
        self.ssh_scanner = ssh_scanner or SSHScanner()
        self.policy_provider = policy_provider
        self.policy_evaluator = policy_evaluator or CryptoPolicyEvaluator()

    def execute(
        self,
        asset: ManagedAsset,
        *,
        source: str | None = None,
        filename: str | None = None,
        timeout: float = 5.0,
        scan_job_id: str | None = None,
    ) -> list[Finding]:
        findings, _ = self.execute_with_provenance(
            asset,
            source=source,
            filename=filename,
            timeout=timeout,
            scan_job_id=scan_job_id,
        )
        return findings

    def execute_with_provenance(
        self,
        asset: ManagedAsset,
        *,
        source: str | None = None,
        filename: str | None = None,
        timeout: float = 5.0,
        scan_job_id: str | None = None,
    ) -> tuple[list[Finding], str]:
        if not asset.enabled:
            raise AssetScanError("asset is disabled")
        policy = (
            self.policy_provider.effective_policy(asset.workspace_id)
            if self.policy_provider is not None
            else None
        )
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
        findings = [
            self.risk_engine.assess(observation, asset.context) for observation in normalized
        ]
        if policy is not None:
            findings = [
                self.policy_evaluator.apply(finding, asset.context, policy)
                for finding in findings
            ]
            return findings, policy.provenance_ref
        return findings, DEFAULT_POLICY_PROVENANCE

    @staticmethod
    def scan_kind(asset: ManagedAsset) -> ScanKind:
        if asset.kind == ManagedAssetKind.SOURCE:
            return ScanKind.SOURCE
        if asset.kind == ManagedAssetKind.REPOSITORY:
            return ScanKind.REPOSITORY
        if asset.kind == ManagedAssetKind.CONTAINER:
            return ScanKind.CONTAINER
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

        if asset.kind == ManagedAssetKind.CONTAINER:
            try:
                return self.container_scanner.scan(asset).observations
            except ContainerImageScanError as exc:
                raise AssetScanError(str(exc)) from exc

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
