from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanKind
from cryptohawk.domain.models import AssetType, CryptoObservation, Evidence, Primitive
from cryptohawk.services.executor import AssetScanExecutor


class FakeEndpointScanner:
    def __init__(self, asset_type: AssetType, family: str) -> None:
        self.asset_type = asset_type
        self.family = family
        self.calls: list[tuple[str, int, float]] = []

    def scan(self, hostname: str, port: int, timeout: float = 5.0):
        self.calls.append((hostname, port, timeout))
        return [
            CryptoObservation(
                asset_id="collector-id",
                asset_name="collector-name",
                asset_type=self.asset_type,
                algorithm=self.family,
                family=self.family,
                primitive=Primitive.SIGNATURE,
                evidence=Evidence(source="test", locator=f"{hostname}:{port}"),
            )
        ]


def _asset(kind: ManagedAssetKind, locator: str) -> ManagedAsset:
    return ManagedAsset(
        workspace_id="workspace-1",
        name=f"managed-{kind.value}",
        kind=kind,
        locator=locator,
    )


def test_certificate_and_ssh_scan_kinds_are_first_class() -> None:
    assert AssetScanExecutor.scan_kind(
        _asset(ManagedAssetKind.CERTIFICATE_ENDPOINT, "cert.example.com")
    ) == ScanKind.CERTIFICATE
    assert AssetScanExecutor.scan_kind(
        _asset(ManagedAssetKind.SSH_ENDPOINT, "ssh.example.com")
    ) == ScanKind.SSH


def test_executor_routes_certificate_and_ssh_default_ports_and_normalizes_identity() -> None:
    certificate = FakeEndpointScanner(AssetType.CERTIFICATE, "ECDSA")
    ssh = FakeEndpointScanner(AssetType.SSH_ENDPOINT, "ED25519")
    executor = AssetScanExecutor(certificate_scanner=certificate, ssh_scanner=ssh)

    certificate_asset = _asset(ManagedAssetKind.CERTIFICATE_ENDPOINT, "cert.example.com")
    ssh_asset = _asset(ManagedAssetKind.SSH_ENDPOINT, "ssh.example.com")
    cert_findings = executor.execute(certificate_asset, timeout=7.0)
    ssh_findings = executor.execute(ssh_asset, timeout=8.0)

    assert certificate.calls == [("cert.example.com", 443, 7.0)]
    assert ssh.calls == [("ssh.example.com", 22, 8.0)]
    assert cert_findings[0].observation.asset_id == certificate_asset.id
    assert cert_findings[0].observation.asset_name == certificate_asset.name
    assert ssh_findings[0].observation.asset_id == ssh_asset.id
    assert ssh_findings[0].observation.asset_name == ssh_asset.name


def test_endpoint_locator_supports_bracketed_ipv6_and_custom_ports() -> None:
    assert AssetScanExecutor.parse_endpoint_locator(
        "[2001:db8::10]:2222",
        default_port=22,
        label="SSH",
    ) == ("2001:db8::10", 2222)
    assert AssetScanExecutor.parse_endpoint_locator(
        "2001:db8::20",
        default_port=443,
        label="certificate",
    ) == ("2001:db8::20", 443)
