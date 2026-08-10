from cryptohawk.cbom.exporter import CycloneDXExporter
from cryptohawk.domain.models import AssetType, CryptoObservation, Evidence, Primitive
from cryptohawk.risk.engine import RiskEngine


def test_exports_cyclonedx_17_crypto_asset() -> None:
    observation = CryptoObservation(
        asset_id="service-a",
        asset_name="auth",
        asset_type=AssetType.SOURCE,
        algorithm="RSA-2048",
        family="RSA",
        primitive=Primitive.PKE,
        key_size=2048,
        parameter_set="2048",
        evidence=Evidence(source="source-code", locator="auth.py", line=42),
    )
    document = CycloneDXExporter().export([RiskEngine().assess(observation)])
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    component = document["components"][0]
    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "algorithm"
    assert component["cryptoProperties"]["algorithmProperties"]["algorithmFamily"] == "RSA"
