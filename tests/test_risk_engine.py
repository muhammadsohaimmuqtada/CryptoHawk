from cryptohawk.domain.models import AssetType, CryptoObservation, Evidence, Primitive, ScanContext
from cryptohawk.risk.engine import RiskEngine


def observation(family: str, *, key_size: int | None = None) -> CryptoObservation:
    return CryptoObservation(
        asset_id="asset-1",
        asset_name="test",
        asset_type=AssetType.SOURCE,
        algorithm=family,
        family=family,
        primitive=Primitive.PKE,
        key_size=key_size,
        evidence=Evidence(source="test"),
    )


def test_rsa_internet_long_lived_is_high_risk() -> None:
    finding = RiskEngine().assess(
        observation("RSA", key_size=2048),
        ScanContext(internet_exposed=True, asset_criticality=9, data_lifetime_years=10),
    )
    assert finding.risk.score >= 80
    assert finding.risk.severity.value == "critical"
    assert finding.risk.migration_target == "ML-KEM"


def test_ml_kem_is_pqc_safe() -> None:
    finding = RiskEngine().assess(observation("ML-KEM"))
    assert finding.risk.quantum_status.value == "safe"
    assert finding.risk.score < 20
