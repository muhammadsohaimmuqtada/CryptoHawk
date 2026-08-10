from cryptohawk.domain.models import AssetType, CryptoObservation, Evidence, Primitive
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.storage.database import FindingRepository


def test_repository_round_trip() -> None:
    repo = FindingRepository("sqlite+pysqlite:///:memory:")
    repo.create_schema()
    observation = CryptoObservation(
        asset_id="a1",
        asset_name="service",
        asset_type=AssetType.SOURCE,
        algorithm="SHA1",
        family="SHA-1",
        primitive=Primitive.HASH,
        evidence=Evidence(source="test"),
    )
    finding = RiskEngine().assess(observation)
    assert repo.upsert_many([finding]) == 1
    stored = repo.list_findings()
    assert len(stored) == 1
    assert stored[0].observation.family == "SHA-1"
    assert repo.summary().quantum_vulnerable == 1
