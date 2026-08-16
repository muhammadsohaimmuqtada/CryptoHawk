from pathlib import Path

import pytest

from cryptohawk.domain.inventory import ManagedAssetKind
from cryptohawk.domain.models import (
    AssetType,
    CryptoAssetType,
    CryptoObservation,
    Evidence,
    Finding,
    Primitive,
    QuantumStatus,
    RiskAssessment,
    ScanContext,
    Severity,
)
from cryptohawk.domain.policy import CryptoPolicyRules
from cryptohawk.risk.policy import CryptoPolicyEvaluator
from cryptohawk.services.executor import AssetScanExecutor
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.policy import PolicyRepository


def _repositories(tmp_path: Path):
    inventory = InventoryRepository(f"sqlite:///{tmp_path / 'policy.db'}")
    policies = PolicyRepository(inventory)
    inventory.create_schema()
    policies.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    other = inventory.create_workspace(name="Other")
    return inventory, policies, workspace, other


def _finding(
    *,
    family: str = "RSA",
    algorithm: str = "RSA-2048",
    key_size: int | None = 2048,
    protocol_version: str | None = None,
    crypto_asset_type: CryptoAssetType = CryptoAssetType.ALGORITHM,
    confidence: float = 1.0,
    quantum_status: QuantumStatus = QuantumStatus.VULNERABLE,
) -> Finding:
    observation = CryptoObservation(
        asset_id="asset-1",
        asset_name="Payments",
        asset_type=AssetType.TLS_ENDPOINT,
        crypto_asset_type=crypto_asset_type,
        algorithm=algorithm,
        family=family,
        primitive=Primitive.PKE,
        key_size=key_size,
        protocol_version=protocol_version,
        confidence=confidence,
        evidence=Evidence(source="test", locator="payments.example.com:443"),
    )
    return Finding(
        observation=observation,
        risk=RiskAssessment(
            observation_id=observation.id,
            score=70,
            severity=Severity.HIGH,
            quantum_status=quantum_status,
            reasons=["base risk"],
        ),
    )


def test_builtins_are_deterministic_and_recommended_is_default(
    tmp_path: Path,
) -> None:
    _, policies, workspace, _ = _repositories(tmp_path)

    first = policies.list_packs(workspace_id=workspace.id)
    second = policies.list_packs(workspace_id=workspace.id)
    effective = policies.effective_policy(workspace.id)

    assert [item.pack.slug for item in first] == [
        item.pack.slug for item in second
    ]
    assert {item.pack.slug for item in first} == {
        "cryptohawk-recommended",
        "strict-modern",
        "long-lived-confidentiality",
    }
    assert effective.pack.slug == "cryptohawk-recommended"
    assert effective.version.version == 1
    assert len(effective.version.rules_hash) == 64
    assert len(effective.pack.id) == 32
    assert effective.provenance_ref.startswith(f"policy:{effective.pack.id}@1:")
    assert len(effective.provenance_ref) <= 80


def test_custom_policy_versions_are_immutable_and_tenant_scoped(
    tmp_path: Path,
) -> None:
    _, policies, workspace, other = _repositories(tmp_path)
    created = policies.create_pack(
        workspace_id=workspace.id,
        slug="payments-baseline",
        name="Payments Baseline",
        description="Payments crypto standard",
        rules=CryptoPolicyRules(minimum_rsa_bits=3072, minimum_aes_bits=256),
        created_by="user:owner",
        activate=True,
    )
    assert created.active_version == 1
    assert len(created.versions[0].provenance_ref) <= 80
    first_hash = created.versions[0].rules_hash

    version_two = policies.create_version(
        workspace_id=workspace.id,
        policy_id=created.pack.id,
        rules=CryptoPolicyRules(
            minimum_rsa_bits=4096,
            minimum_aes_bits=256,
            minimum_tls_version="1.3",
        ),
        created_by="user:owner",
        activate=True,
    )
    assert version_two.version == 2
    assert version_two.rules_hash != first_hash

    reloaded = policies.get_pack(
        workspace_id=workspace.id,
        policy_id=created.pack.id,
    )
    assert reloaded is not None
    assert [version.version for version in reloaded.versions] == [2, 1]
    assert reloaded.versions[1].rules_hash == first_hash
    assert reloaded.active_version == 2

    with pytest.raises(LookupError):
        policies.activate(
            workspace_id=other.id,
            policy_id=created.pack.id,
            version=2,
            assigned_by="user:other-owner",
        )

    builtin = next(
        item
        for item in policies.list_packs(workspace_id=workspace.id)
        if item.pack.built_in
    )
    with pytest.raises(ValueError, match="immutable"):
        policies.create_version(
            workspace_id=workspace.id,
            policy_id=builtin.pack.id,
            rules=CryptoPolicyRules(minimum_rsa_bits=4096),
            created_by="user:owner",
        )


def test_policy_evaluator_adds_baseline_result_without_changing_risk_score(
    tmp_path: Path,
) -> None:
    _, policies, workspace, _ = _repositories(tmp_path)
    strict = next(
        item
        for item in policies.list_packs(workspace_id=workspace.id)
        if item.pack.slug == "strict-modern"
    )
    policy = policies.activate(
        workspace_id=workspace.id,
        policy_id=strict.pack.id,
        version=1,
        assigned_by="user:owner",
    )
    finding = _finding()

    evaluated = CryptoPolicyEvaluator().apply(
        finding,
        ScanContext(internet_exposed=True, data_lifetime_years=8),
        policy,
    )

    assert evaluated.risk.score == finding.risk.score
    assert evaluated.risk.severity == finding.risk.severity
    assert evaluated.risk.policy_status == "fail"
    assert evaluated.risk.policy_id == policy.pack.id
    assert evaluated.risk.policy_version == 1
    assert evaluated.risk.policy_rules_hash == policy.version.rules_hash
    assert "minimum-rsa-bits" in evaluated.risk.policy_controls
    assert "harvest-now-decrypt-later" in evaluated.risk.policy_controls


def test_policy_evaluator_enforces_tls_and_reviews_unknowns(
    tmp_path: Path,
) -> None:
    _, policies, workspace, _ = _repositories(tmp_path)
    custom = policies.create_pack(
        workspace_id=workspace.id,
        slug="custom-modern",
        name="Custom Modern",
        description="",
        rules=CryptoPolicyRules(
            minimum_tls_version="1.3",
            unknown_family_action="review",
        ),
        created_by="user:owner",
        activate=True,
    )
    policy = policies.effective_policy(workspace.id)
    assert policy.pack.id == custom.pack.id

    tls_finding = _finding(
        family="TLS",
        algorithm="TLSv1.2",
        key_size=None,
        protocol_version="TLSv1.2",
        crypto_asset_type=CryptoAssetType.PROTOCOL,
        quantum_status=QuantumStatus.UNKNOWN,
    )
    tls_result = CryptoPolicyEvaluator().apply(
        tls_finding,
        ScanContext(),
        policy,
    )
    assert tls_result.risk.policy_status == "fail"
    assert "minimum-tls-version" in tls_result.risk.policy_controls

    unknown_finding = _finding(
        family="FutureCipher",
        algorithm="FutureCipher",
        key_size=None,
        quantum_status=QuantumStatus.UNKNOWN,
    )
    unknown_result = CryptoPolicyEvaluator().apply(
        unknown_finding,
        ScanContext(),
        policy,
    )
    assert unknown_result.risk.policy_status == "review"
    assert "unknown-family" in unknown_result.risk.policy_controls


def test_executor_returns_exact_policy_provenance_even_with_zero_findings(
    tmp_path: Path,
) -> None:
    inventory, policies, workspace, _ = _repositories(tmp_path)
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Empty source",
        kind=ManagedAssetKind.SOURCE,
        locator="empty.py",
        context=ScanContext(),
    )
    effective = policies.effective_policy(workspace.id)
    executor = AssetScanExecutor(policy_provider=policies)

    findings, provenance = executor.execute_with_provenance(
        asset,
        source="print('no crypto')",
        filename="empty.py",
    )

    assert findings == []
    assert provenance == effective.provenance_ref
