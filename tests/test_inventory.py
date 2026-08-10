from pathlib import Path

import pytest

from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
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
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository


def _database_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'inventory.db'}"


def _finding(asset_id: str, observation_id: str) -> Finding:
    observation = CryptoObservation(
        id=observation_id,
        asset_id=asset_id,
        asset_name="api",
        asset_type=AssetType.SOURCE,
        crypto_asset_type=CryptoAssetType.ALGORITHM,
        algorithm="RSA-2048",
        family="RSA",
        primitive=Primitive.PKE,
        key_size=2048,
        evidence=Evidence(source="test", locator="app.py"),
    )
    risk = RiskAssessment(
        observation_id=observation.id,
        score=90,
        severity=Severity.CRITICAL,
        quantum_status=QuantumStatus.VULNERABLE,
        reasons=["test"],
        migration_target="ML-KEM",
    )
    return Finding(observation=observation, risk=risk)


def test_workspace_asset_isolation_and_scan_state_machine(tmp_path: Path) -> None:
    url = _database_url(tmp_path)
    inventory = InventoryRepository(url)
    inventory.create_schema()

    alpha = inventory.create_workspace(name="Alpha")
    beta = inventory.create_workspace(name="Beta")
    asset = inventory.create_asset(
        workspace_id=alpha.id,
        name="Public API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="example.com:443",
        context=ScanContext(internet_exposed=True, asset_criticality=8),
        tags={"owner": "platform"},
    )

    assert inventory.get_asset(workspace_id=alpha.id, asset_id=asset.id) is not None
    assert inventory.get_asset(workspace_id=beta.id, asset_id=asset.id) is None

    job = inventory.create_scan_job(
        workspace_id=alpha.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )
    running = inventory.transition_scan_job(
        workspace_id=alpha.id,
        job_id=job.id,
        expected=ScanStatus.QUEUED,
        target=ScanStatus.RUNNING,
    )
    assert running.status == ScanStatus.RUNNING
    assert running.started_at is not None

    succeeded = inventory.transition_scan_job(
        workspace_id=alpha.id,
        job_id=job.id,
        expected=ScanStatus.RUNNING,
        target=ScanStatus.SUCCEEDED,
        findings_count=3,
    )
    assert succeeded.status == ScanStatus.SUCCEEDED
    assert succeeded.findings_count == 3
    assert succeeded.finished_at is not None

    with pytest.raises(RuntimeError):
        inventory.transition_scan_job(
            workspace_id=alpha.id,
            job_id=job.id,
            expected=ScanStatus.RUNNING,
            target=ScanStatus.FAILED,
        )


def test_finding_scope_isolated_by_workspace(tmp_path: Path) -> None:
    url = _database_url(tmp_path)
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    inventory.create_schema()
    findings.create_schema()

    alpha = inventory.create_workspace(name="Alpha")
    beta = inventory.create_workspace(name="Beta")
    alpha_asset = inventory.create_asset(
        workspace_id=alpha.id,
        name="Alpha source",
        kind=ManagedAssetKind.SOURCE,
        locator="github:alpha/app",
        context=ScanContext(),
    )
    beta_asset = inventory.create_asset(
        workspace_id=beta.id,
        name="Beta source",
        kind=ManagedAssetKind.SOURCE,
        locator="github:beta/app",
        context=ScanContext(),
    )
    alpha_job = inventory.create_scan_job(
        workspace_id=alpha.id,
        asset_id=alpha_asset.id,
        kind=ScanKind.SOURCE,
    )
    beta_job = inventory.create_scan_job(
        workspace_id=beta.id,
        asset_id=beta_asset.id,
        kind=ScanKind.SOURCE,
    )

    findings.upsert_many(
        [_finding(alpha_asset.id, "alpha-finding")],
        workspace_id=alpha.id,
        managed_asset_id=alpha_asset.id,
        scan_job_id=alpha_job.id,
    )
    findings.upsert_many(
        [_finding(beta_asset.id, "beta-finding")],
        workspace_id=beta.id,
        managed_asset_id=beta_asset.id,
        scan_job_id=beta_job.id,
    )

    alpha_findings = findings.list_findings(workspace_id=alpha.id)
    beta_findings = findings.list_findings(workspace_id=beta.id)
    assert [item.observation.id for item in alpha_findings] == ["alpha-finding"]
    assert [item.observation.id for item in beta_findings] == ["beta-finding"]
    assert findings.summary(workspace_id=alpha.id).total_findings == 1
    assert findings.summary(workspace_id=beta.id).total_findings == 1
