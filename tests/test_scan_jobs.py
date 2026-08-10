from pathlib import Path

import pytest

from cryptohawk.domain.inventory import ManagedAssetKind, ScanStatus
from cryptohawk.domain.models import (
    AssetType,
    CryptoObservation,
    Evidence,
    Finding,
    Primitive,
    QuantumStatus,
    RiskAssessment,
    ScanContext,
    Severity,
)
from cryptohawk.services.scan_jobs import AssetScanError, ScanJobService
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository


class FakeSourceScanner:
    def scan_text(self, text, *, asset_name="inline", locator="inline"):
        return [
            CryptoObservation(
                asset_id="ephemeral",
                asset_name=asset_name,
                asset_type=AssetType.SOURCE,
                algorithm="RSA-2048",
                family="RSA",
                primitive=Primitive.PKE,
                key_size=2048,
                evidence=Evidence(source="source-code", locator=locator, line=1),
            )
        ]


class FakeRiskEngine:
    def assess(self, observation, context):
        return Finding(
            observation=observation,
            risk=RiskAssessment(
                observation_id=observation.id,
                score=88,
                severity=Severity.HIGH,
                quantum_status=QuantumStatus.VULNERABLE,
                reasons=[f"criticality={context.asset_criticality}"],
                migration_target="ML-KEM",
            ),
        )


class FakeTLSScanner:
    def scan(self, hostname, port=443, timeout=5.0):
        raise AssertionError("TLS scanner should not be used for source asset")


def _repos(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'jobs.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    inventory.create_schema()
    findings.create_schema()
    return inventory, findings


def test_managed_source_scan_persists_scope_and_terminal_job(tmp_path: Path) -> None:
    inventory, findings = _repos(tmp_path)
    workspace = inventory.create_workspace(name="Acme Security")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Payments API",
        kind=ManagedAssetKind.SOURCE,
        locator="github:acme/payments",
        context=ScanContext(asset_criticality=9, data_lifetime_years=7),
    )
    service = ScanJobService(
        inventory,
        findings,
        risk_engine=FakeRiskEngine(),
        source_scanner=FakeSourceScanner(),
        tls_scanner=FakeTLSScanner(),
    )

    job, results = service.run(
        workspace_id=workspace.id,
        asset_id=asset.id,
        source="RSA-2048",
        filename="crypto.py",
    )

    assert job.status == ScanStatus.SUCCEEDED
    assert job.findings_count == 1
    assert results[0].observation.asset_id == asset.id
    scoped = findings.list_findings(workspace_id=workspace.id)
    assert len(scoped) == 1
    assert scoped[0].observation.asset_id == asset.id


def test_failed_scan_is_recorded(tmp_path: Path) -> None:
    inventory, findings = _repos(tmp_path)
    workspace = inventory.create_workspace(name="Acme Security")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Payments API",
        kind=ManagedAssetKind.SOURCE,
        locator="github:acme/payments",
        context=ScanContext(),
    )
    service = ScanJobService(
        inventory,
        findings,
        risk_engine=FakeRiskEngine(),
        source_scanner=FakeSourceScanner(),
        tls_scanner=FakeTLSScanner(),
    )

    with pytest.raises(AssetScanError):
        service.run(workspace_id=workspace.id, asset_id=asset.id)

    jobs = inventory.list_scan_jobs(workspace_id=workspace.id)
    assert len(jobs) == 1
    assert jobs[0].status == ScanStatus.FAILED
    assert "source content is required" in (jobs[0].error_message or "")
