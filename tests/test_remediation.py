from datetime import UTC, datetime
from pathlib import Path

import pytest

from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
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
from cryptohawk.domain.remediation import RemediationStatus
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.remediation import RemediationRepository


def _finding(asset_id: str, *, score: int = 78) -> Finding:
    observation = CryptoObservation(
        asset_id=asset_id,
        asset_name="Payments API",
        asset_type=AssetType.TLS_ENDPOINT,
        algorithm="RSA",
        family="RSA",
        primitive=Primitive.PKE,
        key_size=2048,
        evidence=Evidence(source="tls", locator="payments.example.com:443"),
    )
    return Finding(
        observation=observation,
        risk=RiskAssessment(
            observation_id=observation.id,
            score=score,
            severity=Severity.HIGH,
            quantum_status=QuantumStatus.VULNERABLE,
            reasons=["RSA public-key cryptography is vulnerable to a cryptographically relevant quantum computer."],
            migration_target="ML-KEM hybrid deployment",
            migration_strategy="Introduce hybrid key establishment before retiring RSA-only exchange.",
        ),
    )


def _repositories(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'remediation.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    continuous = ContinuousRepository(inventory)
    remediation = RemediationRepository(inventory)
    inventory.create_schema()
    findings.create_schema()
    continuous.create_schema()
    remediation.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Payments API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="payments.example.com:443",
        context=ScanContext(internet_exposed=True, asset_criticality=9, data_lifetime_years=8),
    )
    return inventory, findings, continuous, remediation, workspace, asset


def _successful_scan(
    inventory: InventoryRepository,
    findings: FindingRepository,
    continuous: ContinuousRepository,
    *,
    workspace_id: str,
    asset_id: str,
    raw_findings: list[Finding],
    completed_at: datetime,
):
    job = inventory.create_scan_job(
        workspace_id=workspace_id,
        asset_id=asset_id,
        kind=ScanKind.TLS,
    )
    inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job.id,
        expected=ScanStatus.QUEUED,
        target=ScanStatus.RUNNING,
    )
    prepared = continuous.prepare_findings(job.id, raw_findings)
    findings.upsert_many(
        prepared,
        workspace_id=workspace_id,
        managed_asset_id=asset_id,
        scan_job_id=job.id,
    )
    continuous.record_successful_scan(
        workspace_id=workspace_id,
        asset_id=asset_id,
        scan_job_id=job.id,
        findings=prepared,
        now=completed_at,
    )
    completed = inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job.id,
        expected=ScanStatus.RUNNING,
        target=ScanStatus.SUCCEEDED,
        findings_count=len(prepared),
    )
    return completed, prepared


def test_migration_item_uses_stable_observation_identity(tmp_path: Path) -> None:
    inventory, findings, continuous, remediation, workspace, asset = _repositories(tmp_path)
    job, prepared = _successful_scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        raw_findings=[_finding(asset.id)],
        completed_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    finding = prepared[0]

    item = remediation.create_from_finding(
        workspace_id=workspace.id,
        finding_id=finding.observation.id,
        created_by="user:owner",
        owner="Platform Security",
    )

    assert item.source_scan_job_id == job.id
    assert item.observation_fingerprint == continuous.observation_fingerprint(finding)
    assert item.priority.value == "high"
    assert item.target_algorithm == "ML-KEM hybrid deployment"
    assert item.source_finding.observation.algorithm == "RSA"

    with pytest.raises(ValueError, match="already exists"):
        remediation.create_from_finding(
            workspace_id=workspace.id,
            finding_id=finding.observation.id,
            created_by="user:owner",
        )


def test_workflow_rejects_manual_verified_state_and_requires_risk_reason(tmp_path: Path) -> None:
    inventory, findings, continuous, remediation, workspace, asset = _repositories(tmp_path)
    _, prepared = _successful_scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        raw_findings=[_finding(asset.id)],
        completed_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    item = remediation.create_from_finding(
        workspace_id=workspace.id,
        finding_id=prepared[0].observation.id,
        created_by="user:owner",
    )

    with pytest.raises(ValueError, match="rescan verification"):
        remediation.update_item(
            workspace_id=workspace.id,
            item_id=item.id,
            changes={"status": RemediationStatus.VERIFIED.value},
        )

    with pytest.raises(ValueError, match="acceptance reason"):
        remediation.update_item(
            workspace_id=workspace.id,
            item_id=item.id,
            changes={"status": RemediationStatus.ACCEPTED_RISK.value},
        )

    accepted = remediation.update_item(
        workspace_id=workspace.id,
        item_id=item.id,
        changes={
            "status": RemediationStatus.ACCEPTED_RISK.value,
            "acceptance_reason": "Compensating control approved through the 2026 migration window.",
        },
    )
    assert accepted.status == RemediationStatus.ACCEPTED_RISK
    assert accepted.acceptance_reason


def test_rescan_verification_reopens_when_present_and_verifies_when_resolved(tmp_path: Path) -> None:
    inventory, findings, continuous, remediation, workspace, asset = _repositories(tmp_path)
    _, source_findings = _successful_scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        raw_findings=[_finding(asset.id)],
        completed_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    item = remediation.create_from_finding(
        workspace_id=workspace.id,
        finding_id=source_findings[0].observation.id,
        created_by="user:owner",
    )
    item = remediation.update_item(
        workspace_id=workspace.id,
        item_id=item.id,
        changes={"status": RemediationStatus.IN_PROGRESS.value},
    )
    item = remediation.update_item(
        workspace_id=workspace.id,
        item_id=item.id,
        changes={"status": RemediationStatus.READY_FOR_VERIFICATION.value},
    )

    present_job, _ = _successful_scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        raw_findings=[_finding(asset.id, score=72)],
        completed_at=datetime(2026, 8, 15, 9, 0, tzinfo=UTC),
    )
    present = remediation.verify(
        workspace_id=workspace.id,
        item_id=item.id,
        verification_job_id=present_job.id,
    )
    assert present.verified is False
    assert present.outcome == "still-present"
    assert present.item.status == RemediationStatus.IN_PROGRESS
    assert present.item.verification_evidence["risk_score"] == 72

    ready = remediation.update_item(
        workspace_id=workspace.id,
        item_id=item.id,
        changes={"status": RemediationStatus.READY_FOR_VERIFICATION.value},
    )
    assert ready.status == RemediationStatus.READY_FOR_VERIFICATION

    resolved_job, _ = _successful_scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        raw_findings=[],
        completed_at=datetime(2026, 8, 15, 10, 0, tzinfo=UTC),
    )
    resolved = remediation.verify(
        workspace_id=workspace.id,
        item_id=item.id,
        verification_job_id=resolved_job.id,
    )
    assert resolved.verified is True
    assert resolved.outcome == "resolved"
    assert resolved.item.status == RemediationStatus.VERIFIED
    assert resolved.item.verified_at is not None
    assert resolved.item.verification_evidence["observation_fingerprint"] == item.observation_fingerprint
