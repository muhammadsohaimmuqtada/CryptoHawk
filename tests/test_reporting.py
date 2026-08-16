from datetime import UTC, date, datetime
from pathlib import Path

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
from cryptohawk.services.reporting import ReportingService
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.remediation import RemediationRepository


def _finding(asset_id: str, asset_name: str) -> Finding:
    observation = CryptoObservation(
        asset_id=asset_id,
        asset_name=asset_name,
        asset_type=AssetType.TLS_ENDPOINT,
        algorithm="RSA-2048",
        family="RSA",
        primitive=Primitive.PKE,
        key_size=2048,
        confidence=0.98,
        evidence=Evidence(source="tls", locator="=HYPERLINK(\"https://evil.invalid\")"),
    )
    return Finding(
        observation=observation,
        risk=RiskAssessment(
            observation_id=observation.id,
            score=82,
            severity=Severity.CRITICAL,
            quantum_status=QuantumStatus.VULNERABLE,
            reasons=["Quantum-vulnerable public-key cryptography."],
            migration_target="ML-KEM hybrid",
            migration_strategy="Deploy hybrid key establishment.",
            policy_name="Strict Modern",
            policy_version=1,
            policy_status="fail",
            policy_controls=["minimum-rsa-bits", "quantum-vulnerable"],
            policy_reasons=["RSA does not satisfy the active baseline."],
            policy_rules_hash="a" * 64,
        ),
    )


def _state(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'reporting.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    continuous = ContinuousRepository(inventory)
    remediation = RemediationRepository(inventory)
    inventory.create_schema()
    findings.create_schema()
    continuous.create_schema()
    remediation.create_schema()
    workspace = inventory.create_workspace(name="Acme Security")
    other = inventory.create_workspace(name="Other Tenant")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="=Payments API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="=payments.example.com:443",
        context=ScanContext(
            internet_exposed=True,
            asset_criticality=10,
            data_lifetime_years=8,
            environment="production",
        ),
    )
    return inventory, findings, continuous, remediation, workspace, other, asset


def _scan(
    inventory: InventoryRepository,
    findings: FindingRepository,
    continuous: ContinuousRepository,
    *,
    workspace_id: str,
    asset_id: str,
    values: list[Finding],
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
    prepared = continuous.prepare_findings(job.id, values)
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
    inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job.id,
        expected=ScanStatus.RUNNING,
        target=ScanStatus.SUCCEEDED,
        findings_count=len(prepared),
    )
    return job, prepared


def test_reports_use_active_state_policy_remediation_and_drift(tmp_path: Path) -> None:
    inventory, findings, continuous, remediation, workspace, _, asset = _state(tmp_path)
    now = datetime(2026, 8, 16, 8, 0, tzinfo=UTC)
    _, prepared = _scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        values=[_finding(asset.id, asset.name)],
        completed_at=now,
    )
    remediation.create_from_finding(
        workspace_id=workspace.id,
        finding_id=prepared[0].observation.id,
        created_by="user:owner",
        owner=None,
        due_date=date(2026, 8, 15),
    )

    service = ReportingService(inventory)
    executive = service.executive_report(workspace.id, now=now)
    engineering = service.engineering_report(workspace.id, now=now)

    assert executive.summary.assets_total == 1
    assert executive.summary.active_findings == 1
    assert executive.summary.severity["critical"] == 1
    assert executive.summary.quantum["vulnerable"] == 1
    assert executive.summary.policy["fail"] == 1
    assert executive.summary.remediation["open"] == 1
    assert executive.summary.overdue_remediation == 1
    assert executive.summary.unowned_remediation == 1
    assert executive.summary.drift_30d["introduced"] == 1
    assert len(executive.top_priorities) == 1
    assert engineering.findings[0].evidence_hash
    assert engineering.findings[0].remediation_status == "open"
    assert engineering.metadata.policy.rules_hash


def test_engineering_csv_neutralizes_spreadsheet_formulas(tmp_path: Path) -> None:
    inventory, findings, continuous, _, workspace, _, asset = _state(tmp_path)
    _scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        values=[_finding(asset.id, asset.name)],
        completed_at=datetime(2026, 8, 16, 8, 0, tzinfo=UTC),
    )

    csv_export = ReportingService(inventory).engineering_csv(workspace.id)

    assert "'=Payments API" in csv_export
    assert "'=payments.example.com:443" in csv_export
    assert "'=HYPERLINK" in csv_export


def test_reports_are_tenant_scoped_and_cbom_contains_only_current_state(tmp_path: Path) -> None:
    inventory, findings, continuous, _, workspace, other, asset = _state(tmp_path)
    _scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        values=[_finding(asset.id, asset.name)],
        completed_at=datetime(2026, 8, 16, 8, 0, tzinfo=UTC),
    )
    service = ReportingService(inventory)

    assert len(service.engineering_report(workspace.id).findings) == 1
    assert service.engineering_report(other.id).findings == []
    assert len(service.current_cbom(workspace.id)["components"]) == 1
    assert service.current_cbom(other.id)["components"] == []

    _scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        values=[],
        completed_at=datetime(2026, 8, 16, 9, 0, tzinfo=UTC),
    )
    assert service.engineering_report(workspace.id).findings == []
    assert service.current_cbom(workspace.id)["components"] == []


def test_executive_html_escapes_workspace_and_asset_text(tmp_path: Path) -> None:
    inventory, findings, continuous, _, workspace, _, asset = _state(tmp_path)
    _scan(
        inventory,
        findings,
        continuous,
        workspace_id=workspace.id,
        asset_id=asset.id,
        values=[_finding(asset.id, "<script>alert(1)</script>")],
        completed_at=datetime(2026, 8, 16, 8, 0, tzinfo=UTC),
    )

    report = ReportingService(inventory).executive_html(workspace.id)

    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "https://evil.invalid" not in report
