from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.continuous as continuous_api
import cryptohawk.api.middleware as middleware_module
import cryptohawk.api.remediation as remediation_api
from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
from cryptohawk.domain.models import (
    AssetType,
    CryptoObservation,
    Evidence,
    Primitive,
    QuantumStatus,
    RiskAssessment,
    ScanContext,
    Severity,
)
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository
from cryptohawk.storage.remediation import RemediationRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-remediation.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    continuous = ContinuousRepository(inventory)
    remediation = RemediationRepository(inventory)

    inventory.create_schema()
    findings.create_schema()
    quota.create_schema()
    queue.create_schema()
    auth.create_schema()
    audit.create_schema()
    continuous.create_schema()
    remediation.create_schema()

    monkeypatch.setattr(api_module, "inventory", inventory)
    monkeypatch.setattr(api_module, "repo", findings)
    monkeypatch.setattr(api_module, "quota_repo", quota)
    monkeypatch.setattr(api_module, "scan_queue", queue)
    monkeypatch.setattr(api_module, "auth_repo", auth)
    monkeypatch.setattr(api_module, "audit_repo", audit)
    monkeypatch.setattr(api_module, "continuous_repo", continuous)
    monkeypatch.setattr(auth_module, "inventory", inventory)
    monkeypatch.setattr(auth_module, "auth_repo", auth)
    monkeypatch.setattr(middleware_module, "audit_repo", audit)
    monkeypatch.setattr(continuous_api, "inventory", inventory)
    monkeypatch.setattr(continuous_api, "continuous_repo", continuous)
    monkeypatch.setattr(remediation_api, "inventory", inventory)
    monkeypatch.setattr(remediation_api, "remediation_repo", remediation)
    monkeypatch.setattr(remediation_api, "_schema_ready", True)
    monkeypatch.setattr(
        api_module,
        "scan_jobs",
        ScanJobService(
            inventory,
            findings,
            risk_engine=RiskEngine(),
            source_scanner=SourceScanner(),
            tls_scanner=TLSScanner(),
            quota=quota,
            history=continuous,
        ),
    )
    return TestClient(api_module.app), inventory, findings, auth, continuous


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _bootstrap(client: TestClient) -> tuple[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "email": "owner@example.com",
            "display_name": "Owner",
            "password": "correct-horse-battery-staple",
            "workspace_name": "Acme",
        },
    )
    assert response.status_code == 201
    body = response.json()
    return body["token"], body["workspace"]["id"]


def _seed_finding(
    inventory: InventoryRepository,
    findings: FindingRepository,
    continuous: ContinuousRepository,
    workspace_id: str,
):
    asset = inventory.create_asset(
        workspace_id=workspace_id,
        name="Payments API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="payments.example.com:443",
        context=ScanContext(internet_exposed=True, asset_criticality=9, data_lifetime_years=8),
    )
    job = inventory.create_scan_job(
        workspace_id=workspace_id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )
    inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job.id,
        expected=ScanStatus.QUEUED,
        target=ScanStatus.RUNNING,
    )
    observation = CryptoObservation(
        asset_id=asset.id,
        asset_name=asset.name,
        asset_type=AssetType.TLS_ENDPOINT,
        algorithm="RSA",
        family="RSA",
        primitive=Primitive.PKE,
        key_size=2048,
        evidence=Evidence(source="tls", locator=asset.locator),
    )
    finding = RiskAssessment(
        observation_id=observation.id,
        score=80,
        severity=Severity.CRITICAL,
        quantum_status=QuantumStatus.VULNERABLE,
        reasons=["Quantum-vulnerable public-key cryptography."],
        migration_target="ML-KEM hybrid deployment",
    )
    from cryptohawk.domain.models import Finding

    prepared = continuous.prepare_findings(job.id, [Finding(observation=observation, risk=finding)])
    findings.upsert_many(
        prepared,
        workspace_id=workspace_id,
        managed_asset_id=asset.id,
        scan_job_id=job.id,
    )
    continuous.record_successful_scan(
        workspace_id=workspace_id,
        asset_id=asset.id,
        scan_job_id=job.id,
        findings=prepared,
        now=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job.id,
        expected=ScanStatus.RUNNING,
        target=ScanStatus.SUCCEEDED,
        findings_count=1,
    )
    return asset, prepared[0]


def test_analyst_can_create_and_update_migration_work(tmp_path: Path, monkeypatch) -> None:
    client, inventory, findings, _, continuous = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    asset, finding = _seed_finding(inventory, findings, continuous, workspace_id)

    member = client.post(
        f"/api/v1/workspaces/{workspace_id}/members",
        headers=_bearer(owner_token),
        json={
            "email": "analyst@example.com",
            "display_name": "Analyst",
            "password": "analyst-secure-password",
            "role": "analyst",
        },
    )
    assert member.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "analyst-secure-password"},
    )
    analyst_token = login.json()["token"]

    created = client.post(
        f"/api/v1/workspaces/{workspace_id}/migration-items",
        headers=_bearer(analyst_token),
        json={
            "finding_id": finding.observation.id,
            "owner": "Platform Security",
            "due_date": "2026-10-31",
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["asset_id"] == asset.id
    assert body["priority"] == "critical"
    assert body["status"] == "open"
    assert body["target_algorithm"] == "ML-KEM hybrid deployment"

    updated = client.post(
        f"/api/v1/workspaces/{workspace_id}/migration-items/{body['id']}/update",
        headers=_bearer(analyst_token),
        json={"status": "in-progress", "notes": "Hybrid rollout started."},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in-progress"

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/migration-items",
        headers=_bearer(analyst_token),
    )
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [body["id"]]


def test_viewer_is_read_only_and_workspace_boundary_is_enforced(tmp_path: Path, monkeypatch) -> None:
    client, inventory, findings, auth, continuous = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    _, finding = _seed_finding(inventory, findings, continuous, workspace_id)

    created = client.post(
        f"/api/v1/workspaces/{workspace_id}/migration-items",
        headers=_bearer(owner_token),
        json={"finding_id": finding.observation.id},
    )
    assert created.status_code == 201

    viewer = client.post(
        f"/api/v1/workspaces/{workspace_id}/members",
        headers=_bearer(owner_token),
        json={
            "email": "viewer@example.com",
            "display_name": "Viewer",
            "password": "viewer-secure-password",
            "role": "viewer",
        },
    )
    assert viewer.status_code == 201
    viewer_login = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": "viewer-secure-password"},
    )
    viewer_token = viewer_login.json()["token"]

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/migration-items",
        headers=_bearer(viewer_token),
    )
    assert listed.status_code == 200

    denied = client.post(
        f"/api/v1/workspaces/{workspace_id}/migration-items",
        headers=_bearer(viewer_token),
        json={"finding_id": finding.observation.id},
    )
    assert denied.status_code == 403

    owner_principal = auth.authenticate(owner_token)
    other_workspace = auth.create_workspace(principal=owner_principal, name="Other")
    outside = client.get(
        f"/api/v1/workspaces/{other_workspace.id}/migration-items",
        headers=_bearer(viewer_token),
    )
    assert outside.status_code == 403
