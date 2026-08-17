from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.middleware as middleware_module
import cryptohawk.api.retention as retention_module
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.retention import WorkspaceRetentionRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-retention-policy.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    queue = ScanQueueRepository(inventory)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    retention = WorkspaceRetentionRepository(inventory)
    inventory.create_schema()

    monkeypatch.setattr(api_module, "inventory", inventory)
    monkeypatch.setattr(api_module, "repo", findings)
    monkeypatch.setattr(api_module, "scan_queue", queue)
    monkeypatch.setattr(api_module, "auth_repo", auth)
    monkeypatch.setattr(api_module, "audit_repo", audit)
    monkeypatch.setattr(auth_module, "inventory", inventory)
    monkeypatch.setattr(auth_module, "auth_repo", auth)
    monkeypatch.setattr(middleware_module, "audit_repo", audit)
    monkeypatch.setattr(retention_module, "inventory", inventory)
    monkeypatch.setattr(retention_module, "retention_repo", retention)
    monkeypatch.setattr(
        api_module,
        "scan_jobs",
        ScanJobService(
            inventory,
            findings,
            risk_engine=RiskEngine(),
            source_scanner=SourceScanner(),
            tls_scanner=TLSScanner(),
        ),
    )
    return TestClient(api_module.app)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_retention_policy_is_owner_controlled_and_viewer_readable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client = _client(tmp_path, monkeypatch)
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "email": "owner@example.com",
            "display_name": "Owner",
            "password": "correct-horse-battery-staple",
            "workspace_name": "Acme",
            "workspace_slug": "acme",
        },
    )
    assert bootstrap.status_code == 201
    owner_token = bootstrap.json()["token"]
    workspace_id = bootstrap.json()["workspace"]["id"]

    initial = client.get(
        f"/api/v1/workspaces/{workspace_id}/retention-policy",
        headers=_bearer(owner_token),
    )
    assert initial.status_code == 200
    assert initial.json()["enabled"] is False

    configured = client.post(
        f"/api/v1/workspaces/{workspace_id}/retention-policy",
        headers=_bearer(owner_token),
        json={
            "enabled": True,
            "evidence_retention_days": 90,
            "audit_retention_days": 365,
            "sweep_interval_hours": 24,
        },
    )
    assert configured.status_code == 200
    assert configured.json()["enabled"] is True
    assert configured.json()["evidence_retention_days"] == 90

    member = client.post(
        f"/api/v1/workspaces/{workspace_id}/members",
        headers=_bearer(owner_token),
        json={
            "email": "viewer@example.com",
            "display_name": "Viewer",
            "password": "viewer-secure-password",
            "role": "viewer",
        },
    )
    assert member.status_code == 201
    viewer_token = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": "viewer-secure-password"},
    ).json()["token"]

    viewer_read = client.get(
        f"/api/v1/workspaces/{workspace_id}/retention-policy",
        headers=_bearer(viewer_token),
    )
    assert viewer_read.status_code == 200
    assert viewer_read.json()["audit_retention_days"] == 365

    viewer_write = client.post(
        f"/api/v1/workspaces/{workspace_id}/retention-policy",
        headers=_bearer(viewer_token),
        json={
            "enabled": False,
            "evidence_retention_days": 30,
            "audit_retention_days": 30,
            "sweep_interval_hours": 24,
        },
    )
    assert viewer_write.status_code == 403

    admin_key = client.post(
        f"/api/v1/workspaces/{workspace_id}/api-keys",
        headers=_bearer(owner_token),
        json={"name": "automation", "role": "admin"},
    )
    assert admin_key.status_code == 201
    key_write = client.post(
        f"/api/v1/workspaces/{workspace_id}/retention-policy",
        headers=_bearer(admin_key.json()["token"]),
        json={
            "enabled": False,
            "evidence_retention_days": 30,
            "audit_retention_days": 30,
            "sweep_interval_hours": 24,
        },
    )
    assert key_write.status_code == 403

    manual_run = client.post(
        f"/api/v1/workspaces/{workspace_id}/retention-policy/run",
        headers=_bearer(owner_token),
    )
    assert manual_run.status_code == 200
    assert manual_run.json()["workspace_id"] == workspace_id
