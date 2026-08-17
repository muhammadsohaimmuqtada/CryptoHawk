from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.middleware as middleware_module
import cryptohawk.api.retention as retention_module
from cryptohawk.domain.inventory import ScanStatus
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.audit import AuditEventRecord, AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.retention import WorkspaceRetentionRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-retention.db'}"
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
    return TestClient(api_module.app), inventory, audit


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _delete(client: TestClient, workspace_id: str, token: str, slug: str):
    return client.request(
        "DELETE",
        f"/api/v1/workspaces/{workspace_id}",
        headers=_bearer(token),
        json={"confirm_slug": slug},
    )


def test_workspace_purge_api_is_owner_session_only_and_audit_safe(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, inventory, audit = _client(tmp_path, monkeypatch)
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

    wrong_confirmation = _delete(client, workspace_id, owner_token, "wrong-slug")
    assert wrong_confirmation.status_code == 409

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
    analyst_token = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "analyst-secure-password"},
    ).json()["token"]
    assert _delete(client, workspace_id, analyst_token, "acme").status_code == 403

    admin_key = client.post(
        f"/api/v1/workspaces/{workspace_id}/api-keys",
        headers=_bearer(owner_token),
        json={"name": "automation", "role": "admin"},
    )
    assert admin_key.status_code == 201
    assert (
        _delete(client, workspace_id, admin_key.json()["token"], "acme").status_code
        == 403
    )

    asset = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets",
        headers=_bearer(owner_token),
        json={
            "name": "Public API",
            "kind": "tls-endpoint",
            "locator": "example.com:443",
            "context": {"internet_exposed": True},
        },
    )
    assert asset.status_code == 201
    queued = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets/{asset.json()['id']}/scan-jobs",
        headers=_bearer(owner_token),
        json={"max_attempts": 2},
    )
    assert queued.status_code == 202
    job_id = queued.json()["id"]
    inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job_id,
        expected=ScanStatus.QUEUED,
        target=ScanStatus.RUNNING,
    )

    blocked = _delete(client, workspace_id, owner_token, "acme")
    assert blocked.status_code == 409
    assert "running scans" in blocked.json()["detail"]

    inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job_id,
        expected=ScanStatus.RUNNING,
        target=ScanStatus.FAILED,
        error_message="test completion",
    )
    deleted = _delete(client, workspace_id, owner_token, "acme")
    assert deleted.status_code == 204
    assert inventory.get_workspace(workspace_id) is None
    assert audit.list_workspace(workspace_id) == []

    # The successful DELETE is still auditable, but it is workspace-less so the
    # purge does not recreate tenant-scoped records after commit.
    with inventory.SessionLocal() as session:
        tombstone = session.scalar(
            select(AuditEventRecord)
            .where(
                AuditEventRecord.workspace_id.is_(None),
                AuditEventRecord.action == "api.delete.purge_workspace",
            )
            .order_by(AuditEventRecord.created_at.desc())
        )
        assert tombstone is not None
        assert tombstone.user_id is not None

    workspaces = client.get("/api/v1/workspaces", headers=_bearer(owner_token))
    assert workspaces.status_code == 200
    assert workspaces.json() == []
