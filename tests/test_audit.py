from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.middleware as middleware_module
from cryptohawk.domain.audit import AuditEvent, AuditOutcome
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository


def _repos(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'audit.db'}"
    inventory = InventoryRepository(url)
    audit = AuditRepository(inventory)
    audit.create_schema()
    return inventory, audit


def test_audit_events_are_append_only_and_workspace_scoped(tmp_path: Path) -> None:
    inventory, audit = _repos(tmp_path)
    alpha = inventory.create_workspace(name="Alpha")
    beta = inventory.create_workspace(name="Beta")
    alpha_event = AuditEvent(
        workspace_id=alpha.id,
        request_id="req-alpha",
        actor_kind="session",
        actor_id="session-1",
        user_id="user-1",
        action="api.post.create_asset",
        resource_type="api-route",
        resource_id="/api/v1/workspaces/{workspace_id}/assets",
        outcome=AuditOutcome.SUCCESS,
        metadata={"method": "POST", "status_code": 201},
    )
    beta_event = AuditEvent(
        workspace_id=beta.id,
        request_id="req-beta",
        actor_kind="api-key",
        actor_id="key-1",
        action="api.post.enqueue_managed_scan",
        resource_type="api-route",
        outcome=AuditOutcome.DENIED,
        metadata={"method": "POST", "status_code": 403},
    )
    audit.append(alpha_event)
    audit.append(beta_event)

    assert [event.id for event in audit.list_workspace(alpha.id)] == [alpha_event.id]
    assert [event.id for event in audit.list_workspace(beta.id)] == [beta_event.id]


def test_security_middleware_emits_headers_and_tenant_audit(tmp_path: Path, monkeypatch) -> None:
    url = f"sqlite:///{tmp_path / 'api-audit.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    queue = ScanQueueRepository(inventory)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    inventory.create_schema()
    findings.create_schema()
    queue.create_schema()
    auth.create_schema()
    audit.create_schema()

    monkeypatch.setattr(api_module, "inventory", inventory)
    monkeypatch.setattr(api_module, "repo", findings)
    monkeypatch.setattr(api_module, "scan_queue", queue)
    monkeypatch.setattr(api_module, "auth_repo", auth)
    monkeypatch.setattr(api_module, "audit_repo", audit)
    monkeypatch.setattr(auth_module, "inventory", inventory)
    monkeypatch.setattr(auth_module, "auth_repo", auth)
    monkeypatch.setattr(middleware_module, "audit_repo", audit)

    with TestClient(api_module.app) as client:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Request-ID": "bootstrap-request"},
            json={
                "email": "owner@example.com",
                "display_name": "Owner",
                "password": "correct-horse-battery-staple",
                "workspace_name": "Acme",
            },
        )
        assert bootstrap.status_code == 201
        assert bootstrap.headers["x-request-id"] == "bootstrap-request"
        assert bootstrap.headers["x-content-type-options"] == "nosniff"
        assert bootstrap.headers["x-frame-options"] == "DENY"
        assert bootstrap.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in bootstrap.headers["content-security-policy"]

        body = bootstrap.json()
        workspace_id = body["workspace"]["id"]
        token = body["token"]
        asset = client.post(
            f"/api/v1/workspaces/{workspace_id}/assets",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Request-ID": "asset-request",
            },
            json={
                "name": "Public API",
                "kind": "tls-endpoint",
                "locator": "example.com:443",
                "context": {"internet_exposed": True},
            },
        )
        assert asset.status_code == 201

    events = audit.list_workspace(workspace_id)
    assert len(events) == 1
    event = events[0]
    assert event.request_id == "asset-request"
    assert event.actor_kind == "session"
    assert event.user_id == body["user"]["id"]
    assert event.action == "api.post.create_asset"
    assert event.outcome == AuditOutcome.SUCCESS
    assert event.metadata == {"method": "POST", "status_code": 201}
