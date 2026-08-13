from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.continuous as continuous_api
import cryptohawk.api.middleware as middleware_module
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


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-continuous.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    continuous = ContinuousRepository(inventory)

    inventory.create_schema()
    findings.create_schema()
    quota.create_schema()
    queue.create_schema()
    auth.create_schema()
    audit.create_schema()
    continuous.create_schema()

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
    return TestClient(api_module.app), auth, continuous


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


def _create_asset(
    client: TestClient,
    token: str,
    workspace_id: str,
    *,
    kind: str = "tls-endpoint",
    locator: str = "example.com:443",
) -> str:
    response = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets",
        headers=_bearer(token),
        json={
            "name": "Public API",
            "kind": kind,
            "locator": locator,
            "context": {"internet_exposed": True},
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_owner_can_manage_schedule_and_view_continuous_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    asset_id = _create_asset(client, owner_token, workspace_id)

    created = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/schedule",
        headers=_bearer(owner_token),
        json={"interval_minutes": 15, "max_attempts": 4},
    )
    assert created.status_code == 201
    schedule_id = created.json()["id"]
    assert created.json()["interval_seconds"] == 900
    assert created.json()["max_attempts"] == 4

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/schedules",
        headers=_bearer(owner_token),
    )
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [schedule_id]

    paused = client.post(
        f"/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/pause",
        headers=_bearer(owner_token),
    )
    assert paused.status_code == 200
    assert paused.json()["enabled"] is False

    resumed = client.post(
        f"/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/resume",
        headers=_bearer(owner_token),
    )
    assert resumed.status_code == 200
    assert resumed.json()["enabled"] is True

    assert (
        client.get(
            f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan-history",
            headers=_bearer(owner_token),
        ).json()
        == []
    )
    assert (
        client.get(
            f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/crypto-state",
            headers=_bearer(owner_token),
        ).json()
        == []
    )
    assert (
        client.get(
            f"/api/v1/workspaces/{workspace_id}/drift-events",
            headers=_bearer(owner_token),
        ).json()
        == []
    )

    deleted = client.delete(
        f"/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}",
        headers=_bearer(owner_token),
    )
    assert deleted.status_code == 204


def test_analyst_can_view_but_cannot_manage_schedules(tmp_path: Path, monkeypatch) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    asset_id = _create_asset(client, owner_token, workspace_id)

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
        json={
            "email": "analyst@example.com",
            "password": "analyst-secure-password",
        },
    )
    assert login.status_code == 200
    analyst_token = login.json()["token"]

    create = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/schedule",
        headers=_bearer(analyst_token),
        json={"interval_minutes": 60},
    )
    assert create.status_code == 403

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/schedules",
        headers=_bearer(analyst_token),
    )
    assert listed.status_code == 200


def test_source_schedule_is_rejected_until_repository_collector_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    asset_id = _create_asset(
        client,
        owner_token,
        workspace_id,
        kind="source",
        locator="repository-placeholder",
    )

    response = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/schedule",
        headers=_bearer(owner_token),
        json={"interval_minutes": 60},
    )
    assert response.status_code == 422
    assert "repository-backed source collector" in response.json()["detail"]
