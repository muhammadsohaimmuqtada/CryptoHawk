from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
from cryptohawk.domain.auth import WorkspaceRole
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-auth.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    queue = ScanQueueRepository(inventory)
    auth = AuthRepository(inventory)
    inventory.create_schema()
    findings.create_schema()
    queue.create_schema()
    auth.create_schema()

    monkeypatch.setattr(api_module, "inventory", inventory)
    monkeypatch.setattr(api_module, "repo", findings)
    monkeypatch.setattr(api_module, "scan_queue", queue)
    monkeypatch.setattr(api_module, "auth_repo", auth)
    monkeypatch.setattr(auth_module, "inventory", inventory)
    monkeypatch.setattr(auth_module, "auth_repo", auth)
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
    monkeypatch.setattr(api_module.settings, "allow_legacy_global_api", False)
    return TestClient(api_module.app), auth


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_api_requires_identity_and_enforces_workspace_roles(tmp_path: Path, monkeypatch) -> None:
    client, auth = _client(tmp_path, monkeypatch)

    assert client.get("/api/v1/auth/status").json() == {"bootstrap_required": True}
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "email": "owner@example.com",
            "display_name": "Owner",
            "password": "correct-horse-battery-staple",
            "workspace_name": "Acme",
        },
    )
    assert bootstrap.status_code == 201
    owner_body = bootstrap.json()
    owner_token = owner_body["token"]
    workspace_id = owner_body["workspace"]["id"]

    assert client.get("/api/v1/workspaces").status_code == 401
    assert client.get("/api/v1/findings").status_code == 404
    workspaces = client.get("/api/v1/workspaces", headers=_bearer(owner_token))
    assert workspaces.status_code == 200
    assert [workspace["id"] for workspace in workspaces.json()] == [workspace_id]

    asset = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets",
        headers=_bearer(owner_token),
        json={
            "name": "Public API",
            "kind": "tls-endpoint",
            "locator": "example.com:443",
            "context": {"internet_exposed": True},
            "tags": {"owner": "platform"},
        },
    )
    assert asset.status_code == 201
    asset_id = asset.json()["id"]

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

    analyst_login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "analyst-secure-password"},
    )
    assert analyst_login.status_code == 200
    analyst_token = analyst_login.json()["token"]

    assert (
        client.get(
            f"/api/v1/workspaces/{workspace_id}/assets",
            headers=_bearer(analyst_token),
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/workspaces/{workspace_id}/assets",
            headers=_bearer(analyst_token),
            json={
                "name": "Forbidden asset",
                "kind": "tls-endpoint",
                "locator": "other.example.com:443",
                "context": {"internet_exposed": True},
            },
        ).status_code
        == 403
    )
    queued = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan-jobs",
        headers=_bearer(analyst_token),
        json={"max_attempts": 2},
    )
    assert queued.status_code == 202

    owner_principal = auth.authenticate(owner_token)
    other = auth.create_workspace(principal=owner_principal, name="Research")
    assert (
        client.get(
            f"/api/v1/workspaces/{other.id}/assets",
            headers=_bearer(analyst_token),
        ).status_code
        == 403
    )


def test_viewer_api_key_cannot_start_scans_or_cross_workspaces(
    tmp_path: Path, monkeypatch
) -> None:
    client, auth = _client(tmp_path, monkeypatch)
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "email": "owner@example.com",
            "display_name": "Owner",
            "password": "correct-horse-battery-staple",
            "workspace_name": "Acme",
        },
    ).json()
    owner_token = bootstrap["token"]
    workspace_id = bootstrap["workspace"]["id"]

    asset = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets",
        headers=_bearer(owner_token),
        json={
            "name": "Public API",
            "kind": "tls-endpoint",
            "locator": "example.com:443",
            "context": {"internet_exposed": True},
        },
    ).json()

    key = client.post(
        f"/api/v1/workspaces/{workspace_id}/api-keys",
        headers=_bearer(owner_token),
        json={"name": "reporter", "role": "viewer"},
    )
    assert key.status_code == 201
    key_token = key.json()["token"]

    assert (
        client.get(
            f"/api/v1/workspaces/{workspace_id}/findings",
            headers=_bearer(key_token),
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/workspaces/{workspace_id}/assets/{asset['id']}/scan-jobs",
            headers=_bearer(key_token),
            json={"max_attempts": 2},
        ).status_code
        == 403
    )

    owner = auth.authenticate(owner_token)
    other = auth.create_workspace(principal=owner, name="Other")
    assert (
        client.get(
            f"/api/v1/workspaces/{other.id}/findings",
            headers=_bearer(key_token),
        ).status_code
        == 403
    )
