from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.middleware as middleware_module
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-quotas.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
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
        ),
    )
    monkeypatch.setattr(api_module.settings, "allow_legacy_global_api", False)
    monkeypatch.setattr(api_module.settings, "principal_requests_per_minute", 100)
    monkeypatch.setattr(api_module.settings, "workspace_requests_per_minute", 100)
    monkeypatch.setattr(api_module.settings, "login_attempts_per_15_minutes", 10)
    monkeypatch.setattr(api_module.settings, "bootstrap_attempts_per_hour", 5)
    monkeypatch.setattr(api_module.settings, "scan_submissions_per_minute", 30)
    monkeypatch.setattr(api_module.settings, "workspace_scan_concurrency", 4)
    return TestClient(api_module.app), auth, quota


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


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_login_attempts_are_throttled_with_retry_after(tmp_path: Path, monkeypatch) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    with client:
        _bootstrap(client)
        monkeypatch.setattr(api_module.settings, "login_attempts_per_15_minutes", 1)
        first = client.post(
            "/api/v1/auth/login",
            json={"email": "OWNER@example.com", "password": "wrong-password"},
        )
        second = client.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "wrong-password"},
        )

    assert first.status_code == 401
    assert second.status_code == 429
    assert int(second.headers["retry-after"]) >= 1


def test_workspace_request_budget_is_shared_and_enforced(tmp_path: Path, monkeypatch) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    with client:
        token, workspace_id = _bootstrap(client)
        monkeypatch.setattr(api_module.settings, "workspace_requests_per_minute", 1)
        first = client.get(
            f"/api/v1/workspaces/{workspace_id}/assets",
            headers=_bearer(token),
        )
        second = client.get(
            f"/api/v1/workspaces/{workspace_id}/assets",
            headers=_bearer(token),
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert int(second.headers["retry-after"]) >= 1


def test_scan_submission_budget_is_separate_from_general_requests(
    tmp_path: Path, monkeypatch
) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    with client:
        token, workspace_id = _bootstrap(client)
        asset = client.post(
            f"/api/v1/workspaces/{workspace_id}/assets",
            headers=_bearer(token),
            json={
                "name": "Public API",
                "kind": "tls-endpoint",
                "locator": "example.com:443",
                "context": {"internet_exposed": True},
            },
        )
        assert asset.status_code == 201
        asset_id = asset.json()["id"]
        monkeypatch.setattr(api_module.settings, "scan_submissions_per_minute", 1)

        first = client.post(
            f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan-jobs",
            headers=_bearer(token),
            json={"max_attempts": 2},
        )
        second = client.post(
            f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan-jobs",
            headers=_bearer(token),
            json={"max_attempts": 2},
        )

    assert first.status_code == 202
    assert second.status_code == 429
    assert int(second.headers["retry-after"]) >= 1


def test_scan_capacity_endpoint_reports_shared_running_slots(tmp_path: Path, monkeypatch) -> None:
    client, _, quota = _client(tmp_path, monkeypatch)
    with client:
        token, workspace_id = _bootstrap(client)
        monkeypatch.setattr(api_module.settings, "workspace_scan_concurrency", 2)
        assert quota.acquire_scan_slot(workspace_id=workspace_id, limit=2) is True
        response = client.get(
            f"/api/v1/workspaces/{workspace_id}/scan-capacity",
            headers=_bearer(token),
        )

    assert response.status_code == 200
    assert response.json() == {
        "workspace_id": workspace_id,
        "active_scans": 1,
        "limit": 2,
        "available": 1,
    }
