import hashlib
import json
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.middleware as middleware_module
import cryptohawk.api.reporting as reporting_api
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.policy import PolicyRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository
from cryptohawk.storage.remediation import RemediationRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-reporting.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    continuous = ContinuousRepository(inventory)
    policy = PolicyRepository(inventory)
    remediation = RemediationRepository(inventory)

    inventory.create_schema()
    findings.create_schema()
    quota.create_schema()
    queue.create_schema()
    auth.create_schema()
    audit.create_schema()
    continuous.create_schema()
    policy.create_schema()
    remediation.create_schema()

    monkeypatch.setattr(api_module, "inventory", inventory)
    monkeypatch.setattr(api_module, "repo", findings)
    monkeypatch.setattr(api_module, "quota_repo", quota)
    monkeypatch.setattr(api_module, "scan_queue", queue)
    monkeypatch.setattr(api_module, "auth_repo", auth)
    monkeypatch.setattr(api_module, "audit_repo", audit)
    monkeypatch.setattr(auth_module, "inventory", inventory)
    monkeypatch.setattr(auth_module, "auth_repo", auth)
    monkeypatch.setattr(middleware_module, "audit_repo", audit)
    monkeypatch.setattr(reporting_api, "inventory", inventory)
    return TestClient(api_module.app), auth


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


def test_viewer_can_export_reports_but_cannot_cross_workspace(tmp_path: Path, monkeypatch) -> None:
    client, auth = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": "viewer-secure-password"},
    )
    viewer_token = login.json()["token"]

    executive = client.get(
        f"/api/v1/workspaces/{workspace_id}/reports/executive",
        headers=_bearer(viewer_token),
    )
    assert executive.status_code == 200
    assert executive.json()["metadata"]["workspace_id"] == workspace_id

    engineering_csv = client.get(
        f"/api/v1/workspaces/{workspace_id}/reports/engineering.csv",
        headers=_bearer(viewer_token),
    )
    assert engineering_csv.status_code == 200
    assert engineering_csv.headers["content-type"].startswith("text/csv")
    assert "attachment;" in engineering_csv.headers["content-disposition"]

    executive_html = client.get(
        f"/api/v1/workspaces/{workspace_id}/reports/executive.html",
        headers=_bearer(viewer_token),
    )
    assert executive_html.status_code == 200
    assert executive_html.headers["content-type"].startswith("text/html")

    cbom = client.get(
        f"/api/v1/workspaces/{workspace_id}/reports/cbom",
        headers=_bearer(viewer_token),
    )
    assert cbom.status_code == 200
    assert cbom.json()["specVersion"] == "1.7"

    bundle = client.get(
        f"/api/v1/workspaces/{workspace_id}/reports/pilot-evidence.zip",
        headers=_bearer(viewer_token),
    )
    assert bundle.status_code == 200
    assert bundle.headers["content-type"].startswith("application/zip")
    assert "pilot-evidence.zip" in bundle.headers["content-disposition"]

    with ZipFile(BytesIO(bundle.content)) as archive:
        assert set(archive.namelist()) == {
            "manifest.json",
            "executive.json",
            "engineering.json",
            "executive.csv",
            "engineering.csv",
            "executive.html",
            "cbom.cdx.json",
        }
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["schema"] == "cryptohawk-pilot-evidence/v1"
        assert manifest["workspace"]["id"] == workspace_id
        assert "does not certify" in manifest["disclaimer"]
        for artifact in manifest["artifacts"]:
            content = archive.read(artifact["path"])
            assert len(content) == artifact["bytes"]
            assert hashlib.sha256(content).hexdigest() == artifact["sha256"]
        all_content = b"".join(archive.read(name) for name in archive.namelist())
        assert b"correct-horse-battery-staple" not in all_content
        assert viewer_token.encode() not in all_content

    owner = auth.authenticate(owner_token)
    other = auth.create_workspace(principal=owner, name="Other")
    denied = client.get(
        f"/api/v1/workspaces/{other.id}/reports/executive",
        headers=_bearer(viewer_token),
    )
    assert denied.status_code == 403
    bundle_denied = client.get(
        f"/api/v1/workspaces/{other.id}/reports/pilot-evidence.zip",
        headers=_bearer(viewer_token),
    )
    assert bundle_denied.status_code == 403


def test_reporting_requires_authentication(tmp_path: Path, monkeypatch) -> None:
    client, _ = _client(tmp_path, monkeypatch)
    _, workspace_id = _bootstrap(client)

    response = client.get(f"/api/v1/workspaces/{workspace_id}/reports/executive")
    bundle = client.get(
        f"/api/v1/workspaces/{workspace_id}/reports/pilot-evidence.zip"
    )

    assert response.status_code == 401
    assert bundle.status_code == 401
