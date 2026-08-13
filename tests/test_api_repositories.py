from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.continuous as continuous_api
import cryptohawk.api.middleware as middleware_module
import cryptohawk.api.repositories as repository_api
from cryptohawk.domain.repositories import RepositoryProvider
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.repository import RepositoryScanner
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
from cryptohawk.storage.repositories import RepositoryAssetRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-repositories.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    continuous = ContinuousRepository(inventory)
    repositories = RepositoryAssetRepository(inventory)

    repositories.create_schema()
    findings.create_schema()
    quota.create_schema()
    queue.create_schema()
    auth.create_schema()
    audit.create_schema()
    continuous.create_schema()

    scanner = RepositoryScanner(
        repositories,
        continuous,
        allowed_hosts=["github.com", "gitlab.com"],
        max_scan_bytes=5_000_000,
        max_file_bytes=1_000_000,
    )
    monkeypatch.setattr(
        scanner,
        "validate_repository_url",
        lambda url: (
            RepositoryProvider.GITLAB if "gitlab.com" in url else RepositoryProvider.GITHUB
        ),
    )

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
    monkeypatch.setattr(repository_api, "inventory", inventory)
    monkeypatch.setattr(repository_api, "continuous_repo", continuous)
    monkeypatch.setattr(repository_api, "repository_assets", repositories)
    monkeypatch.setattr(repository_api, "repository_scanner", scanner)
    monkeypatch.setattr(
        api_module,
        "scan_jobs",
        ScanJobService(
            inventory,
            findings,
            risk_engine=RiskEngine(),
            source_scanner=SourceScanner(),
            repository_scanner=scanner,
            tls_scanner=TLSScanner(),
            quota=quota,
            history=continuous,
        ),
    )
    return TestClient(api_module.app), auth, repositories


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


def test_owner_can_register_repository_and_schedule_it(tmp_path: Path, monkeypatch) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    token, workspace_id = _bootstrap(client)

    created = client.post(
        f"/api/v1/workspaces/{workspace_id}/repositories",
        headers=_bearer(token),
        json={
            "name": "Payments",
            "repository_url": "https://github.com/acme/payments.git",
            "ref": "main",
            "context": {"asset_criticality": 9},
        },
    )
    assert created.status_code == 201
    body = created.json()
    asset_id = body["asset"]["id"]
    assert body["asset"]["kind"] == "repository"
    assert body["repository"]["provider"] == "github"
    assert body["repository"]["ref"] == "main"
    assert "credential" not in body["repository"] or body["repository"]["credential_id"] is None

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/repositories",
        headers=_bearer(token),
    )
    assert listed.status_code == 200
    assert [item["asset"]["id"] for item in listed.json()] == [asset_id]

    schedule = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/schedule",
        headers=_bearer(token),
        json={"interval_minutes": 30},
    )
    assert schedule.status_code == 201
    assert schedule.json()["asset_id"] == asset_id

    provenance = client.get(
        f"/api/v1/workspaces/{workspace_id}/repositories/{asset_id}/commits",
        headers=_bearer(token),
    )
    assert provenance.status_code == 200
    assert provenance.json() == []


def test_analyst_can_view_repository_but_cannot_register_one(tmp_path: Path, monkeypatch) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
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
    assert login.status_code == 200
    token = login.json()["token"]

    denied = client.post(
        f"/api/v1/workspaces/{workspace_id}/repositories",
        headers=_bearer(token),
        json={
            "name": "Denied",
            "repository_url": "https://github.com/acme/denied.git",
        },
    )
    assert denied.status_code == 403

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/repositories",
        headers=_bearer(token),
    )
    assert listed.status_code == 200


def test_repository_registration_is_workspace_scoped(tmp_path: Path, monkeypatch) -> None:
    client, auth, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    created = client.post(
        f"/api/v1/workspaces/{workspace_id}/repositories",
        headers=_bearer(owner_token),
        json={
            "name": "Payments",
            "repository_url": "https://github.com/acme/payments.git",
        },
    )
    assert created.status_code == 201
    asset_id = created.json()["asset"]["id"]

    principal = auth.authenticate(owner_token)
    other = auth.create_workspace(principal=principal, name="Other", slug="other")

    hidden = client.get(
        f"/api/v1/workspaces/{other.id}/repositories/{asset_id}",
        headers=_bearer(owner_token),
    )
    assert hidden.status_code == 404
