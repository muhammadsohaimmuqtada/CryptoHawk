import base64
from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.credentials as credential_api
import cryptohawk.api.middleware as middleware_module
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.security.secrets import VersionedAesGcmCipher
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.credentials import ConnectorCredentialRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


def _cipher() -> VersionedAesGcmCipher:
    encoded = base64.urlsafe_b64encode(b"C" * 32).decode().rstrip("=")
    return VersionedAesGcmCipher.from_spec(f"1:{encoded}", active_version=1)


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-credentials.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    credentials = ConnectorCredentialRepository(inventory, _cipher())
    inventory.create_schema()
    findings.create_schema()
    quota.create_schema()
    queue.create_schema()
    auth.create_schema()
    audit.create_schema()
    credentials.create_schema()

    monkeypatch.setattr(api_module, "inventory", inventory)
    monkeypatch.setattr(api_module, "repo", findings)
    monkeypatch.setattr(api_module, "quota_repo", quota)
    monkeypatch.setattr(api_module, "scan_queue", queue)
    monkeypatch.setattr(api_module, "auth_repo", auth)
    monkeypatch.setattr(api_module, "audit_repo", audit)
    monkeypatch.setattr(auth_module, "inventory", inventory)
    monkeypatch.setattr(auth_module, "auth_repo", auth)
    monkeypatch.setattr(middleware_module, "audit_repo", audit)
    monkeypatch.setattr(credential_api, "credential_repo", credentials)
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
    return TestClient(api_module.app), auth, audit


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


def test_admin_only_credential_api_never_returns_secret_material(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, _, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    secret = "ghp_api-secret-that-must-not-leak"

    created = client.post(
        f"/api/v1/workspaces/{workspace_id}/credentials",
        headers=_bearer(owner_token),
        json={
            "name": "GitHub",
            "kind": "github-token",
            "secret": {"token": secret},
        },
    )
    assert created.status_code == 201
    created_text = created.text
    assert secret not in created_text
    credential_id = created.json()["id"]
    assert created.json()["secret_fields"] == ["token"]

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/credentials",
        headers=_bearer(owner_token),
    )
    assert listed.status_code == 200
    assert secret not in listed.text
    assert [item["id"] for item in listed.json()] == [credential_id]

    replacement = "ghp_rotated-secret"
    replaced = client.post(
        f"/api/v1/workspaces/{workspace_id}/credentials/{credential_id}/replace",
        headers=_bearer(owner_token),
        json={"secret": {"token": replacement}},
    )
    assert replaced.status_code == 200
    assert replacement not in replaced.text

    deleted = client.delete(
        f"/api/v1/workspaces/{workspace_id}/credentials/{credential_id}",
        headers=_bearer(owner_token),
    )
    assert deleted.status_code == 204


def test_analyst_cannot_manage_connector_credentials(tmp_path: Path, monkeypatch) -> None:
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
        json={
            "email": "analyst@example.com",
            "password": "analyst-secure-password",
        },
    )
    analyst_token = login.json()["token"]

    assert (
        client.get(
            f"/api/v1/workspaces/{workspace_id}/credentials",
            headers=_bearer(analyst_token),
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/workspaces/{workspace_id}/credentials",
            headers=_bearer(analyst_token),
            json={
                "name": "Forbidden",
                "kind": "generic-bearer",
                "secret": {"token": "do-not-store"},
            },
        ).status_code
        == 403
    )


def test_credential_mutation_audit_does_not_capture_secret_values(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, _, audit = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    secret = "registry-password-that-must-never-enter-audit"

    response = client.post(
        f"/api/v1/workspaces/{workspace_id}/credentials",
        headers=_bearer(owner_token),
        json={
            "name": "Registry",
            "kind": "registry-basic",
            "secret": {"username": "scanner", "password": secret},
        },
    )
    assert response.status_code == 201

    events = audit.list_workspace(workspace_id)
    assert events
    serialized = "\n".join(event.model_dump_json() for event in events)
    assert secret not in serialized
    assert "scanner" not in serialized
