from pathlib import Path

from fastapi.testclient import TestClient

import cryptohawk.api.app as api_module
import cryptohawk.api.auth as auth_module
import cryptohawk.api.continuous as continuous_api
import cryptohawk.api.middleware as middleware_module
import cryptohawk.api.policy as policy_api
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.policy import PolicyRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


def _client(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'api-policy.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    continuous = ContinuousRepository(inventory)
    policies = PolicyRepository(inventory)

    inventory.create_schema()
    findings.create_schema()
    quota.create_schema()
    queue.create_schema()
    auth.create_schema()
    audit.create_schema()
    continuous.create_schema()
    policies.create_schema()

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
    monkeypatch.setattr(policy_api, "inventory", inventory)
    monkeypatch.setattr(policy_api, "policy_repo", policies)
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
            policy_repository=policies,
        ),
    )
    return TestClient(api_module.app), auth, inventory, continuous, policies


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


def test_owner_can_select_builtin_and_create_versioned_custom_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, _, _, _, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)

    builtins = client.get(
        f"/api/v1/workspaces/{workspace_id}/policy-packs",
        headers=_bearer(owner_token),
    )
    assert builtins.status_code == 200
    payload = builtins.json()
    assert {item["pack"]["slug"] for item in payload} >= {
        "cryptohawk-recommended",
        "strict-modern",
        "long-lived-confidentiality",
    }

    effective = client.get(
        f"/api/v1/workspaces/{workspace_id}/policy-packs/effective",
        headers=_bearer(owner_token),
    )
    assert effective.status_code == 200
    assert effective.json()["pack"]["slug"] == "cryptohawk-recommended"

    created = client.post(
        f"/api/v1/workspaces/{workspace_id}/policy-packs",
        headers=_bearer(owner_token),
        json={
            "slug": "payments-baseline",
            "name": "Payments Baseline",
            "description": "Production payment cryptography baseline",
            "activate": True,
            "rules": {
                "minimum_rsa_bits": 3072,
                "minimum_aes_bits": 256,
                "minimum_tls_version": "1.3",
                "quantum_vulnerable_default": "fail",
                "internet_exposed_quantum_action": "fail",
                "long_lived_data_years": 3,
                "unknown_family_action": "review",
                "minimum_detection_confidence": 0.85,
            },
        },
    )
    assert created.status_code == 201
    custom = created.json()
    assert custom["active_version"] == 1
    assert custom["versions"][0]["version"] == 1

    version_two = client.post(
        f"/api/v1/workspaces/{workspace_id}/policy-packs/"
        f"{custom['pack']['id']}/versions",
        headers=_bearer(owner_token),
        json={
            "activate": True,
            "rules": {
                **custom["versions"][0]["rules"],
                "minimum_rsa_bits": 4096,
            },
        },
    )
    assert version_two.status_code == 201
    assert version_two.json()["version"] == 2

    effective = client.get(
        f"/api/v1/workspaces/{workspace_id}/policy-packs/effective",
        headers=_bearer(owner_token),
    )
    assert effective.json()["pack"]["id"] == custom["pack"]["id"]
    assert effective.json()["version"]["version"] == 2


def test_viewer_can_read_policy_but_cannot_mutate_or_cross_workspace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, auth, _, _, _ = _client(tmp_path, monkeypatch)
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

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/policy-packs",
        headers=_bearer(viewer_token),
    )
    assert listed.status_code == 200

    denied = client.post(
        f"/api/v1/workspaces/{workspace_id}/policy-packs",
        headers=_bearer(viewer_token),
        json={
            "slug": "viewer-policy",
            "name": "Viewer Policy",
            "rules": {},
        },
    )
    assert denied.status_code == 403

    owner_principal = auth.authenticate(owner_token)
    other_workspace = auth.create_workspace(principal=owner_principal, name="Other")
    outside = client.get(
        f"/api/v1/workspaces/{other_workspace.id}/policy-packs",
        headers=_bearer(viewer_token),
    )
    assert outside.status_code == 403


def test_builtin_policy_is_immutable_through_api(tmp_path: Path, monkeypatch) -> None:
    client, _, _, _, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)
    builtins = client.get(
        f"/api/v1/workspaces/{workspace_id}/policy-packs",
        headers=_bearer(owner_token),
    ).json()
    recommended = next(
        item for item in builtins if item["pack"]["slug"] == "cryptohawk-recommended"
    )

    response = client.post(
        f"/api/v1/workspaces/{workspace_id}/policy-packs/"
        f"{recommended['pack']['id']}/versions",
        headers=_bearer(owner_token),
        json={"rules": {"minimum_rsa_bits": 4096}},
    )
    assert response.status_code == 409
    assert "immutable" in response.json()["detail"]


def test_managed_scan_records_exact_active_policy_in_finding_and_history(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, _, inventory, continuous, _ = _client(tmp_path, monkeypatch)
    owner_token, workspace_id = _bootstrap(client)

    policies = client.get(
        f"/api/v1/workspaces/{workspace_id}/policy-packs",
        headers=_bearer(owner_token),
    ).json()
    strict = next(item for item in policies if item["pack"]["slug"] == "strict-modern")
    activated = client.post(
        f"/api/v1/workspaces/{workspace_id}/policy-packs/"
        f"{strict['pack']['id']}/versions/1/activate",
        headers=_bearer(owner_token),
    )
    assert activated.status_code == 200
    effective = activated.json()

    asset = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets",
        headers=_bearer(owner_token),
        json={
            "name": "Legacy crypto source",
            "kind": "source",
            "locator": "legacy.py",
            "context": {
                "internet_exposed": True,
                "asset_criticality": 9,
                "data_lifetime_years": 8,
                "environment": "production",
            },
        },
    )
    assert asset.status_code == 201
    asset_id = asset.json()["id"]

    scanned = client.post(
        f"/api/v1/workspaces/{workspace_id}/assets/{asset_id}/scan",
        headers=_bearer(owner_token),
        json={
            "source": (
                "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                "key = RSA-2048\n"
            ),
            "filename": "legacy.py",
        },
    )
    assert scanned.status_code == 200
    findings = scanned.json()["findings"]
    rsa_finding = next(item for item in findings if item["observation"]["family"] == "RSA")
    assert rsa_finding["risk"]["policy_status"] == "fail"
    assert rsa_finding["risk"]["policy_id"] == effective["pack"]["id"]
    assert rsa_finding["risk"]["policy_version"] == 1
    assert (
        rsa_finding["risk"]["policy_rules_hash"]
        == effective["version"]["rules_hash"]
    )

    history = continuous.list_scan_history(workspace_id=workspace_id, asset_id=asset_id)
    assert len(history) == 1
    expected_ref = (
        f"policy:{effective['pack']['id']}@1:"
        f"{effective['version']['rules_hash'][:16]}"
    )
    assert history[0].policy_version == expected_ref
    assert inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id) is not None
