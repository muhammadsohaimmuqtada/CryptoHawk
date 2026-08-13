from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from sqlalchemy import text

from cryptohawk.domain.audit import AuditEvent, AuditOutcome
from cryptohawk.domain.auth import PrincipalKind, WorkspaceRole
from cryptohawk.domain.credentials import ConnectorCredentialKind
from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
from cryptohawk.domain.models import AssetType, CryptoObservation, Evidence, Primitive, ScanContext
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.security.secrets import VersionedAesGcmCipher
from cryptohawk.storage.audit import AuditRepository
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.credentials import ConnectorCredentialRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


class DisasterRecoveryVerificationError(RuntimeError):
    pass


def _database_url() -> str:
    value = os.environ.get("CRYPTOHAWK_DATABASE_URL", "").strip()
    if not value:
        raise DisasterRecoveryVerificationError("CRYPTOHAWK_DATABASE_URL is required")
    if not value.startswith("postgresql"):
        raise DisasterRecoveryVerificationError("DR fixture requires a PostgreSQL database URL")
    return value


def _cipher() -> VersionedAesGcmCipher:
    spec = os.environ.get("CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS", "").strip()
    if not spec:
        raise DisasterRecoveryVerificationError(
            "CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS is required"
        )
    version = int(os.environ.get("CRYPTOHAWK_CONNECTOR_ENCRYPTION_ACTIVE_VERSION", "1"))
    return VersionedAesGcmCipher.from_spec(spec, active_version=version)


def _repositories():
    database_url = _database_url()
    inventory = InventoryRepository(database_url)
    findings = FindingRepository(database_url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    auth = AuthRepository(inventory)
    audit = AuditRepository(inventory)
    continuous = ContinuousRepository(inventory)
    credentials = ConnectorCredentialRepository(inventory, _cipher())
    return inventory, findings, quota, queue, auth, audit, continuous, credentials


def _write_manifest(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


def seed(manifest_path: Path) -> None:
    inventory, findings, quota, queue, auth, audit, continuous, credentials = _repositories()

    issued = auth.bootstrap(
        email="dr-owner@example.test",
        display_name="DR Owner",
        password="dr-fixture-password-strong-enough",
        workspace_name="DR Verification Workspace",
        workspace_slug="dr-verification",
    )
    if issued.workspace is None or issued.user is None:
        raise DisasterRecoveryVerificationError("bootstrap fixture did not return workspace and user")
    workspace = issued.workspace
    owner = auth.authenticate(issued.token)
    if owner.kind != PrincipalKind.SESSION:
        raise DisasterRecoveryVerificationError("bootstrap did not create a session principal")

    api_key = auth.create_api_key(
        principal=owner,
        workspace_id=workspace.id,
        name="dr-verification-key",
        role=WorkspaceRole.ANALYST,
        expires_days=30,
    )

    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="DR TLS Endpoint",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="dr.example.test:443",
        context=ScanContext(
            internet_exposed=True,
            asset_criticality=9,
            data_lifetime_years=7,
            environment="dr-fixture",
        ),
        tags={"purpose": "backup-restore-verification"},
    )

    schedule = continuous.create_schedule(
        workspace_id=workspace.id,
        asset_id=asset.id,
        interval_seconds=3600,
        max_attempts=4,
        created_by=f"session:{owner.subject_id}",
    )
    queued_job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=4,
    )

    observation = CryptoObservation(
        asset_id=asset.id,
        asset_name=asset.name,
        asset_type=AssetType.TLS_ENDPOINT,
        algorithm="RSA-2048",
        family="RSA",
        primitive=Primitive.PKE,
        key_size=2048,
        confidence=1.0,
        evidence=Evidence(
            source="dr-fixture",
            locator=asset.locator,
            metadata={"fixture": True},
        ),
    )
    finding = RiskEngine().assess(observation, asset.context)
    prepared = continuous.prepare_findings(queued_job.id, [finding])
    findings.upsert_many(
        prepared,
        workspace_id=workspace.id,
        managed_asset_id=asset.id,
        scan_job_id=queued_job.id,
    )
    continuous.record_successful_scan(
        workspace_id=workspace.id,
        asset_id=asset.id,
        scan_job_id=queued_job.id,
        findings=prepared,
    )

    connector_secret = "ghp_dr_fixture_token_value_1234567890"
    credential = credentials.create(
        workspace_id=workspace.id,
        name="dr-github-credential",
        kind=ConnectorCredentialKind.GITHUB_TOKEN,
        secret={"token": connector_secret},
        created_by=f"session:{owner.subject_id}",
    )

    audit_event = audit.append(
        AuditEvent(
            workspace_id=workspace.id,
            request_id="dr-verification-request",
            actor_kind=owner.kind.value,
            actor_id=owner.subject_id,
            user_id=owner.user_id,
            action="dr.fixture.seeded",
            resource_type="workspace",
            resource_id=workspace.id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"fixture": True},
        )
    )

    quota.consume(
        scope_key=f"workspace:{workspace.id}",
        action="dr-fixture",
        limit=10,
        window_seconds=60,
    )

    with inventory.engine.connect() as connection:
        alembic_revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()

    _write_manifest(
        manifest_path,
        {
            "workspace_id": workspace.id,
            "user_id": issued.user.id,
            "session_token": issued.token,
            "api_key_token": api_key.token,
            "api_key_id": api_key.metadata.id,
            "asset_id": asset.id,
            "schedule_id": schedule.id,
            "scan_job_id": queued_job.id,
            "finding_id": prepared[0].observation.id,
            "credential_id": credential.id,
            "credential_secret": connector_secret,
            "audit_event_id": audit_event.id,
            "alembic_revision": alembic_revision,
        },
    )
    print("dr_fixture_seeded=true")


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise DisasterRecoveryVerificationError(message)


def verify(manifest_path: Path) -> None:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    inventory, findings, quota, queue, auth, audit, continuous, credentials = _repositories()

    workspace_id = str(data["workspace_id"])
    user_id = str(data["user_id"])
    asset_id = str(data["asset_id"])
    scan_job_id = str(data["scan_job_id"])
    credential_id = str(data["credential_id"])

    workspace = inventory.get_workspace(workspace_id)
    _expect(workspace is not None, "workspace was not restored")
    _expect(workspace.slug == "dr-verification", "workspace identity changed after restore")

    session_principal = auth.authenticate(str(data["session_token"]))
    _expect(session_principal.user_id == user_id, "restored session token is invalid")
    _expect(session_principal.kind == PrincipalKind.SESSION, "restored session principal changed")
    _expect(
        auth.authorize_workspace(session_principal, workspace_id, WorkspaceRole.OWNER)
        == WorkspaceRole.OWNER,
        "restored owner membership is invalid",
    )

    api_principal = auth.authenticate(str(data["api_key_token"]))
    _expect(api_principal.kind == PrincipalKind.API_KEY, "restored API key principal changed")
    _expect(
        api_principal.api_key_workspace_id == workspace_id,
        "restored API key workspace scope changed",
    )
    _expect(
        api_principal.api_key_role == WorkspaceRole.ANALYST,
        "restored API key role changed",
    )

    asset = inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id)
    _expect(asset is not None, "managed asset was not restored")
    _expect(asset.locator == "dr.example.test:443", "managed asset locator changed")
    _expect(asset.context.asset_criticality == 9, "managed asset context changed")

    schedule = continuous.get_schedule(
        workspace_id=workspace_id,
        schedule_id=str(data["schedule_id"]),
    )
    _expect(schedule is not None and schedule.enabled, "scan schedule was not restored")
    _expect(schedule.max_attempts == 4, "scan schedule retry policy changed")

    job = inventory.get_scan_job(workspace_id=workspace_id, job_id=scan_job_id)
    _expect(job is not None, "scan job was not restored")
    _expect(job.status == ScanStatus.QUEUED, "scan job state changed after restore")
    lease = queue.claim_next(
        worker_id="dr-verifier",
        lease_seconds=30,
        concurrency_limit=4,
    )
    _expect(lease is not None and lease.job.id == scan_job_id, "restored queue is not claimable")

    restored_findings = findings.list_findings(workspace_id=workspace_id)
    _expect(len(restored_findings) == 1, "restored scoped finding count is incorrect")
    restored_finding = restored_findings[0]
    _expect(
        restored_finding.observation.id == str(data["finding_id"]),
        "restored finding identity changed",
    )
    _expect(restored_finding.observation.family == "RSA", "restored finding payload changed")

    history = continuous.list_scan_history(workspace_id=workspace_id, asset_id=asset_id)
    _expect(len(history) == 1, "scan history was not restored")
    states = continuous.list_observation_states(
        workspace_id=workspace_id,
        asset_id=asset_id,
        active_only=True,
    )
    _expect(len(states) == 1, "cryptographic observation state was not restored")

    material = credentials.resolve_for_use(
        workspace_id=workspace_id,
        credential_id=credential_id,
    )
    _expect(
        material == {"token": str(data["credential_secret"])},
        "encrypted connector credential cannot be decrypted after restore",
    )

    audit_events = audit.list_workspace(workspace_id, limit=20)
    _expect(
        any(event.id == str(data["audit_event_id"]) for event in audit_events),
        "audit event was not restored",
    )

    quota_state = quota.capacity(workspace_id=workspace_id, limit=4)
    _expect(quota_state.limit == 4, "quota runtime is invalid after restore")

    with inventory.engine.connect() as connection:
        restored_revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    _expect(
        restored_revision == str(data["alembic_revision"]),
        "alembic revision changed after restore",
    )

    print("dr_restore_verified=true")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("seed", "verify"))
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()

    if args.mode == "seed":
        seed(args.manifest)
    else:
        verify(args.manifest)


if __name__ == "__main__":
    main()
