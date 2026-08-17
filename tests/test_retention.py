from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from cryptohawk.domain.auth import WorkspaceRole
from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
from cryptohawk.domain.models import ScanContext
from cryptohawk.storage.audit import AuditEventRecord
from cryptohawk.storage.auth import ApiKeyRecord, AuthRepository, SessionRecord, UserRecord
from cryptohawk.storage.continuous import (
    DriftEventRecord,
    ObservationOccurrenceRecord,
    ObservationStateRecord,
    ScanScheduleRecord,
    ScanSnapshotRecord,
    ScheduledExecutionRecord,
)
from cryptohawk.storage.credentials import ConnectorCredentialRecord
from cryptohawk.storage.database import FindingRecord, FindingScopeRecord
from cryptohawk.storage.inventory import InventoryRepository, ManagedAssetRecord, ScanJobRecord
from cryptohawk.storage.policy import (
    CryptoPolicyPackRecord,
    CryptoPolicyVersionRecord,
    WorkspacePolicyAssignmentRecord,
)
from cryptohawk.storage.queue import ScanQueueRecord, ScanQueueRepository
from cryptohawk.storage.quotas import RateLimitBucketRecord, WorkspaceRuntimeRecord
from cryptohawk.storage.remediation import MigrationItemRecord
from cryptohawk.storage.repositories import (
    RepositoryConfigurationRecord,
    RepositoryScanRunRecord,
)
from cryptohawk.storage.retention import (
    WorkspacePurgeBlocked,
    WorkspaceRetentionRepository,
)


def _repositories(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'retention.db'}"
    inventory = InventoryRepository(url)
    # Importing WorkspaceRetentionRepository above registers every workspace-owned
    # ORM model with Base metadata before schema creation.
    inventory.create_schema()
    auth = AuthRepository(inventory)
    queue = ScanQueueRepository(inventory)
    return inventory, auth, queue, WorkspaceRetentionRepository(inventory)


def _count(session, model, *criteria) -> int:
    statement = select(func.count()).select_from(model)
    if criteria:
        statement = statement.where(*criteria)
    return int(session.scalar(statement) or 0)


def test_workspace_purge_removes_tenant_state_and_preserves_neighbor(
    tmp_path: Path,
) -> None:
    inventory, auth, queue, retention = _repositories(tmp_path)
    issued = auth.bootstrap(
        email="owner@example.com",
        display_name="Owner",
        password="correct-horse-battery-staple",
        workspace_name="Acme",
        workspace_slug="acme",
    )
    assert issued.workspace is not None
    principal = auth.authenticate(issued.token)
    assert principal.user_id is not None
    target = issued.workspace
    neighbor = auth.create_workspace(principal=principal, name="Neighbor", slug="neighbor")

    target_asset = inventory.create_asset(
        workspace_id=target.id,
        name="Target TLS",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="target.example:443",
        context=ScanContext(internet_exposed=True),
    )
    neighbor_asset = inventory.create_asset(
        workspace_id=neighbor.id,
        name="Neighbor TLS",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="neighbor.example:443",
        context=ScanContext(internet_exposed=True),
    )
    target_job = queue.enqueue(
        workspace_id=target.id,
        asset_id=target_asset.id,
        kind=ScanKind.TLS,
    )
    neighbor_job = queue.enqueue(
        workspace_id=neighbor.id,
        asset_id=neighbor_asset.id,
        kind=ScanKind.TLS,
    )

    now = datetime.now(UTC)
    target_finding_id = "target-finding"
    neighbor_finding_id = "neighbor-finding"
    policy_id = "target-policy"
    policy_version_id = "target-policy-v1"
    schedule_id = "target-schedule"

    with inventory.SessionLocal() as session:
        session.add_all(
            [
                FindingRecord(
                    id=target_finding_id,
                    asset_id=target_asset.id,
                    asset_name=target_asset.name,
                    family="RSA",
                    algorithm="RSA-2048",
                    primitive="public-key",
                    key_size=2048,
                    risk_score=90,
                    severity="critical",
                    quantum_status="vulnerable",
                    migration_target="ML-KEM",
                    payload="{}",
                    discovered_at=now,
                ),
                FindingScopeRecord(
                    finding_id=target_finding_id,
                    workspace_id=target.id,
                    managed_asset_id=target_asset.id,
                    scan_job_id=target_job.id,
                ),
                FindingRecord(
                    id=neighbor_finding_id,
                    asset_id=neighbor_asset.id,
                    asset_name=neighbor_asset.name,
                    family="RSA",
                    algorithm="RSA-3072",
                    primitive="public-key",
                    key_size=3072,
                    risk_score=70,
                    severity="high",
                    quantum_status="vulnerable",
                    migration_target="ML-KEM",
                    payload="{}",
                    discovered_at=now,
                ),
                FindingScopeRecord(
                    finding_id=neighbor_finding_id,
                    workspace_id=neighbor.id,
                    managed_asset_id=neighbor_asset.id,
                    scan_job_id=neighbor_job.id,
                ),
                ScanScheduleRecord(
                    id=schedule_id,
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    interval_seconds=3600,
                    max_attempts=3,
                    enabled=True,
                    next_run_at=now + timedelta(hours=1),
                    last_run_at=None,
                    created_by=principal.user_id,
                    created_at=now,
                    updated_at=now,
                ),
                ScheduledExecutionRecord(
                    job_id=target_job.id,
                    schedule_id=schedule_id,
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    scheduled_for=now,
                    enqueued_at=now,
                ),
                ScanSnapshotRecord(
                    job_id=target_job.id,
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    origin="scheduled",
                    schedule_id=schedule_id,
                    scheduled_for=now,
                    completed_at=now,
                    finding_count=1,
                    scanner_version="test",
                    policy_version="test-policy",
                    fingerprint_set_hash="1" * 64,
                ),
                ObservationStateRecord(
                    id="target-state",
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    fingerprint="2" * 64,
                    active=True,
                    first_seen=now,
                    last_seen=now,
                    first_job_id=target_job.id,
                    last_job_id=target_job.id,
                    occurrence_count=1,
                    risk_score=90,
                    severity="critical",
                    quantum_status="vulnerable",
                    evidence_hash="3" * 64,
                    finding_payload="{}",
                    updated_at=now,
                ),
                ObservationOccurrenceRecord(
                    id="target-occurrence",
                    job_id=target_job.id,
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    fingerprint="2" * 64,
                    finding_id=target_finding_id,
                    observed_at=now,
                    risk_score=90,
                    severity="critical",
                    quantum_status="vulnerable",
                    evidence_hash="3" * 64,
                    finding_payload="{}",
                    scanner_version="test",
                    policy_version="test-policy",
                ),
                DriftEventRecord(
                    id="target-drift",
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    scan_job_id=target_job.id,
                    fingerprint="2" * 64,
                    event_type="introduced",
                    previous_risk_score=None,
                    new_risk_score=90,
                    previous_severity=None,
                    new_severity="critical",
                    occurred_at=now,
                    details_json="{}",
                ),
                ConnectorCredentialRecord(
                    id="target-credential",
                    workspace_id=target.id,
                    name="git-token",
                    kind="github-token",
                    ciphertext=b"ciphertext",
                    nonce=b"123456789012",
                    key_version=1,
                    secret_fields_json='["token"]',
                    created_by=principal.user_id,
                    created_at=now,
                    updated_at=now,
                    last_used_at=None,
                ),
                RepositoryConfigurationRecord(
                    asset_id=target_asset.id,
                    workspace_id=target.id,
                    repository_url="https://example.com/acme/repo.git",
                    provider="generic",
                    ref="HEAD",
                    credential_id="target-credential",
                    created_at=now,
                    updated_at=now,
                ),
                RepositoryScanRunRecord(
                    scan_job_id=target_job.id,
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    repository_url="https://example.com/acme/repo.git",
                    ref="HEAD",
                    commit_sha="4" * 40,
                    previous_commit_sha=None,
                    scan_mode="full",
                    changed_paths=1,
                    scanned_files=1,
                    retained_observations=0,
                    collected_at=now,
                ),
                MigrationItemRecord(
                    id="target-migration",
                    workspace_id=target.id,
                    asset_id=target_asset.id,
                    observation_fingerprint="2" * 64,
                    source_finding_id=target_finding_id,
                    source_scan_job_id=target_job.id,
                    title="Replace RSA",
                    owner="platform",
                    status="open",
                    priority="critical",
                    target_algorithm="ML-KEM",
                    due_date=None,
                    notes=None,
                    acceptance_reason=None,
                    verification_job_id=None,
                    verified_at=None,
                    verification_evidence_json="{}",
                    source_finding_json="{}",
                    created_by=principal.user_id,
                    created_at=now,
                    updated_at=now,
                ),
                CryptoPolicyPackRecord(
                    id=policy_id,
                    workspace_id=target.id,
                    slug="target-policy",
                    name="Target Policy",
                    description="test",
                    built_in=False,
                    created_by=principal.user_id,
                    created_at=now,
                ),
                CryptoPolicyVersionRecord(
                    id=policy_version_id,
                    policy_id=policy_id,
                    workspace_id=target.id,
                    version=1,
                    rules_json="{}",
                    rules_hash="5" * 64,
                    created_by=principal.user_id,
                    created_at=now,
                ),
                WorkspacePolicyAssignmentRecord(
                    workspace_id=target.id,
                    policy_version_id=policy_version_id,
                    assigned_by=principal.user_id,
                    assigned_at=now,
                ),
                ApiKeyRecord(
                    id="target-api-key",
                    workspace_id=target.id,
                    name="automation",
                    prefix="chk_target",
                    token_hash="6" * 64,
                    role=WorkspaceRole.ANALYST.value,
                    created_by_user_id=principal.user_id,
                    created_at=now,
                    expires_at=None,
                    last_used_at=None,
                    revoked_at=None,
                ),
                WorkspaceRuntimeRecord(
                    workspace_id=target.id,
                    active_scans=0,
                    updated_at=now,
                ),
                RateLimitBucketRecord(
                    scope_key=f"workspace:{target.id}",
                    action="api",
                    window_start=int(now.timestamp()),
                    count=1,
                    updated_at=now,
                ),
                RateLimitBucketRecord(
                    scope_key="principal:api-key:target-api-key",
                    action="api",
                    window_start=int(now.timestamp()),
                    count=1,
                    updated_at=now,
                ),
                AuditEventRecord(
                    id="target-audit",
                    workspace_id=target.id,
                    request_id="request-1",
                    actor_kind="session",
                    actor_id=principal.subject_id,
                    user_id=principal.user_id,
                    action="test.seed",
                    resource_type="workspace",
                    resource_id=target.id,
                    outcome="success",
                    metadata_json="{}",
                    created_at=now,
                ),
            ]
        )
        session.commit()

    result = retention.purge_workspace(target.id)
    assert result.workspace_id == target.id
    assert result.workspace_slug == "acme"
    assert result.deleted_rows["workspaces"] == 1

    assert inventory.get_workspace(target.id) is None
    assert inventory.get_workspace(neighbor.id) is not None

    with inventory.SessionLocal() as session:
        target_workspace_models = (
            ManagedAssetRecord,
            ScanJobRecord,
            FindingScopeRecord,
            ScanScheduleRecord,
            ScheduledExecutionRecord,
            ScanSnapshotRecord,
            ObservationStateRecord,
            ObservationOccurrenceRecord,
            DriftEventRecord,
            ConnectorCredentialRecord,
            RepositoryConfigurationRecord,
            RepositoryScanRunRecord,
            MigrationItemRecord,
            CryptoPolicyPackRecord,
            CryptoPolicyVersionRecord,
            WorkspacePolicyAssignmentRecord,
            ApiKeyRecord,
            WorkspaceRuntimeRecord,
            AuditEventRecord,
        )
        for model in target_workspace_models:
            assert _count(session, model, model.workspace_id == target.id) == 0

        assert session.get(ScanQueueRecord, target_job.id) is None
        assert session.get(FindingRecord, target_finding_id) is None
        assert session.get(FindingRecord, neighbor_finding_id) is not None
        assert session.get(ManagedAssetRecord, neighbor_asset.id) is not None
        assert session.get(ScanJobRecord, neighbor_job.id) is not None
        assert session.get(ScanQueueRecord, neighbor_job.id) is not None
        assert session.get(UserRecord, principal.user_id) is not None
        assert session.get(SessionRecord, principal.subject_id) is not None
        assert (
            _count(
                session,
                RateLimitBucketRecord,
                RateLimitBucketRecord.scope_key.in_(
                    [
                        f"workspace:{target.id}",
                        "principal:api-key:target-api-key",
                    ]
                ),
            )
            == 0
        )


def test_workspace_purge_refuses_running_scan(tmp_path: Path) -> None:
    inventory, auth, queue, retention = _repositories(tmp_path)
    issued = auth.bootstrap(
        email="owner@example.com",
        display_name="Owner",
        password="correct-horse-battery-staple",
        workspace_name="Acme",
        workspace_slug="acme",
    )
    assert issued.workspace is not None
    asset = inventory.create_asset(
        workspace_id=issued.workspace.id,
        name="Target TLS",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="target.example:443",
        context=ScanContext(internet_exposed=True),
    )
    job = queue.enqueue(
        workspace_id=issued.workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )
    inventory.transition_scan_job(
        workspace_id=issued.workspace.id,
        job_id=job.id,
        expected=ScanStatus.QUEUED,
        target=ScanStatus.RUNNING,
    )

    with pytest.raises(WorkspacePurgeBlocked, match="running scans"):
        retention.purge_workspace(issued.workspace.id)

    assert inventory.get_workspace(issued.workspace.id) is not None
    assert inventory.get_scan_job(workspace_id=issued.workspace.id, job_id=job.id) is not None
