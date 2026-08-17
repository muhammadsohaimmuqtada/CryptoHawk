from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cryptohawk.domain.inventory import ManagedAssetKind, ScanStatus
from cryptohawk.domain.models import ScanContext
from cryptohawk.storage.audit import AuditEventRecord
from cryptohawk.storage.continuous import (
    DriftEventRecord,
    ObservationOccurrenceRecord,
    ObservationStateRecord,
    ScanSnapshotRecord,
)
from cryptohawk.storage.database import FindingRecord, FindingScopeRecord
from cryptohawk.storage.inventory import InventoryRepository, ScanJobRecord
from cryptohawk.storage.queue import ScanQueueRecord
from cryptohawk.storage.repositories import RepositoryScanRunRecord
from cryptohawk.storage.retention import (
    WorkspaceRetentionPolicyRecord,
    WorkspaceRetentionRepository,
)


def _repo(tmp_path: Path) -> tuple[InventoryRepository, WorkspaceRetentionRepository]:
    inventory = InventoryRepository(f"sqlite:///{tmp_path / 'policy.db'}")
    retention = WorkspaceRetentionRepository(inventory)
    inventory.create_schema()
    return inventory, retention


def test_retention_prunes_old_history_but_protects_current_evidence(tmp_path: Path) -> None:
    inventory, retention = _repo(tmp_path)
    workspace = inventory.create_workspace(name="Acme")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Repository",
        kind=ManagedAssetKind.REPOSITORY,
        locator="https://github.com/example/repo.git",
        context=ScanContext(internet_exposed=True),
    )
    now = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
    old = now - timedelta(days=60)
    recent = now - timedelta(days=1)
    old_job_id = "old-job"
    latest_job_id = "latest-job"
    old_finding_id = "old-finding"
    latest_finding_id = "latest-finding"
    fingerprint = "f" * 64

    retention.set_policy(
        workspace_id=workspace.id,
        enabled=True,
        evidence_retention_days=30,
        audit_retention_days=30,
        sweep_interval_hours=24,
        updated_by="owner",
        now=now - timedelta(days=2),
    )

    with inventory.SessionLocal() as session:
        session.add_all(
            [
                ScanJobRecord(
                    id=old_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    kind="repository",
                    status=ScanStatus.SUCCEEDED.value,
                    requested_at=old,
                    started_at=old,
                    finished_at=old,
                    findings_count=1,
                    error_message=None,
                ),
                ScanQueueRecord(
                    job_id=old_job_id,
                    attempts=1,
                    max_attempts=3,
                    lease_owner=None,
                    lease_expires_at=None,
                    last_heartbeat_at=None,
                    next_attempt_at=old,
                    cancel_requested=False,
                ),
                ScanJobRecord(
                    id=latest_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    kind="repository",
                    status=ScanStatus.SUCCEEDED.value,
                    requested_at=recent,
                    started_at=recent,
                    finished_at=recent,
                    findings_count=1,
                    error_message=None,
                ),
                ScanSnapshotRecord(
                    job_id=old_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    origin="manual",
                    schedule_id=None,
                    scheduled_for=None,
                    completed_at=old,
                    finding_count=1,
                    scanner_version="test",
                    policy_version="test-policy",
                    fingerprint_set_hash="1" * 64,
                ),
                ScanSnapshotRecord(
                    job_id=latest_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    origin="manual",
                    schedule_id=None,
                    scheduled_for=None,
                    completed_at=recent,
                    finding_count=1,
                    scanner_version="test",
                    policy_version="test-policy",
                    fingerprint_set_hash="2" * 64,
                ),
                FindingRecord(
                    id=old_finding_id,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    family="RSA",
                    algorithm="RSA-2048",
                    primitive="public-key",
                    key_size=2048,
                    risk_score=90,
                    severity="critical",
                    quantum_status="vulnerable",
                    migration_target="ML-KEM",
                    payload="{}",
                    discovered_at=old,
                ),
                FindingScopeRecord(
                    finding_id=old_finding_id,
                    workspace_id=workspace.id,
                    managed_asset_id=asset.id,
                    scan_job_id=old_job_id,
                ),
                FindingRecord(
                    id=latest_finding_id,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    family="RSA",
                    algorithm="RSA-3072",
                    primitive="public-key",
                    key_size=3072,
                    risk_score=80,
                    severity="high",
                    quantum_status="vulnerable",
                    migration_target="ML-KEM",
                    payload="{}",
                    discovered_at=recent,
                ),
                FindingScopeRecord(
                    finding_id=latest_finding_id,
                    workspace_id=workspace.id,
                    managed_asset_id=asset.id,
                    scan_job_id=latest_job_id,
                ),
                ObservationOccurrenceRecord(
                    id="old-occurrence",
                    job_id=old_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    fingerprint=fingerprint,
                    finding_id=old_finding_id,
                    observed_at=old,
                    risk_score=90,
                    severity="critical",
                    quantum_status="vulnerable",
                    evidence_hash="3" * 64,
                    finding_payload="{}",
                    scanner_version="test",
                    policy_version="test-policy",
                ),
                ObservationOccurrenceRecord(
                    id="latest-occurrence",
                    job_id=latest_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    fingerprint=fingerprint,
                    finding_id=latest_finding_id,
                    observed_at=recent,
                    risk_score=80,
                    severity="high",
                    quantum_status="vulnerable",
                    evidence_hash="4" * 64,
                    finding_payload="{}",
                    scanner_version="test",
                    policy_version="test-policy",
                ),
                ObservationStateRecord(
                    id="state",
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    fingerprint=fingerprint,
                    active=True,
                    first_seen=old,
                    last_seen=recent,
                    first_job_id=old_job_id,
                    last_job_id=latest_job_id,
                    occurrence_count=2,
                    risk_score=80,
                    severity="high",
                    quantum_status="vulnerable",
                    evidence_hash="4" * 64,
                    finding_payload="{}",
                    updated_at=recent,
                ),
                DriftEventRecord(
                    id="old-drift",
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    scan_job_id=old_job_id,
                    fingerprint=fingerprint,
                    event_type="introduced",
                    previous_risk_score=None,
                    new_risk_score=90,
                    previous_severity=None,
                    new_severity="critical",
                    occurred_at=old,
                    details_json="{}",
                ),
                DriftEventRecord(
                    id="recent-drift",
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    scan_job_id=latest_job_id,
                    fingerprint=fingerprint,
                    event_type="risk-changed",
                    previous_risk_score=90,
                    new_risk_score=80,
                    previous_severity="critical",
                    new_severity="high",
                    occurred_at=recent,
                    details_json="{}",
                ),
                RepositoryScanRunRecord(
                    scan_job_id=old_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    repository_url="https://github.com/example/repo.git",
                    ref="HEAD",
                    commit_sha="a" * 40,
                    previous_commit_sha=None,
                    scan_mode="full",
                    changed_paths=1,
                    scanned_files=1,
                    retained_observations=0,
                    collected_at=old,
                ),
                RepositoryScanRunRecord(
                    scan_job_id=latest_job_id,
                    workspace_id=workspace.id,
                    asset_id=asset.id,
                    repository_url="https://github.com/example/repo.git",
                    ref="HEAD",
                    commit_sha="b" * 40,
                    previous_commit_sha="a" * 40,
                    scan_mode="incremental",
                    changed_paths=1,
                    scanned_files=1,
                    retained_observations=1,
                    collected_at=recent,
                ),
                AuditEventRecord(
                    id="old-audit",
                    workspace_id=workspace.id,
                    request_id="old-request",
                    actor_kind="session",
                    actor_id="owner",
                    user_id="owner",
                    action="test.old",
                    resource_type="workspace",
                    resource_id=workspace.id,
                    outcome="success",
                    metadata_json="{}",
                    created_at=old,
                ),
                AuditEventRecord(
                    id="recent-audit",
                    workspace_id=workspace.id,
                    request_id="recent-request",
                    actor_kind="session",
                    actor_id="owner",
                    user_id="owner",
                    action="test.recent",
                    resource_type="workspace",
                    resource_id=workspace.id,
                    outcome="success",
                    metadata_json="{}",
                    created_at=recent,
                ),
            ]
        )
        session.commit()

    result = retention.prune_workspace_history(workspace_id=workspace.id, now=now)
    assert result is not None
    assert result.deleted_rows["observation_occurrences"] == 1
    assert result.deleted_rows["drift_events"] == 1
    assert result.deleted_rows["scan_snapshots"] == 1
    assert result.deleted_rows["repository_scan_runs"] == 1
    assert result.deleted_rows["findings"] == 1
    assert result.deleted_rows["scan_jobs"] == 1
    assert result.deleted_rows["audit_events"] == 1

    with inventory.SessionLocal() as session:
        assert session.get(ScanJobRecord, old_job_id) is None
        assert session.get(ScanQueueRecord, old_job_id) is None
        assert session.get(ScanSnapshotRecord, old_job_id) is None
        assert session.get(RepositoryScanRunRecord, old_job_id) is None
        assert session.get(FindingRecord, old_finding_id) is None
        assert session.get(AuditEventRecord, "old-audit") is None

        assert session.get(ScanJobRecord, latest_job_id) is not None
        assert session.get(ScanSnapshotRecord, latest_job_id) is not None
        assert session.get(RepositoryScanRunRecord, latest_job_id) is not None
        assert session.get(FindingRecord, latest_finding_id) is not None
        assert session.get(ObservationOccurrenceRecord, "latest-occurrence") is not None
        assert session.get(ObservationStateRecord, "state") is not None
        assert session.get(AuditEventRecord, "recent-audit") is not None

        policy = session.get(WorkspaceRetentionPolicyRecord, workspace.id)
        assert policy is not None
        assert policy.last_run_at == now.replace(tzinfo=None) or policy.last_run_at == now


def test_due_retention_obeys_policy_interval_and_purge_removes_policy(tmp_path: Path) -> None:
    inventory, retention = _repo(tmp_path)
    workspace = inventory.create_workspace(name="Acme")
    now = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
    retention.set_policy(
        workspace_id=workspace.id,
        enabled=True,
        evidence_retention_days=30,
        audit_retention_days=90,
        sweep_interval_hours=24,
        updated_by="owner",
        now=now,
    )

    first = retention.run_due_retention(now=now)
    assert len(first) == 1
    assert retention.run_due_retention(now=now + timedelta(hours=23)) == []
    assert len(retention.run_due_retention(now=now + timedelta(hours=24))) == 1

    retention.purge_workspace(workspace.id)
    with inventory.SessionLocal() as session:
        assert session.get(WorkspaceRetentionPolicyRecord, workspace.id) is None


def test_scheduler_skip_path_does_not_treat_unavailable_policy_as_failure(
    tmp_path: Path,
) -> None:
    inventory, retention = _repo(tmp_path)
    workspace = inventory.create_workspace(name="Acme")

    assert (
        retention.prune_workspace_history(
            workspace_id=workspace.id,
            only_if_due=True,
        )
        is None
    )
    with pytest.raises(ValueError, match="has not been configured"):
        retention.prune_workspace_history(workspace_id=workspace.id)


def test_retention_is_disabled_until_owner_configures_it(tmp_path: Path) -> None:
    inventory, retention = _repo(tmp_path)
    workspace = inventory.create_workspace(name="Acme")
    policy = retention.get_policy(workspace.id)
    assert policy.enabled is False
    assert retention.run_due_retention(now=datetime.now(UTC)) == []
