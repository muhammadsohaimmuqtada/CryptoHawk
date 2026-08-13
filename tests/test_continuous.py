from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptohawk.domain.continuous import DriftEventType, ScanOrigin
from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind
from cryptohawk.domain.models import (
    AssetType,
    CryptoObservation,
    Evidence,
    Finding,
    Primitive,
    QuantumStatus,
    RiskAssessment,
    ScanContext,
    Severity,
)
from cryptohawk.services.executor import AssetScanExecutor
from cryptohawk.services.scheduler import ScanScheduler, SchedulerConfig
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


def _stack(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'continuous.db'}"
    inventory = InventoryRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    continuous = ContinuousRepository(inventory)
    continuous.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Public API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="example.com:443",
        context=ScanContext(internet_exposed=True),
    )
    return inventory, quota, queue, continuous, workspace, asset


def _finding(
    asset_id: str,
    algorithm: str,
    *,
    score: int,
    line: int | None = None,
    snippet: str | None = None,
) -> Finding:
    observation = CryptoObservation(
        asset_id=asset_id,
        asset_name="Public API",
        asset_type=AssetType.TLS_ENDPOINT,
        algorithm=algorithm,
        family=algorithm.lower(),
        primitive=Primitive.PKE,
        evidence=Evidence(
            source="tls",
            locator="example.com:443",
            line=line,
            snippet=snippet or algorithm,
        ),
    )
    risk = RiskAssessment(
        observation_id=observation.id,
        score=score,
        severity=Severity.HIGH,
        quantum_status=QuantumStatus.VULNERABLE,
        reasons=["test exposure"],
    )
    return Finding(observation=observation, risk=risk)


def test_prepare_findings_deduplicates_and_uses_deterministic_ids(tmp_path: Path) -> None:
    _, _, _, continuous, _, asset = _stack(tmp_path)
    low = _finding(asset.id, "RSA", score=60)
    high = _finding(asset.id, "RSA", score=80)

    first = continuous.prepare_findings("job-1", [low, high])
    second = continuous.prepare_findings("job-1", [high, low])

    assert len(first) == 1
    assert len(second) == 1
    assert first[0].risk.score == 80
    assert first[0].observation.id == second[0].observation.id
    assert first[0].risk.observation_id == first[0].observation.id


def test_history_baseline_then_detects_introduced_resolved_and_risk_change(
    tmp_path: Path,
) -> None:
    inventory, _, _, continuous, workspace, asset = _stack(tmp_path)
    baseline_job = inventory.create_scan_job(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )
    baseline = continuous.prepare_findings(
        baseline_job.id,
        [
            _finding(asset.id, "RSA", score=60),
            _finding(asset.id, "SHA-1", score=70, line=1),
        ],
    )
    assert continuous.record_successful_scan(
        workspace_id=workspace.id,
        asset_id=asset.id,
        scan_job_id=baseline_job.id,
        findings=baseline,
    ) == []

    second_job = inventory.create_scan_job(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )
    second = continuous.prepare_findings(
        second_job.id,
        [
            _finding(asset.id, "RSA", score=80),
            _finding(asset.id, "AES-256", score=20, line=2),
        ],
    )
    events = continuous.record_successful_scan(
        workspace_id=workspace.id,
        asset_id=asset.id,
        scan_job_id=second_job.id,
        findings=second,
    )

    event_types = {event.event_type for event in events}
    assert DriftEventType.INTRODUCED in event_types
    assert DriftEventType.RESOLVED in event_types
    assert DriftEventType.RISK_INCREASED in event_types

    replayed = continuous.record_successful_scan(
        workspace_id=workspace.id,
        asset_id=asset.id,
        scan_job_id=second_job.id,
        findings=second,
    )
    assert len(replayed) == len(events)
    assert len(continuous.list_drift_events(workspace_id=workspace.id)) == len(events)

    states = continuous.list_observation_states(
        workspace_id=workspace.id,
        asset_id=asset.id,
    )
    active_fingerprints = {state.fingerprint for state in states if state.active}
    assert len(active_fingerprints) == 2
    assert sum(not state.active for state in states) == 1

    history = continuous.list_scan_history(
        workspace_id=workspace.id,
        asset_id=asset.id,
    )
    assert len(history) == 2
    assert history[0].origin == ScanOrigin.API


def test_scheduler_occurrence_is_idempotent_and_skips_missed_backlog(tmp_path: Path) -> None:
    inventory, _, queue, continuous, workspace, asset = _stack(tmp_path)
    now = datetime(2026, 8, 13, 5, 0, tzinfo=UTC)
    schedule = continuous.create_schedule(
        workspace_id=workspace.id,
        asset_id=asset.id,
        interval_seconds=60,
        max_attempts=3,
        first_run_at=now - timedelta(hours=1),
        created_by="session:owner",
        now=now - timedelta(hours=1),
    )
    scheduler = ScanScheduler(
        inventory,
        queue,
        continuous,
        executor=AssetScanExecutor(),
        config=SchedulerConfig(poll_interval=1, batch_size=10),
    )

    assert scheduler.run_once(now=now) == 1
    job_id = continuous.scheduled_job_id(schedule.id, schedule.next_run_at)
    job = inventory.get_scan_job(workspace_id=workspace.id, job_id=job_id)
    assert job is not None
    assert queue.get_state(job_id) is not None

    duplicate = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=3,
        now=now,
        job_id=job_id,
    )
    assert duplicate.id == job_id
    assert scheduler.run_once(now=now) == 0

    updated = continuous.get_schedule(
        workspace_id=workspace.id,
        schedule_id=schedule.id,
    )
    assert updated is not None
    assert updated.last_run_at == schedule.next_run_at
    assert updated.next_run_at > now
