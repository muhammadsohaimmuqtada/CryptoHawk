from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
from cryptohawk.domain.models import ScanContext
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository


def _queue(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'queue.db'}"
    inventory = InventoryRepository(url)
    queue = ScanQueueRepository(inventory)
    queue.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Public API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="example.com:443",
        context=ScanContext(internet_exposed=True),
    )
    return inventory, queue, workspace, asset


def test_single_owner_claim_and_heartbeat(tmp_path: Path) -> None:
    _, queue, workspace, asset = _queue(tmp_path)
    now = datetime(2026, 8, 10, tzinfo=UTC)
    job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        now=now,
    )

    lease = queue.claim_next(worker_id="worker-a", lease_seconds=30, now=now)
    assert lease is not None
    assert lease.job.id == job.id
    assert lease.job.status == ScanStatus.RUNNING
    assert lease.attempt == 1
    assert queue.claim_next(worker_id="worker-b", lease_seconds=30, now=now) is None

    renewed = queue.heartbeat(
        job_id=job.id,
        worker_id="worker-a",
        lease_seconds=60,
        now=now + timedelta(seconds=10),
    )
    assert renewed.lease_expires_at == now + timedelta(seconds=70)

    with pytest.raises(RuntimeError):
        queue.heartbeat(
            job_id=job.id,
            worker_id="worker-b",
            lease_seconds=60,
            now=now + timedelta(seconds=10),
        )


def test_retry_then_terminal_failure(tmp_path: Path) -> None:
    inventory, queue, workspace, asset = _queue(tmp_path)
    now = datetime(2026, 8, 10, tzinfo=UTC)
    job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=2,
        now=now,
    )
    first = queue.claim_next(worker_id="worker-a", now=now)
    assert first is not None

    retried = queue.fail(
        job_id=job.id,
        worker_id="worker-a",
        error_message="temporary network error",
        retryable=True,
        backoff_seconds=10,
        now=now,
    )
    assert retried.status == ScanStatus.QUEUED
    assert queue.claim_next(worker_id="worker-b", now=now + timedelta(seconds=5)) is None

    second = queue.claim_next(worker_id="worker-b", now=now + timedelta(seconds=10))
    assert second is not None
    assert second.attempt == 2
    failed = queue.fail(
        job_id=job.id,
        worker_id="worker-b",
        error_message="still unavailable",
        retryable=True,
        now=now + timedelta(seconds=11),
    )
    assert failed.status == ScanStatus.FAILED

    stored = inventory.get_scan_job(workspace_id=workspace.id, job_id=job.id)
    assert stored is not None
    assert stored.status == ScanStatus.FAILED


def test_expired_lease_recovery_and_queued_cancel(tmp_path: Path) -> None:
    inventory, queue, workspace, asset = _queue(tmp_path)
    now = datetime(2026, 8, 10, tzinfo=UTC)
    job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=3,
        now=now,
    )
    lease = queue.claim_next(worker_id="worker-a", lease_seconds=10, now=now)
    assert lease is not None

    requeued, terminated = queue.recover_expired_leases(now=now + timedelta(seconds=11))
    assert (requeued, terminated) == (1, 0)
    recovered = inventory.get_scan_job(workspace_id=workspace.id, job_id=job.id)
    assert recovered is not None
    assert recovered.status == ScanStatus.QUEUED

    canceled = queue.request_cancel(job_id=job.id, now=now + timedelta(seconds=12))
    assert canceled.status == ScanStatus.CANCELED
    assert queue.claim_next(worker_id="worker-b", now=now + timedelta(seconds=13)) is None


def test_running_cancel_requires_worker_acknowledgement(tmp_path: Path) -> None:
    inventory, queue, workspace, asset = _queue(tmp_path)
    now = datetime(2026, 8, 10, tzinfo=UTC)
    job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        now=now,
    )
    lease = queue.claim_next(worker_id="worker-a", now=now)
    assert lease is not None

    running = queue.request_cancel(job_id=job.id, now=now + timedelta(seconds=1))
    assert running.status == ScanStatus.RUNNING
    assert queue.should_cancel(job_id=job.id, worker_id="worker-a") is True

    canceled = queue.acknowledge_cancel(
        job_id=job.id,
        worker_id="worker-a",
        now=now + timedelta(seconds=2),
    )
    assert canceled.status == ScanStatus.CANCELED
    stored = inventory.get_scan_job(workspace_id=workspace.id, job_id=job.id)
    assert stored is not None
    assert stored.status == ScanStatus.CANCELED


def test_final_expired_lease_becomes_failure(tmp_path: Path) -> None:
    inventory, queue, workspace, asset = _queue(tmp_path)
    now = datetime(2026, 8, 10, tzinfo=UTC)
    job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=1,
        now=now,
    )
    lease = queue.claim_next(worker_id="worker-a", lease_seconds=10, now=now)
    assert lease is not None

    requeued, terminated = queue.recover_expired_leases(now=now + timedelta(seconds=11))
    assert (requeued, terminated) == (0, 1)
    stored = inventory.get_scan_job(workspace_id=workspace.id, job_id=job.id)
    assert stored is not None
    assert stored.status == ScanStatus.FAILED
    assert stored.error_message == "worker lease expired after final attempt"
