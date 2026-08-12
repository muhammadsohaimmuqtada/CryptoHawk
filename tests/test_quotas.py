from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cryptohawk.config import settings
from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind
from cryptohawk.domain.models import ScanContext
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository, ScanCapacityExceeded


def _inventory(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'quotas.db'}"
    inventory = InventoryRepository(url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)
    queue.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Public API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="example.com:443",
        context=ScanContext(internet_exposed=True),
    )
    return url, inventory, quota, queue, workspace, asset


def test_fixed_window_rate_limit_resets_cleanly(tmp_path: Path) -> None:
    _, _, quota, _, _, _ = _inventory(tmp_path)
    now = datetime(2026, 8, 10, 12, 0, 5, tzinfo=UTC)

    first = quota.consume(
        scope_key="principal:user-1",
        action="api",
        limit=2,
        window_seconds=60,
        now=now,
    )
    second = quota.consume(
        scope_key="principal:user-1",
        action="api",
        limit=2,
        window_seconds=60,
        now=now + timedelta(seconds=1),
    )
    denied = quota.consume(
        scope_key="principal:user-1",
        action="api",
        limit=2,
        window_seconds=60,
        now=now + timedelta(seconds=2),
    )

    assert first.allowed is True and first.remaining == 1
    assert second.allowed is True and second.remaining == 0
    assert denied.allowed is False
    assert denied.retry_after_seconds > 0

    next_window = quota.consume(
        scope_key="principal:user-1",
        action="api",
        limit=2,
        window_seconds=60,
        now=now + timedelta(seconds=60),
    )
    assert next_window.allowed is True
    assert next_window.remaining == 1


def test_scan_slots_are_atomic_and_releasable(tmp_path: Path) -> None:
    _, _, quota, _, workspace, _ = _inventory(tmp_path)

    assert quota.acquire_scan_slot(workspace_id=workspace.id, limit=2) is True
    assert quota.acquire_scan_slot(workspace_id=workspace.id, limit=2) is True
    assert quota.acquire_scan_slot(workspace_id=workspace.id, limit=2) is False

    capacity = quota.scan_capacity(workspace_id=workspace.id, limit=2)
    assert capacity.active_scans == 2
    assert capacity.available == 0

    quota.release_scan_slot(workspace_id=workspace.id)
    assert quota.acquire_scan_slot(workspace_id=workspace.id, limit=2) is True


def test_reconcile_repairs_crash_leaked_capacity(tmp_path: Path) -> None:
    _, _, quota, _, workspace, _ = _inventory(tmp_path)
    assert quota.acquire_scan_slot(workspace_id=workspace.id, limit=1) is True
    assert quota.scan_capacity(workspace_id=workspace.id, limit=1).active_scans == 1

    changed = quota.reconcile_scan_slots()

    assert changed == 1
    assert quota.scan_capacity(workspace_id=workspace.id, limit=1).active_scans == 0


def test_queue_capacity_does_not_burn_retry_attempts(tmp_path: Path) -> None:
    _, _, quota, queue, workspace, asset = _inventory(tmp_path)
    first_job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )
    second_job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )

    first = queue.claim_next(
        worker_id="worker-a",
        lease_seconds=30,
        concurrency_limit=1,
    )
    assert first is not None
    assert first.job.id == first_job.id

    blocked = queue.claim_next(
        worker_id="worker-b",
        lease_seconds=30,
        concurrency_limit=1,
    )
    assert blocked is None
    second_state = queue.get_state(second_job.id)
    assert second_state is not None
    assert second_state.attempts == 0

    queue.complete(
        job_id=first_job.id,
        worker_id="worker-a",
        findings_count=0,
    )
    assert quota.scan_capacity(workspace_id=workspace.id, limit=1).active_scans == 0

    second = queue.claim_next(
        worker_id="worker-b",
        lease_seconds=30,
        concurrency_limit=1,
    )
    assert second is not None
    assert second.job.id == second_job.id
    assert second.attempt == 1


def test_saturated_workspace_does_not_starve_other_tenant(tmp_path: Path) -> None:
    _, inventory, _quota, queue, alpha, alpha_asset = _inventory(tmp_path)
    beta = inventory.create_workspace(name="Beta")
    beta_asset = inventory.create_asset(
        workspace_id=beta.id,
        name="Beta API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="beta.example.com:443",
        context=ScanContext(internet_exposed=True),
    )

    alpha_first = queue.enqueue(
        workspace_id=alpha.id,
        asset_id=alpha_asset.id,
        kind=ScanKind.TLS,
    )
    queue.enqueue(
        workspace_id=alpha.id,
        asset_id=alpha_asset.id,
        kind=ScanKind.TLS,
    )
    beta_job = queue.enqueue(
        workspace_id=beta.id,
        asset_id=beta_asset.id,
        kind=ScanKind.TLS,
    )

    first = queue.claim_next(
        worker_id="worker-alpha",
        lease_seconds=30,
        concurrency_limit=1,
    )
    assert first is not None and first.job.id == alpha_first.id

    cross_tenant = queue.claim_next(
        worker_id="worker-beta",
        lease_seconds=30,
        concurrency_limit=1,
    )
    assert cross_tenant is not None
    assert cross_tenant.job.id == beta_job.id
    assert cross_tenant.job.workspace_id == beta.id



def test_synchronous_scan_respects_shared_capacity(tmp_path: Path, monkeypatch) -> None:
    url, inventory, quota, _, workspace, asset = _inventory(tmp_path)
    findings = FindingRepository(url)
    findings.create_schema()
    service = ScanJobService(inventory, findings, quota=quota)
    monkeypatch.setattr(settings, "workspace_scan_concurrency", 1)

    assert quota.acquire_scan_slot(workspace_id=workspace.id, limit=1) is True
    with pytest.raises(ScanCapacityExceeded):
        service.run(workspace_id=workspace.id, asset_id=asset.id)

    capacity = quota.scan_capacity(workspace_id=workspace.id, limit=1)
    assert capacity.active_scans == 1
