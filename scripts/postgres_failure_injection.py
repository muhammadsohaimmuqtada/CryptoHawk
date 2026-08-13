from __future__ import annotations

import argparse
import subprocess
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
from cryptohawk.domain.models import ScanContext
from cryptohawk.services.worker import ScanWorker, WorkerConfig
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


class FailureInjectionError(RuntimeError):
    pass


class TransientNetworkExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def execute(
        self,
        asset,
        *,
        source=None,
        filename=None,
        timeout=5.0,
        scan_job_id=None,
    ):
        del asset, source, filename, timeout, scan_job_id
        self.calls += 1
        if self.calls == 1:
            raise OSError("synthetic upstream network interruption")
        return []


class DatabaseStoppingExecutor:
    def __init__(self, container_id: str) -> None:
        self.container_id = container_id

    def execute(
        self,
        asset,
        *,
        source=None,
        filename=None,
        timeout=5.0,
        scan_job_id=None,
    ):
        del asset, source, filename, timeout, scan_job_id
        subprocess.run(
            ["docker", "stop", "--time", "1", self.container_id],
            check=True,
            capture_output=True,
            text=True,
        )
        return []


class SuccessfulExecutor:
    def execute(
        self,
        asset,
        *,
        source=None,
        filename=None,
        timeout=5.0,
        scan_job_id=None,
    ):
        del asset, source, filename, timeout, scan_job_id
        return []


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise FailureInjectionError(message)


def _restart_postgres(container_id: str) -> None:
    subprocess.run(
        ["docker", "start", container_id],
        check=True,
        capture_output=True,
        text=True,
    )
    for _ in range(30):
        ready = subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "pg_isready",
                "-U",
                "cryptohawk",
                "-d",
                "cryptohawk_failure",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if ready.returncode == 0:
            return
        time.sleep(1)
    raise FailureInjectionError("PostgreSQL did not become ready after injected restart")


def _worker(
    inventory: InventoryRepository,
    findings: FindingRepository,
    queue: ScanQueueRepository,
    *,
    worker_id: str,
    executor,
) -> ScanWorker:
    return ScanWorker(
        inventory,
        findings,
        queue,
        executor=executor,
        config=WorkerConfig(
            worker_id=worker_id,
            lease_seconds=5,
            poll_interval=0.1,
            retry_backoff_seconds=0,
            scan_timeout=1.0,
        ),
    )


def run(database_url: str, postgres_container: str) -> None:
    inventory = InventoryRepository(database_url)
    findings = FindingRepository(database_url)
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)

    workspace = inventory.create_workspace(
        name="Failure Injection",
        slug="failure-injection",
    )
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Failure Injection Endpoint",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="failure-injection.example.test:443",
        context=ScanContext(internet_exposed=True, asset_criticality=8),
        tags={"failure-injection": "true"},
    )

    print("failure_injection=worker_lease_expiry", flush=True)
    crash_job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=2,
    )
    t0 = datetime.now(UTC)
    abandoned = queue.claim_next(
        worker_id="crashed-worker",
        lease_seconds=5,
        concurrency_limit=1,
        now=t0,
    )
    _expect(abandoned is not None, "crash fixture could not claim job")
    _expect(abandoned.job.id == crash_job.id, "crash fixture claimed the wrong job")
    _expect(
        quota.scan_capacity(workspace_id=workspace.id, limit=1).active_scans == 1,
        "claimed crash fixture did not consume capacity",
    )

    requeued, failed = queue.recover_expired_leases(now=t0 + timedelta(seconds=6))
    _expect((requeued, failed) == (1, 0), "expired worker lease was not requeued")
    _expect(
        quota.scan_capacity(workspace_id=workspace.id, limit=1).active_scans == 0,
        "expired worker lease leaked capacity",
    )
    recovered = queue.claim_next(
        worker_id="recovery-worker",
        lease_seconds=5,
        concurrency_limit=1,
        now=t0 + timedelta(seconds=7),
    )
    _expect(recovered is not None and recovered.attempt == 2, "recovered job attempt is wrong")
    queue.complete(
        job_id=crash_job.id,
        worker_id="recovery-worker",
        findings_count=0,
        now=t0 + timedelta(seconds=8),
    )

    print("failure_injection=final_lease_expiry", flush=True)
    terminal_job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=1,
    )
    terminal_start = t0 + timedelta(seconds=20)
    terminal_lease = queue.claim_next(
        worker_id="terminal-crash-worker",
        lease_seconds=5,
        concurrency_limit=1,
        now=terminal_start,
    )
    _expect(terminal_lease is not None, "terminal crash fixture could not claim job")
    requeued, failed = queue.recover_expired_leases(
        now=terminal_start + timedelta(seconds=6)
    )
    _expect((requeued, failed) == (0, 1), "final expired attempt was not failed")
    terminal = inventory.get_scan_job(
        workspace_id=workspace.id,
        job_id=terminal_job.id,
    )
    _expect(terminal is not None and terminal.status == ScanStatus.FAILED, "terminal state wrong")
    _expect(
        quota.scan_capacity(workspace_id=workspace.id, limit=1).active_scans == 0,
        "terminal lease expiry leaked capacity",
    )

    print("failure_injection=transient_network", flush=True)
    network_job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=2,
    )
    network_executor = TransientNetworkExecutor()
    network_worker = _worker(
        inventory,
        findings,
        queue,
        worker_id="network-worker",
        executor=network_executor,
    )
    _expect(network_worker.run_once(), "network worker did not claim first attempt")
    after_failure = inventory.get_scan_job(
        workspace_id=workspace.id,
        job_id=network_job.id,
    )
    _expect(
        after_failure is not None and after_failure.status == ScanStatus.QUEUED,
        "transient network failure was not scheduled for retry",
    )
    _expect(network_worker.run_once(), "network worker did not claim retry")
    after_retry = inventory.get_scan_job(
        workspace_id=workspace.id,
        job_id=network_job.id,
    )
    _expect(
        after_retry is not None and after_retry.status == ScanStatus.SUCCEEDED,
        "transient network retry did not succeed",
    )
    network_state = queue.get_state(network_job.id)
    _expect(network_state is not None and network_state.attempts == 2, "network attempts wrong")

    print("failure_injection=database_interruption", flush=True)
    database_job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=2,
    )
    database_worker = _worker(
        inventory,
        findings,
        queue,
        worker_id="database-fault-worker",
        executor=DatabaseStoppingExecutor(postgres_container),
    )
    database_went_down = False
    try:
        database_worker.run_once()
    except (SQLAlchemyError, OSError):
        database_went_down = True
    finally:
        _restart_postgres(postgres_container)
    _expect(database_went_down, "database interruption did not break the in-flight worker")

    # Reuse the same engine objects after restart. pool_pre_ping must discard stale
    # connections. Then let the real wall clock cross the existing durable lease
    # deadline instead of manufacturing a future queue timestamp that a replacement
    # ScanWorker cannot yet observe.
    with inventory.engine.connect() as connection:
        _expect(connection.execute(text("SELECT 1")).scalar_one() == 1, "database did not recover")

    outage_state = queue.get_state(database_job.id)
    _expect(
        outage_state is not None and outage_state.lease_expires_at is not None,
        "database-outage job lost its durable lease state",
    )
    remaining = (outage_state.lease_expires_at - datetime.now(UTC)).total_seconds()
    if remaining > 0:
        time.sleep(remaining + 0.25)

    requeued, failed = queue.recover_expired_leases()
    _expect((requeued, failed) == (1, 0), "database-outage lease was not recovered")
    recovery_worker = _worker(
        inventory,
        findings,
        queue,
        worker_id="database-recovery-worker",
        executor=SuccessfulExecutor(),
    )
    _expect(recovery_worker.run_once(), "recovery worker did not reclaim database-outage job")
    recovered_job = inventory.get_scan_job(
        workspace_id=workspace.id,
        job_id=database_job.id,
    )
    _expect(
        recovered_job is not None and recovered_job.status == ScanStatus.SUCCEEDED,
        "database-outage job did not complete after restart",
    )
    recovered_state = queue.get_state(database_job.id)
    _expect(
        recovered_state is not None and recovered_state.attempts == 2,
        "database-outage recovery attempt accounting is wrong",
    )

    _expect(quota.reconcile_scan_slots() == 0, "failure injection left leaked capacity")
    print("failure_injection_status=passed", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--postgres-container", required=True)
    args = parser.parse_args()
    run(args.database_url, args.postgres_container)


if __name__ == "__main__":
    main()
