from __future__ import annotations

import argparse
import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass

from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
from cryptohawk.domain.models import ScanContext
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


class LoadSoakError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Workload:
    workspaces: int
    assets_per_workspace: int
    rounds: int
    workers: int
    concurrency_per_workspace: int
    retry_every: int

    @property
    def assets(self) -> int:
        return self.workspaces * self.assets_per_workspace

    @property
    def jobs(self) -> int:
        return self.assets * self.rounds


def _database_url() -> str:
    value = os.environ.get("CRYPTOHAWK_DATABASE_URL", "").strip()
    if not value:
        raise LoadSoakError("CRYPTOHAWK_DATABASE_URL is required")
    if not value.startswith("postgresql"):
        raise LoadSoakError("load/soak validation requires PostgreSQL")
    return value


def _validate(workload: Workload) -> None:
    if not 2 <= workload.workspaces <= 50:
        raise LoadSoakError("workspaces must be between 2 and 50")
    if not 1 <= workload.assets_per_workspace <= 1000:
        raise LoadSoakError("assets_per_workspace must be between 1 and 1000")
    if not 1 <= workload.rounds <= 100:
        raise LoadSoakError("rounds must be between 1 and 100")
    if not 1 <= workload.workers <= 100:
        raise LoadSoakError("workers must be between 1 and 100")
    if not 1 <= workload.concurrency_per_workspace <= 100:
        raise LoadSoakError("concurrency_per_workspace must be between 1 and 100")
    if workload.retry_every < 0:
        raise LoadSoakError("retry_every cannot be negative")


def run(workload: Workload) -> dict[str, object]:
    _validate(workload)
    inventory = InventoryRepository(_database_url())
    quota = QuotaRepository(inventory)
    queue = ScanQueueRepository(inventory, quota)

    started = time.monotonic()
    workspace_assets: dict[str, list[str]] = {}
    for workspace_index in range(workload.workspaces):
        workspace = inventory.create_workspace(
            name=f"Load Soak {workspace_index:02d}",
            slug=f"load-soak-{workspace_index:02d}",
        )
        assets: list[str] = []
        for asset_index in range(workload.assets_per_workspace):
            asset = inventory.create_asset(
                workspace_id=workspace.id,
                name=f"Endpoint {asset_index:04d}",
                kind=ManagedAssetKind.TLS_ENDPOINT,
                locator=(
                    f"load-{workspace_index:02d}-{asset_index:04d}.example.test:443"
                ),
                context=ScanContext(
                    internet_exposed=asset_index % 3 == 0,
                    asset_criticality=1 + (asset_index % 10),
                    data_lifetime_years=1 + (asset_index % 12),
                    environment=("production" if asset_index % 2 == 0 else "staging"),
                ),
                tags={"load-soak": "true", "workspace": str(workspace_index)},
            )
            assets.append(asset.id)
        workspace_assets[workspace.id] = assets

    all_jobs: list[str] = []
    retry_jobs: set[str] = set()
    ordinal = 0
    for round_index in range(workload.rounds):
        # Intentionally enqueue tenant-by-tenant. This creates deep contiguous
        # backlogs and exercises fairness rather than relying on interleaved input.
        for workspace_id, asset_ids in workspace_assets.items():
            for asset_id in asset_ids:
                job = queue.enqueue(
                    workspace_id=workspace_id,
                    asset_id=asset_id,
                    kind=ScanKind.TLS,
                    max_attempts=3,
                )
                all_jobs.append(job.id)
                ordinal += 1
                if workload.retry_every and ordinal % workload.retry_every == 0:
                    retry_jobs.add(job.id)
        print(
            f"load_soak_enqueued_round={round_index + 1} total_jobs={len(all_jobs)}",
            flush=True,
        )

    completed = 0
    retries_scheduled = 0
    claims = 0
    worker_cursor = 0
    max_active: dict[str, int] = defaultdict(int)

    while completed < workload.jobs:
        leases = []
        for _ in range(workload.workers):
            worker_id = f"load-worker-{worker_cursor % workload.workers:03d}"
            worker_cursor += 1
            lease = queue.claim_next(
                worker_id=worker_id,
                lease_seconds=60,
                concurrency_limit=workload.concurrency_per_workspace,
            )
            if lease is None:
                break
            leases.append(lease)
            claims += 1
            capacity = quota.scan_capacity(
                workspace_id=lease.job.workspace_id,
                limit=workload.concurrency_per_workspace,
            )
            if capacity.active_scans > workload.concurrency_per_workspace:
                raise LoadSoakError("workspace scan capacity exceeded configured limit")
            max_active[lease.job.workspace_id] = max(
                max_active[lease.job.workspace_id], capacity.active_scans
            )

        if not leases:
            raise LoadSoakError(
                f"queue stalled with {workload.jobs - completed} jobs incomplete"
            )

        for lease in leases:
            if lease.job.id in retry_jobs and lease.attempt == 1:
                queue.fail(
                    job_id=lease.job.id,
                    worker_id=lease.worker_id,
                    error_message="synthetic transient load-soak retry",
                    retryable=True,
                    backoff_seconds=0,
                )
                retries_scheduled += 1
                continue

            if claims % 17 == 0:
                queue.heartbeat(
                    job_id=lease.job.id,
                    worker_id=lease.worker_id,
                    lease_seconds=60,
                )
            queue.complete(
                job_id=lease.job.id,
                worker_id=lease.worker_id,
                findings_count=lease.attempt % 3,
            )
            completed += 1

        if completed and completed % 200 == 0:
            print(f"load_soak_completed={completed}", flush=True)

    for workspace_id in workspace_assets:
        jobs = inventory.list_scan_jobs(
            workspace_id=workspace_id,
            limit=workload.assets_per_workspace * workload.rounds + 10,
        )
        expected = workload.assets_per_workspace * workload.rounds
        if len(jobs) != expected:
            raise LoadSoakError(
                f"workspace {workspace_id} has {len(jobs)} jobs; expected {expected}"
            )
        if any(job.status != ScanStatus.SUCCEEDED for job in jobs):
            raise LoadSoakError(f"workspace {workspace_id} retained non-success jobs")
        capacity = quota.scan_capacity(
            workspace_id=workspace_id,
            limit=workload.concurrency_per_workspace,
        )
        if capacity.active_scans != 0:
            raise LoadSoakError(f"workspace {workspace_id} leaked scan capacity")
        if max_active[workspace_id] < 1:
            raise LoadSoakError(f"workspace {workspace_id} was starved")

    if quota.reconcile_scan_slots() != 0:
        raise LoadSoakError("quota reconciliation found leaked runtime capacity")

    for job_id in all_jobs:
        state = queue.get_state(job_id)
        if state is None:
            raise LoadSoakError(f"queue state disappeared for {job_id}")
        expected_attempts = 2 if job_id in retry_jobs else 1
        if state.attempts != expected_attempts:
            raise LoadSoakError(
                f"job {job_id} attempts={state.attempts}; expected {expected_attempts}"
            )
        if state.lease_owner is not None or state.lease_expires_at is not None:
            raise LoadSoakError(f"job {job_id} retained a finished lease")

    elapsed = time.monotonic() - started
    result: dict[str, object] = {
        "workspaces": workload.workspaces,
        "assets": workload.assets,
        "jobs": workload.jobs,
        "claims": claims,
        "synthetic_retries": retries_scheduled,
        "elapsed_seconds": round(elapsed, 3),
        "jobs_per_second": round(workload.jobs / elapsed, 3) if elapsed else None,
        "max_active_scans": max(max_active.values(), default=0),
        "status": "passed",
    }
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exercise CryptoHawk queue/quota persistence under sustained PostgreSQL churn."
    )
    parser.add_argument("--workspaces", type=int, default=4)
    parser.add_argument("--assets-per-workspace", type=int, default=40)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--concurrency-per-workspace", type=int, default=4)
    parser.add_argument("--retry-every", type=int, default=20)
    args = parser.parse_args()
    run(
        Workload(
            workspaces=args.workspaces,
            assets_per_workspace=args.assets_per_workspace,
            rounds=args.rounds,
            workers=args.workers,
            concurrency_per_workspace=args.concurrency_per_workspace,
            retry_every=args.retry_every,
        )
    )


if __name__ == "__main__":
    main()
