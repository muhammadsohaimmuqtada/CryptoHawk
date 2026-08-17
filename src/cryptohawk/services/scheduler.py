from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptohawk.domain.inventory import ManagedAssetKind
from cryptohawk.observability import (
    SCHEDULER_ENQUEUED,
    SCHEDULER_RUNS,
    configure_observability,
    log_event,
    traced_operation,
)
from cryptohawk.services.executor import AssetScanError, AssetScanExecutor
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.retention import WorkspaceRetentionRepository

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SchedulerConfig:
    poll_interval: float = 5.0
    batch_size: int = 100

    def __post_init__(self) -> None:
        if not 0.5 <= self.poll_interval <= 300:
            raise ValueError("poll_interval must be between 0.5 and 300 seconds")
        if not 1 <= self.batch_size <= 1000:
            raise ValueError("batch_size must be between 1 and 1000")


class ScanScheduler:
    def __init__(
        self,
        inventory: InventoryRepository,
        queue: ScanQueueRepository,
        continuous: ContinuousRepository,
        *,
        executor: AssetScanExecutor,
        config: SchedulerConfig | None = None,
        retention: WorkspaceRetentionRepository | None = None,
    ) -> None:
        self.inventory = inventory
        self.queue = queue
        self.continuous = continuous
        self.executor = executor
        self.config = config or SchedulerConfig()
        self.retention = retention

    def run_once(self, *, now: datetime | None = None) -> int:
        configure_observability()
        outcome = "failed"
        with traced_operation(
            "scheduler.run",
            attributes={"cryptohawk.scheduler.batch_size": self.config.batch_size},
            component="scheduler",
        ) as span:
            try:
                current = now or datetime.now(UTC)
                if self.retention is not None:
                    sweeps = self.retention.run_due_retention(
                        now=current,
                        limit=min(self.config.batch_size, 100),
                    )
                    span.set_attribute("cryptohawk.retention.sweep_count", len(sweeps))
                    for sweep in sweeps:
                        log_event(
                            logger,
                            logging.INFO,
                            "retention.sweep.completed",
                            workspace_id=sweep.workspace_id,
                            deleted_rows=sum(sweep.deleted_rows.values()),
                            protected_evidence_jobs=sweep.protected_evidence_jobs,
                        )

                schedules = self.continuous.list_due_schedules(
                    now=current,
                    limit=self.config.batch_size,
                )
                span.set_attribute("cryptohawk.scheduler.due_count", len(schedules))
                enqueued = 0
                for schedule in schedules:
                    asset = self.inventory.get_asset(
                        workspace_id=schedule.workspace_id,
                        asset_id=schedule.asset_id,
                    )
                    if asset is None:
                        continue
                    if not asset.enabled:
                        self.continuous.set_schedule_enabled(
                            workspace_id=schedule.workspace_id,
                            schedule_id=schedule.id,
                            enabled=False,
                            now=current,
                        )
                        continue
                    if asset.kind == ManagedAssetKind.SOURCE:
                        self.continuous.set_schedule_enabled(
                            workspace_id=schedule.workspace_id,
                            schedule_id=schedule.id,
                            enabled=False,
                            now=current,
                        )
                        log_event(
                            logger,
                            logging.WARNING,
                            "scheduler.schedule.paused",
                            schedule_id=schedule.id,
                            reason="source-requires-repository-collector",
                        )
                        continue

                    try:
                        kind = self.executor.scan_kind(asset)
                    except AssetScanError as exc:
                        self.continuous.set_schedule_enabled(
                            workspace_id=schedule.workspace_id,
                            schedule_id=schedule.id,
                            enabled=False,
                            now=current,
                        )
                        log_event(
                            logger,
                            logging.WARNING,
                            "scheduler.schedule.paused",
                            schedule_id=schedule.id,
                            reason="unsupported-scan-kind",
                            error_type=type(exc).__name__,
                        )
                        continue

                    scheduled_for = schedule.next_run_at
                    job_id = self.continuous.scheduled_job_id(schedule.id, scheduled_for)
                    job = self.queue.enqueue(
                        workspace_id=schedule.workspace_id,
                        asset_id=schedule.asset_id,
                        kind=kind,
                        max_attempts=schedule.max_attempts,
                        now=current,
                        job_id=job_id,
                    )
                    self.continuous.record_scheduled_execution(
                        schedule=schedule,
                        job_id=job.id,
                        scheduled_for=scheduled_for,
                        now=current,
                    )
                    if self.continuous.advance_schedule(
                        schedule=schedule,
                        scheduled_for=scheduled_for,
                        now=current,
                    ):
                        enqueued += 1
                        SCHEDULER_ENQUEUED.inc()
                span.set_attribute("cryptohawk.scheduler.enqueued_count", enqueued)
                outcome = "succeeded"
                return enqueued
            finally:
                SCHEDULER_RUNS.labels(outcome).inc()

    def run_forever(self) -> None:
        configure_observability()
        log_event(logger, logging.INFO, "scheduler.started")
        while True:
            processed = self.run_once()
            if processed == 0:
                time.sleep(self.config.poll_interval)
