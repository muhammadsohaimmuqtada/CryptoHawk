from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from sqlalchemy.exc import SQLAlchemyError

from cryptohawk.config import settings
from cryptohawk.domain.inventory import ManagedAssetKind
from cryptohawk.services.executor import AssetScanError, AssetScanExecutor
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    worker_id: str
    lease_seconds: int = 60
    poll_interval: float = 1.0
    retry_backoff_seconds: int = 5
    scan_timeout: float = 5.0

    def __post_init__(self) -> None:
        if not self.worker_id.strip():
            raise ValueError("worker_id is required")
        if not 5 <= self.lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 5 and 3600")
        if not 0.1 <= self.poll_interval <= 60:
            raise ValueError("poll_interval must be between 0.1 and 60 seconds")
        if self.retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds cannot be negative")
        if not 0.5 <= self.scan_timeout <= 120:
            raise ValueError("scan_timeout must be between 0.5 and 120 seconds")


class ScanWorker:
    def __init__(
        self,
        inventory: InventoryRepository,
        findings: FindingRepository,
        queue: ScanQueueRepository,
        *,
        executor: AssetScanExecutor,
        config: WorkerConfig,
        history: ContinuousRepository | None = None,
    ) -> None:
        self.inventory = inventory
        self.findings = findings
        self.queue = queue
        self.executor = executor
        self.config = config
        self.history = history

    def run_once(self) -> bool:
        self.queue.recover_expired_leases()
        lease = self.queue.claim_next(
            worker_id=self.config.worker_id,
            lease_seconds=self.config.lease_seconds,
            concurrency_limit=settings.workspace_scan_concurrency,
        )
        if lease is None:
            return False

        job = lease.job
        try:
            if self.queue.should_cancel(job_id=job.id, worker_id=self.config.worker_id):
                self.queue.acknowledge_cancel(
                    job_id=job.id,
                    worker_id=self.config.worker_id,
                )
                return True

            asset = self.inventory.get_asset(
                workspace_id=job.workspace_id,
                asset_id=job.asset_id,
            )
            if asset is None:
                raise AssetScanError("managed asset no longer exists")
            if asset.kind == ManagedAssetKind.SOURCE:
                raise AssetScanError(
                    "durable source scans require a repository-backed source collector"
                )

            if self._heartbeat_or_cancel(job.id):
                return True
            results = self.executor.execute(asset, timeout=self.config.scan_timeout)
            if self.history is not None:
                results = self.history.prepare_findings(job.id, results)

            if self.queue.should_cancel(job_id=job.id, worker_id=self.config.worker_id):
                self.queue.acknowledge_cancel(
                    job_id=job.id,
                    worker_id=self.config.worker_id,
                )
                return True

            self.findings.upsert_many(
                results,
                workspace_id=job.workspace_id,
                managed_asset_id=asset.id,
                scan_job_id=job.id,
            )
            if self.history is not None:
                self.history.record_successful_scan(
                    workspace_id=job.workspace_id,
                    asset_id=asset.id,
                    scan_job_id=job.id,
                    findings=results,
                )
            self.queue.complete(
                job_id=job.id,
                worker_id=self.config.worker_id,
                findings_count=len(results),
            )
            return True
        except Exception as exc:
            retryable = (
                isinstance(exc, OSError) and not isinstance(exc, AssetScanError)
            ) or isinstance(exc, SQLAlchemyError)
            logger.warning(
                "scan job %s failed on attempt %s/%s: %s",
                job.id,
                lease.attempt,
                lease.max_attempts,
                exc,
            )
            self.queue.fail(
                job_id=job.id,
                worker_id=self.config.worker_id,
                error_message=str(exc),
                retryable=retryable,
                backoff_seconds=self.config.retry_backoff_seconds,
            )
            return True

    def run_forever(self) -> None:
        logger.info("CryptoHawk worker %s started", self.config.worker_id)
        while True:
            worked = self.run_once()
            if not worked:
                time.sleep(self.config.poll_interval)

    def _heartbeat_or_cancel(self, job_id: str) -> bool:
        try:
            self.queue.heartbeat(
                job_id=job_id,
                worker_id=self.config.worker_id,
                lease_seconds=self.config.lease_seconds,
            )
            return False
        except RuntimeError:
            if self.queue.should_cancel(job_id=job_id, worker_id=self.config.worker_id):
                self.queue.acknowledge_cancel(
                    job_id=job_id,
                    worker_id=self.config.worker_id,
                )
                return True
            raise
