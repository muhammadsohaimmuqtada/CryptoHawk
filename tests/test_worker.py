from pathlib import Path

from cryptohawk.domain.inventory import ManagedAssetKind, ScanKind, ScanStatus
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
from cryptohawk.services.worker import ScanWorker, WorkerConfig
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository


class FakeExecutor:
    def __init__(self, *, fail_once: bool = False) -> None:
        self.fail_once = fail_once
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
        del source, filename, timeout, scan_job_id
        self.calls += 1
        if self.fail_once and self.calls == 1:
            raise OSError("temporary network failure")
        observation = CryptoObservation(
            asset_id=asset.id,
            asset_name=asset.name,
            asset_type=AssetType.TLS_ENDPOINT,
            algorithm="RSA-2048",
            family="RSA",
            primitive=Primitive.PKE,
            key_size=2048,
            evidence=Evidence(source="tls", locator=asset.locator),
        )
        return [
            Finding(
                observation=observation,
                risk=RiskAssessment(
                    observation_id=observation.id,
                    score=90,
                    severity=Severity.CRITICAL,
                    quantum_status=QuantumStatus.VULNERABLE,
                    reasons=["test"],
                    migration_target="ML-KEM",
                ),
            )
        ]


def _worker(tmp_path: Path, *, executor=None):
    url = f"sqlite:///{tmp_path / 'worker.db'}"
    inventory = InventoryRepository(url)
    findings = FindingRepository(url)
    queue = ScanQueueRepository(inventory)
    queue.create_schema()
    findings.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Public API",
        kind=ManagedAssetKind.TLS_ENDPOINT,
        locator="example.com:443",
        context=ScanContext(internet_exposed=True),
    )
    worker = ScanWorker(
        inventory,
        findings,
        queue,
        executor=executor or FakeExecutor(),
        config=WorkerConfig(
            worker_id="worker-a",
            lease_seconds=30,
            poll_interval=0.1,
            retry_backoff_seconds=0,
        ),
    )
    return inventory, findings, queue, workspace, asset, worker


def test_worker_claims_executes_persists_and_completes(tmp_path: Path) -> None:
    inventory, findings, queue, workspace, asset, worker = _worker(tmp_path)
    job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
    )

    assert worker.run_once() is True
    stored = inventory.get_scan_job(workspace_id=workspace.id, job_id=job.id)
    assert stored is not None
    assert stored.status == ScanStatus.SUCCEEDED
    assert stored.findings_count == 1
    scoped = findings.list_findings(workspace_id=workspace.id)
    assert len(scoped) == 1
    assert scoped[0].observation.asset_id == asset.id


def test_worker_retries_transient_failure_then_succeeds(tmp_path: Path) -> None:
    executor = FakeExecutor(fail_once=True)
    inventory, findings, queue, workspace, asset, worker = _worker(
        tmp_path,
        executor=executor,
    )
    job = queue.enqueue(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.TLS,
        max_attempts=2,
    )

    assert worker.run_once() is True
    retried = inventory.get_scan_job(workspace_id=workspace.id, job_id=job.id)
    assert retried is not None
    assert retried.status == ScanStatus.QUEUED

    assert worker.run_once() is True
    succeeded = inventory.get_scan_job(workspace_id=workspace.id, job_id=job.id)
    assert succeeded is not None
    assert succeeded.status == ScanStatus.SUCCEEDED
    assert executor.calls == 2
    assert len(findings.list_findings(workspace_id=workspace.id)) == 1
