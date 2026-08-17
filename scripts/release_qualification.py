from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptohawk.domain.inventory import ManagedAssetKind
from cryptohawk.domain.models import ScanContext
from cryptohawk.domain.remediation import RemediationStatus
from cryptohawk.services.executor import AssetScanExecutor
from cryptohawk.services.reporting import ReportingService
from cryptohawk.services.scan_jobs import ScanJobService
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.policy import PolicyRepository
from cryptohawk.storage.remediation import RemediationRepository
from cryptohawk.storage.retention import WorkspaceRetentionRepository


class _UnusedRepositoryScanner:
    def scan(self, asset, *, scan_job_id: str):
        raise AssertionError("release qualification must not perform repository network I/O")


def main() -> None:
    from cryptohawk.config import settings

    settings.validate_runtime()
    inventory = InventoryRepository(settings.database_url)
    findings = FindingRepository(settings.database_url)
    continuous = ContinuousRepository(inventory)
    policies = PolicyRepository(inventory)
    remediation = RemediationRepository(inventory)
    retention = WorkspaceRetentionRepository(inventory)

    workspace = inventory.create_workspace(name="Release Qualification")
    asset = inventory.create_asset(
        workspace_id=workspace.id,
        name="Payments Service",
        kind=ManagedAssetKind.SOURCE,
        locator="payments.py",
        context=ScanContext(
            internet_exposed=True,
            asset_criticality=10,
            data_lifetime_years=8,
            environment="production",
        ),
    )

    strict = next(
        item
        for item in policies.list_packs(workspace_id=workspace.id)
        if item.pack.slug == "strict-modern"
    )
    effective = policies.activate(
        workspace_id=workspace.id,
        policy_id=strict.pack.id,
        version=1,
        assigned_by="system:release-qualification",
    )

    executor = AssetScanExecutor(policy_provider=policies)
    scans = ScanJobService(
        inventory,
        findings,
        executor=executor,
        repository_scanner=_UnusedRepositoryScanner(),
        history=continuous,
        policy_repository=policies,
    )
    source_job, source_findings = scans.run(
        workspace_id=workspace.id,
        asset_id=asset.id,
        source='legacy = "SHA1"\nkey = RSA-2048\n',
        filename="payments.py",
    )
    rsa = next(finding for finding in source_findings if finding.observation.family == "RSA")
    if rsa.risk.policy_status != "fail":
        raise AssertionError("Strict Modern must fail RSA-2048 in release qualification")
    if rsa.risk.policy_rules_hash != effective.version.rules_hash:
        raise AssertionError("finding did not retain exact active policy rules hash")

    item = remediation.create_from_finding(
        workspace_id=workspace.id,
        finding_id=rsa.observation.id,
        created_by="system:release-qualification",
        owner="Platform Security",
    )
    item = remediation.update_item(
        workspace_id=workspace.id,
        item_id=item.id,
        changes={"status": RemediationStatus.IN_PROGRESS.value},
    )
    item = remediation.update_item(
        workspace_id=workspace.id,
        item_id=item.id,
        changes={"status": RemediationStatus.READY_FOR_VERIFICATION.value},
    )

    verification_job, verification_findings = scans.run(
        workspace_id=workspace.id,
        asset_id=asset.id,
        source='print("post-quantum migration completed")\n',
        filename="payments.py",
    )
    if verification_findings:
        raise AssertionError("verification source unexpectedly retained crypto observations")
    verification = remediation.verify(
        workspace_id=workspace.id,
        item_id=item.id,
        verification_job_id=verification_job.id,
    )
    if not verification.verified or verification.item.status != RemediationStatus.VERIFIED:
        raise AssertionError("evidence-backed migration verification did not complete")

    reporting = ReportingService(inventory)
    executive = reporting.executive_report(workspace.id)
    engineering = reporting.engineering_report(workspace.id)
    cbom = reporting.current_cbom(workspace.id)
    if executive.summary.active_findings != 0:
        raise AssertionError("resolved exposure remained in executive current-state reporting")
    if executive.summary.remediation.get("verified") != 1:
        raise AssertionError("verified migration was not represented in executive reporting")
    if engineering.findings:
        raise AssertionError("resolved exposure remained in engineering current-state reporting")
    if cbom.get("components"):
        raise AssertionError("resolved exposure remained in current-state CBOM")

    history = continuous.list_scan_history(workspace_id=workspace.id, asset_id=asset.id)
    if len(history) != 2:
        raise AssertionError("release qualification expected exactly two successful scan snapshots")
    if not all(snapshot.policy_version == effective.provenance_ref for snapshot in history):
        raise AssertionError("scan history did not retain the exact policy provenance")

    retention.set_policy(
        workspace_id=workspace.id,
        enabled=True,
        evidence_retention_days=7,
        audit_retention_days=7,
        sweep_interval_hours=1,
        updated_by="system:release-qualification",
    )
    sweep = retention.prune_workspace_history(
        workspace_id=workspace.id,
        now=datetime.now(UTC) + timedelta(days=8),
    )
    if sweep is None or sweep.deleted_rows.get("scan_snapshots", 0) < 1:
        raise AssertionError("retention policy did not expire old PostgreSQL scan history")
    retained_history = continuous.list_scan_history(
        workspace_id=workspace.id,
        asset_id=asset.id,
    )
    if len(retained_history) != 1 or retained_history[0].job_id != verification_job.id:
        raise AssertionError("retention policy did not preserve the newest scan evidence")

    purge = retention.purge_workspace(workspace.id)
    if purge.workspace_id != workspace.id or inventory.get_workspace(workspace.id) is not None:
        raise AssertionError("workspace purge did not remove the qualified tenant on PostgreSQL")
    if findings.list_findings(workspace_id=workspace.id):
        raise AssertionError("workspace purge left scoped findings behind on PostgreSQL")

    print(
        "release qualification passed:",
        f"workspace={workspace.id}",
        f"source_job={source_job.id}",
        f"verification_job={verification_job.id}",
        f"policy={effective.provenance_ref}",
        f"retention_deleted={sum(sweep.deleted_rows.values())}",
        "workspace_purged=true",
    )


if __name__ == "__main__":
    main()
