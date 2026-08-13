from datetime import UTC, datetime
from pathlib import Path

import pytest

from cryptohawk.domain.inventory import ScanKind, ScanStatus
from cryptohawk.domain.models import Finding, ScanContext
from cryptohawk.domain.repositories import RepositoryProvider, RepositoryScanMode
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.repository import RepositoryScanError, RepositoryScanner
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.repositories import RepositoryAssetRepository


def _stack(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'repository.db'}"
    inventory = InventoryRepository(url)
    history = ContinuousRepository(inventory)
    repositories = RepositoryAssetRepository(inventory)
    repositories.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    repository_asset = repositories.create_repository_asset(
        workspace_id=workspace.id,
        name="Payments API",
        repository_url="https://github.com/acme/payments.git",
        provider=RepositoryProvider.GITHUB,
        ref="main",
        credential_id=None,
        context=ScanContext(asset_criticality=9),
    )
    scanner = RepositoryScanner(
        repositories,
        history,
        allowed_hosts=["github.com"],
        max_scan_bytes=5_000_000,
        max_file_bytes=1_000_000,
    )
    return inventory, history, repositories, workspace, repository_asset, scanner


def _successful_history(
    *,
    inventory: InventoryRepository,
    history: ContinuousRepository,
    workspace_id: str,
    asset_id: str,
    job_id: str,
    observations,
) -> list[Finding]:
    asset = inventory.get_asset(workspace_id=workspace_id, asset_id=asset_id)
    assert asset is not None
    normalized = [
        observation.model_copy(update={"asset_id": asset.id, "asset_name": asset.name})
        for observation in observations
    ]
    findings = [RiskEngine().assess(observation, asset.context) for observation in normalized]
    findings = history.prepare_findings(job_id, findings)
    history.record_successful_scan(
        workspace_id=workspace_id,
        asset_id=asset_id,
        scan_job_id=job_id,
        findings=findings,
    )
    inventory.transition_scan_job(
        workspace_id=workspace_id,
        job_id=job_id,
        expected=ScanStatus.RUNNING,
        target=ScanStatus.SUCCEEDED,
        findings_count=len(findings),
    )
    return findings


def test_repository_url_policy_rejects_unsafe_forms(tmp_path: Path, monkeypatch) -> None:
    _, _, _, _, _, scanner = _stack(tmp_path)
    monkeypatch.setattr(
        "cryptohawk.scanners.repository.resolve_target",
        lambda *args, **kwargs: object(),
    )

    assert (
        scanner.validate_repository_url("https://github.com/acme/payments.git")
        == RepositoryProvider.GITHUB
    )
    with pytest.raises(RepositoryScanError, match="HTTPS"):
        scanner.validate_repository_url("http://github.com/acme/payments.git")
    with pytest.raises(RepositoryScanError, match="embedded credentials"):
        scanner.validate_repository_url("https://token@github.com/acme/payments.git")
    with pytest.raises(RepositoryScanError, match="not allowlisted"):
        scanner.validate_repository_url("https://evil.example/acme/payments.git")
    with pytest.raises(RepositoryScanError, match="query strings"):
        scanner.validate_repository_url("https://github.com/acme/payments.git?token=secret")


def test_repository_ref_validation_blocks_option_and_revision_injection() -> None:
    assert RepositoryScanner.validate_ref("main") == "main"
    assert RepositoryScanner.validate_ref("release/2026.08") == "release/2026.08"
    for value in ("--upload-pack=evil", "main..other", "main@{1}", "refs/heads/"):
        with pytest.raises(RepositoryScanError):
            RepositoryScanner.validate_ref(value)


def test_git_error_redaction_removes_credential_material() -> None:
    message = RepositoryScanner._sanitize_git_error(
        "fatal: token secret-token for x-access-token was rejected",
        {
            "CRYPTOHAWK_GIT_USERNAME": "x-access-token",
            "CRYPTOHAWK_GIT_PASSWORD": "secret-token",
        },
    )
    assert "secret-token" not in message
    assert "x-access-token" not in message
    assert "[REDACTED]" in message


def test_repository_full_then_incremental_scan_retains_untouched_observations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    inventory, history, repositories, workspace, repository_asset, scanner = _stack(tmp_path)
    asset = repository_asset.asset
    first_sha = "a" * 40
    second_sha = "b" * 40
    current_sha = first_sha

    monkeypatch.setattr(
        scanner,
        "validate_repository_url",
        lambda url: RepositoryProvider.GITHUB,
    )

    def fake_git(args: list[str], *, cwd: Path, env: dict[str, str]) -> str:
        del env
        command = args[0]
        if command == "rev-parse":
            return f"{current_sha}\n"
        if command == "checkout":
            (cwd / "a.py").write_text(
                "import hashlib\nvalue = hashlib.md5(payload).hexdigest()\n"
                if current_sha == first_sha
                else "import hashlib\nvalue = hashlib.sha256(payload).hexdigest()\n",
                encoding="utf-8",
            )
            (cwd / "b.py").write_text(
                "import hashlib\nlegacy = hashlib.sha1(payload).hexdigest()\n",
                encoding="utf-8",
            )
            return ""
        if command == "diff":
            return "M\0a.py\0"
        return ""

    monkeypatch.setattr(scanner, "_git", fake_git)

    first_job = inventory.create_scan_job(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.REPOSITORY,
    )
    inventory.transition_scan_job(
        workspace_id=workspace.id,
        job_id=first_job.id,
        expected=ScanStatus.QUEUED,
        target=ScanStatus.RUNNING,
    )
    first = scanner.scan(asset, scan_job_id=first_job.id)
    assert first.provenance.scan_mode == RepositoryScanMode.FULL
    assert first.provenance.commit_sha == first_sha
    assert {obs.evidence.locator for obs in first.observations} == {"a.py", "b.py"}
    _successful_history(
        inventory=inventory,
        history=history,
        workspace_id=workspace.id,
        asset_id=asset.id,
        job_id=first_job.id,
        observations=first.observations,
    )

    current_sha = second_sha
    second_job = inventory.create_scan_job(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.REPOSITORY,
    )
    inventory.transition_scan_job(
        workspace_id=workspace.id,
        job_id=second_job.id,
        expected=ScanStatus.QUEUED,
        target=ScanStatus.RUNNING,
    )
    second = scanner.scan(asset, scan_job_id=second_job.id)

    assert second.provenance.scan_mode == RepositoryScanMode.INCREMENTAL
    assert second.provenance.previous_commit_sha == first_sha
    assert second.provenance.commit_sha == second_sha
    assert second.provenance.changed_paths == 1
    assert second.provenance.scanned_files == 1
    assert second.provenance.retained_observations >= 1
    assert {obs.evidence.locator for obs in second.observations} == {"a.py", "b.py"}
    algorithms = {obs.algorithm for obs in second.observations}
    assert "SHA-256" in algorithms
    assert "SHA-1" in algorithms
    assert "MD5" not in algorithms

    provenance = repositories.list_scan_provenance(
        workspace_id=workspace.id,
        asset_id=asset.id,
    )
    assert [item.commit_sha for item in provenance] == [second_sha, first_sha]


def test_scan_checkout_skips_symlinks_and_ignored_vendor_paths(
    tmp_path: Path,
) -> None:
    _, _, _, _, repository_asset, scanner = _stack(tmp_path)
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "good.py").write_text("import hashlib\nx = hashlib.md5(data)\n", encoding="utf-8")
    vendor = root / "node_modules"
    vendor.mkdir()
    (vendor / "bad.py").write_text("import hashlib\nx = hashlib.sha1(data)\n", encoding="utf-8")
    target = tmp_path / "outside.py"
    target.write_text("import hashlib\nx = hashlib.sha1(data)\n", encoding="utf-8")
    (root / "link.py").symlink_to(target)

    observations, scanned_files = scanner._scan_checkout(
        root,
        asset_name=repository_asset.asset.name,
    )
    assert scanned_files == 1
    assert {observation.evidence.locator for observation in observations} == {"good.py"}


def test_scan_provenance_only_becomes_baseline_after_job_success(tmp_path: Path) -> None:
    inventory, _, repositories, workspace, repository_asset, _ = _stack(tmp_path)
    asset = repository_asset.asset
    job = inventory.create_scan_job(
        workspace_id=workspace.id,
        asset_id=asset.id,
        kind=ScanKind.REPOSITORY,
    )
    from cryptohawk.domain.repositories import RepositoryScanProvenance

    repositories.record_scan_provenance(
        RepositoryScanProvenance(
            scan_job_id=job.id,
            workspace_id=workspace.id,
            asset_id=asset.id,
            repository_url=repository_asset.repository.repository_url,
            ref="main",
            commit_sha="c" * 40,
            scan_mode=RepositoryScanMode.FULL,
            changed_paths=0,
            scanned_files=2,
            retained_observations=0,
            collected_at=datetime(2026, 8, 13, tzinfo=UTC),
        )
    )
    assert (
        repositories.last_successful_scan(
            workspace_id=workspace.id,
            asset_id=asset.id,
        )
        is None
    )
