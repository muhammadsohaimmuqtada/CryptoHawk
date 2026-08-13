from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from sqlalchemy import select

from cryptohawk.config import settings
from cryptohawk.domain.credentials import ConnectorCredentialKind
from cryptohawk.domain.inventory import ManagedAsset
from cryptohawk.domain.models import AssetType, CryptoObservation, Finding
from cryptohawk.domain.repositories import (
    RepositoryConfiguration,
    RepositoryProvider,
    RepositoryScanMode,
    RepositoryScanProvenance,
)
from cryptohawk.scanners.source import IGNORED_DIRS, SUPPORTED_EXTENSIONS, SourceScanner
from cryptohawk.security.network import NetworkTargetError, resolve_target
from cryptohawk.storage.continuous import ContinuousRepository, ObservationStateRecord
from cryptohawk.storage.credentials import ConnectorCredentialRepository
from cryptohawk.storage.repositories import RepositoryAssetRepository


class RepositoryScanError(RuntimeError):
    """Raised when repository acquisition or scanning cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class RepositoryCollection:
    observations: list[CryptoObservation]
    provenance: RepositoryScanProvenance


@dataclass(frozen=True, slots=True)
class RepositoryDelta:
    touched_paths: frozenset[str]
    current_paths: frozenset[str]


_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")


class RepositoryScanner:
    def __init__(
        self,
        repositories: RepositoryAssetRepository,
        history: ContinuousRepository,
        *,
        source_scanner: SourceScanner | None = None,
        credentials: ConnectorCredentialRepository | None = None,
        allowed_hosts: list[str] | None = None,
        allow_private_targets: bool | None = None,
        fetch_depth: int | None = None,
        git_timeout_seconds: int | None = None,
        max_files: int | None = None,
        max_scan_bytes: int | None = None,
        max_file_bytes: int | None = None,
    ) -> None:
        self.repositories = repositories
        self.history = history
        self.source_scanner = source_scanner or SourceScanner()
        self.credentials = credentials
        self.allowed_hosts = frozenset(
            host.lower().rstrip(".")
            for host in (allowed_hosts or settings.repository_allowed_host_list)
        )
        self.allow_private_targets = (
            settings.allow_private_targets
            if allow_private_targets is None
            else allow_private_targets
        )
        self.fetch_depth = fetch_depth or settings.repository_fetch_depth
        self.git_timeout_seconds = (
            git_timeout_seconds or settings.repository_git_timeout_seconds
        )
        self.max_files = max_files or settings.repository_max_files
        self.max_scan_bytes = max_scan_bytes or settings.repository_max_scan_bytes
        self.max_file_bytes = max_file_bytes or settings.repository_max_file_bytes
        self._validate_limits()

    def scan(self, asset: ManagedAsset, *, scan_job_id: str) -> RepositoryCollection:
        if not scan_job_id.strip():
            raise RepositoryScanError("scan_job_id is required for repository scans")
        config = self.repositories.get_configuration(
            workspace_id=asset.workspace_id,
            asset_id=asset.id,
        )
        self.validate_repository_url(config.repository_url)
        self.validate_ref(config.ref)
        auth = self._credential_material(config)
        previous = self.repositories.last_successful_scan(
            workspace_id=asset.workspace_id,
            asset_id=asset.id,
        )

        with tempfile.TemporaryDirectory(prefix="cryptohawk-repository-") as temp_dir:
            root = Path(temp_dir) / "checkout"
            root.mkdir(mode=0o700)
            askpass = self._write_askpass(Path(temp_dir)) if auth is not None else None
            env = self._git_environment(auth=auth, askpass=askpass)
            self._git(["init", "--quiet"], cwd=root, env=env)
            self._git(
                ["remote", "add", "origin", config.repository_url],
                cwd=root,
                env=env,
            )
            self._git(
                [
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--prune",
                    f"--depth={self.fetch_depth}",
                    "origin",
                    config.ref,
                ],
                cwd=root,
                env=env,
            )
            commit_sha = self._git(
                ["rev-parse", "FETCH_HEAD"],
                cwd=root,
                env=env,
            ).strip().lower()
            if not _SHA_PATTERN.fullmatch(commit_sha):
                raise RepositoryScanError("git returned an invalid commit identity")
            self._git(
                ["checkout", "--quiet", "--detach", "--force", commit_sha],
                cwd=root,
                env=env,
            )

            previous_sha = previous.commit_sha if previous else None
            incremental = bool(
                previous_sha
                and self._commit_available(root, previous_sha, env)
                and self._is_ancestor(root, previous_sha, commit_sha, env)
            )
            if incremental:
                delta = self._changed_paths(root, previous_sha or "", commit_sha, env)
                retained = self._retained_observations(
                    workspace_id=asset.workspace_id,
                    asset_id=asset.id,
                    touched_paths=delta.touched_paths,
                )
                rescanned, scanned_files = self._scan_paths(
                    root,
                    delta.current_paths,
                    asset_name=asset.name,
                )
                observations = retained + rescanned
                mode = RepositoryScanMode.INCREMENTAL
            else:
                observations, scanned_files = self._scan_checkout(root, asset_name=asset.name)
                retained = []
                delta = RepositoryDelta(frozenset(), frozenset())
                mode = RepositoryScanMode.FULL

        normalized = [
            observation.model_copy(update={"asset_type": AssetType.REPOSITORY})
            for observation in observations
        ]
        provenance = RepositoryScanProvenance(
            scan_job_id=scan_job_id,
            workspace_id=asset.workspace_id,
            asset_id=asset.id,
            repository_url=config.repository_url,
            ref=config.ref,
            commit_sha=commit_sha,
            previous_commit_sha=previous_sha,
            scan_mode=mode,
            changed_paths=len(delta.touched_paths),
            scanned_files=scanned_files,
            retained_observations=len(retained),
        )
        self.repositories.record_scan_provenance(provenance)
        return RepositoryCollection(observations=normalized, provenance=provenance)

    def validate_repository_url(self, repository_url: str) -> RepositoryProvider:
        try:
            parsed = urlsplit(repository_url)
        except ValueError as exc:
            raise RepositoryScanError("repository URL is invalid") from exc
        if parsed.scheme.lower() != "https":
            raise RepositoryScanError("repository URL must use HTTPS")
        if parsed.username or parsed.password:
            raise RepositoryScanError("repository URL must not contain embedded credentials")
        if parsed.query or parsed.fragment:
            raise RepositoryScanError("repository URL must not contain query strings or fragments")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname or not parsed.path or parsed.path == "/":
            raise RepositoryScanError("repository URL must include a host and repository path")
        if hostname not in self.allowed_hosts:
            raise RepositoryScanError(
                f"repository host is not allowlisted: {hostname}"
            )
        try:
            resolve_target(
                hostname,
                parsed.port or 443,
                allow_private=self.allow_private_targets,
            )
        except NetworkTargetError as exc:
            raise RepositoryScanError(str(exc)) from exc
        if hostname == "github.com":
            return RepositoryProvider.GITHUB
        if hostname == "gitlab.com":
            return RepositoryProvider.GITLAB
        return RepositoryProvider.GENERIC

    @staticmethod
    def validate_ref(ref: str) -> str:
        value = ref.strip()
        if (
            not _REF_PATTERN.fullmatch(value)
            or ".." in value
            or "@{" in value
            or value.endswith("/")
            or value.endswith(".lock")
        ):
            raise RepositoryScanError("repository ref is invalid or unsafe")
        return value

    def _credential_material(
        self,
        config: RepositoryConfiguration,
    ) -> tuple[str, str] | None:
        if config.credential_id is None:
            return None
        if self.credentials is None:
            raise RepositoryScanError(
                "repository credential is configured but connector encryption is unavailable"
            )
        metadata = self.credentials.get_metadata(
            workspace_id=config.workspace_id,
            credential_id=config.credential_id,
        )
        if config.provider == RepositoryProvider.GITHUB:
            expected = ConnectorCredentialKind.GITHUB_TOKEN
            username = "x-access-token"
        elif config.provider == RepositoryProvider.GITLAB:
            expected = ConnectorCredentialKind.GITLAB_TOKEN
            username = "oauth2"
        else:
            raise RepositoryScanError(
                "authenticated custom repository hosts are not supported by this collector"
            )
        if metadata.kind != expected:
            raise RepositoryScanError(
                f"repository requires a {expected.value} credential"
            )
        material = self.credentials.resolve_for_use(
            workspace_id=config.workspace_id,
            credential_id=config.credential_id,
        )
        token = material.get("token", "")
        if not token:
            raise RepositoryScanError("repository credential does not contain a token")
        return username, token

    def _scan_checkout(
        self,
        root: Path,
        *,
        asset_name: str,
    ) -> tuple[list[CryptoObservation], int]:
        paths: list[str] = []
        for path in root.rglob("*"):
            if len(paths) >= self.max_files:
                raise RepositoryScanError("repository exceeds configured file-count limit")
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if self._supported_relative_path(relative):
                paths.append(relative)
        return self._scan_paths(root, paths, asset_name=asset_name)

    def _scan_paths(
        self,
        root: Path,
        paths: object,
        *,
        asset_name: str,
    ) -> tuple[list[CryptoObservation], int]:
        observations: list[CryptoObservation] = []
        scanned_files = 0
        scanned_bytes = 0
        normalized_paths = sorted({str(path) for path in paths})
        if len(normalized_paths) > self.max_files:
            raise RepositoryScanError("repository scan exceeds configured file-count limit")
        for relative in normalized_paths:
            if not self._supported_relative_path(relative):
                continue
            path = root / PurePosixPath(relative)
            if path.is_symlink() or not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > self.max_file_bytes:
                continue
            scanned_bytes += size
            if scanned_bytes > self.max_scan_bytes:
                raise RepositoryScanError("repository scan exceeds configured byte limit")
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            observations.extend(
                self.source_scanner.scan_text(
                    text,
                    asset_name=asset_name,
                    locator=relative,
                )
            )
            scanned_files += 1
        return observations, scanned_files

    def _retained_observations(
        self,
        *,
        workspace_id: str,
        asset_id: str,
        touched_paths: frozenset[str],
    ) -> list[CryptoObservation]:
        with self.history.SessionLocal() as session:
            rows = session.scalars(
                select(ObservationStateRecord).where(
                    ObservationStateRecord.workspace_id == workspace_id,
                    ObservationStateRecord.asset_id == asset_id,
                    ObservationStateRecord.active.is_(True),
                )
            ).all()
            retained: list[CryptoObservation] = []
            for row in rows:
                finding = Finding.model_validate_json(row.finding_payload)
                locator = finding.observation.evidence.locator
                if locator is None or locator not in touched_paths:
                    retained.append(finding.observation)
            return retained

    def _changed_paths(
        self,
        root: Path,
        previous_sha: str,
        current_sha: str,
        env: dict[str, str],
    ) -> RepositoryDelta:
        output = self._git(
            ["diff", "--name-status", "-z", previous_sha, current_sha, "--"],
            cwd=root,
            env=env,
        )
        fields = output.split("\0")
        if fields and fields[-1] == "":
            fields.pop()
        touched: set[str] = set()
        current: set[str] = set()
        index = 0
        while index < len(fields):
            status_code = fields[index]
            index += 1
            if not status_code:
                continue
            status = status_code[0]
            if status in {"R", "C"}:
                if index + 1 >= len(fields):
                    raise RepositoryScanError("git returned malformed rename/copy diff data")
                old_path = self._safe_relative_path(fields[index])
                new_path = self._safe_relative_path(fields[index + 1])
                index += 2
                touched.update({old_path, new_path})
                current.add(new_path)
            else:
                if index >= len(fields):
                    raise RepositoryScanError("git returned malformed diff data")
                path = self._safe_relative_path(fields[index])
                index += 1
                touched.add(path)
                if status != "D":
                    current.add(path)
        return RepositoryDelta(frozenset(touched), frozenset(current))

    @staticmethod
    def _safe_relative_path(value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise RepositoryScanError("git returned an unsafe repository path")
        return path.as_posix()

    @staticmethod
    def _supported_relative_path(relative: str) -> bool:
        path = PurePosixPath(relative)
        return (
            path.suffix.lower() in SUPPORTED_EXTENSIONS
            and not any(part in IGNORED_DIRS for part in path.parts)
        )

    def _commit_available(self, root: Path, commit_sha: str, env: dict[str, str]) -> bool:
        if not _SHA_PATTERN.fullmatch(commit_sha):
            return False
        return self._git_success(
            ["cat-file", "-e", f"{commit_sha}^{{commit}}"],
            cwd=root,
            env=env,
        )

    def _is_ancestor(
        self,
        root: Path,
        previous_sha: str,
        current_sha: str,
        env: dict[str, str],
    ) -> bool:
        return self._git_success(
            ["merge-base", "--is-ancestor", previous_sha, current_sha],
            cwd=root,
            env=env,
        )

    def _git(
        self,
        args: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
    ) -> str:
        if shutil.which("git") is None:
            raise RepositoryScanError("git executable is required for repository scanning")
        command = [
            "git",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
            *args,
        ]
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.git_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RepositoryScanError("git operation exceeded configured timeout") from exc
        if result.returncode != 0:
            raise RepositoryScanError(self._sanitize_git_error(result.stderr, env))
        return result.stdout

    def _git_success(
        self,
        args: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
    ) -> bool:
        try:
            self._git(args, cwd=cwd, env=env)
        except RepositoryScanError:
            return False
        return True

    @staticmethod
    def _write_askpass(directory: Path) -> Path:
        path = directory / "git-askpass.sh"
        path.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  *Username*) printf "%s\\n" "$CRYPTOHAWK_GIT_USERNAME" ;;\n'
            '  *Password*) printf "%s\\n" "$CRYPTOHAWK_GIT_PASSWORD" ;;\n'
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return path

    @staticmethod
    def _git_environment(
        *,
        auth: tuple[str, str] | None,
        askpass: Path | None,
    ) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
            }
        )
        if auth is not None and askpass is not None:
            username, token = auth
            env["GIT_ASKPASS"] = str(askpass)
            env["CRYPTOHAWK_GIT_USERNAME"] = username
            env["CRYPTOHAWK_GIT_PASSWORD"] = token
        return env

    @staticmethod
    def _sanitize_git_error(stderr: str, env: dict[str, str]) -> str:
        message = stderr.strip() or "git operation failed"
        for key in ("CRYPTOHAWK_GIT_USERNAME", "CRYPTOHAWK_GIT_PASSWORD"):
            secret = env.get(key)
            if secret:
                message = message.replace(secret, "[REDACTED]")
        return message[:1000]

    def _validate_limits(self) -> None:
        if not 1 <= self.fetch_depth <= 10_000:
            raise ValueError("repository_fetch_depth must be between 1 and 10000")
        if not 5 <= self.git_timeout_seconds <= 1800:
            raise ValueError("repository_git_timeout_seconds must be between 5 and 1800")
        if not 1 <= self.max_files <= 1_000_000:
            raise ValueError("repository_max_files must be positive")
        if not 1_000_000 <= self.max_scan_bytes <= 10_000_000_000:
            raise ValueError("repository_max_scan_bytes is outside supported bounds")
        if not 1_000 <= self.max_file_bytes <= self.max_scan_bytes:
            raise ValueError("repository_max_file_bytes is outside supported bounds")
