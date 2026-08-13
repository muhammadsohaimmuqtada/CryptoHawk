from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

import zstandard as zstd
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cryptohawk.domain.inventory import ManagedAsset
from cryptohawk.domain.models import AssetType, CryptoObservation
from cryptohawk.scanners.certificates import CertificateScanner
from cryptohawk.scanners.source import IGNORED_DIRS, SUPPORTED_EXTENSIONS, SourceScanner


class ContainerImageScanError(RuntimeError):
    """Raised when a container image archive cannot be safely or deterministically scanned."""


@dataclass(frozen=True, slots=True)
class ContainerImageCollection:
    observations: list[CryptoObservation]
    image_digest: str
    image_format: str
    layer_count: int
    scanned_files: int


@dataclass(frozen=True, slots=True)
class _ImageFile:
    content: bytes
    layer_digest: str


@dataclass(frozen=True, slots=True)
class _Layer:
    digest: str
    media_type: str
    content: bytes


_PEM_CERT_PATTERN = re.compile(
    br"-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)
_SHA256_PATTERN = re.compile(r"^sha256:([0-9a-f]{64})$")
_DOCKER_CONFIG_PATTERN = re.compile(r"(?:^|/)([0-9a-f]{64})\.json$")
_CERTIFICATE_EXTENSIONS = {".cer", ".crt", ".pem"}


class ContainerImageScanner:
    """Scan OCI or Docker image archives without extracting them to the host filesystem."""

    def __init__(
        self,
        *,
        archive_root: str | Path | None = None,
        source_scanner: SourceScanner | None = None,
        certificate_scanner: CertificateScanner | None = None,
        platform_os: str = "linux",
        platform_arch: str = "amd64",
        max_archive_bytes: int = 2_000_000_000,
        max_layers: int = 128,
        max_layer_compressed_bytes: int = 256_000_000,
        max_layer_uncompressed_bytes: int = 1_000_000_000,
        max_entries: int = 250_000,
        max_file_bytes: int = 2_000_000,
        max_scan_bytes: int = 150_000_000,
    ) -> None:
        self.archive_root = Path(archive_root).resolve() if archive_root else None
        self.source_scanner = source_scanner or SourceScanner()
        self.certificate_scanner = certificate_scanner or CertificateScanner()
        self.platform_os = platform_os.strip().lower()
        self.platform_arch = platform_arch.strip().lower()
        self.max_archive_bytes = max_archive_bytes
        self.max_layers = max_layers
        self.max_layer_compressed_bytes = max_layer_compressed_bytes
        self.max_layer_uncompressed_bytes = max_layer_uncompressed_bytes
        self.max_entries = max_entries
        self.max_file_bytes = max_file_bytes
        self.max_scan_bytes = max_scan_bytes
        self._validate_limits()

    def scan(self, asset: ManagedAsset) -> ContainerImageCollection:
        path = self._resolve_managed_locator(asset.locator)
        return self.scan_path(
            path,
            asset_name=asset.name,
            image_ref=asset.tags.get("image_ref"),
            oci_ref=asset.tags.get("oci_ref"),
        )

    def scan_path(
        self,
        path: str | Path,
        *,
        asset_name: str | None = None,
        image_ref: str | None = None,
        oci_ref: str | None = None,
    ) -> ContainerImageCollection:
        archive = Path(path).resolve()
        self._validate_archive_path(archive)
        try:
            with tarfile.open(archive, mode="r:*") as outer:
                members = self._outer_members(outer)
                if "oci-layout" in members and "index.json" in members:
                    image_digest, layers = self._load_oci_image(
                        outer,
                        members,
                        oci_ref=oci_ref,
                    )
                    image_format = "oci"
                elif "manifest.json" in members:
                    image_digest, layers = self._load_docker_image(
                        outer,
                        members,
                        image_ref=image_ref,
                    )
                    image_format = "docker-archive"
                else:
                    raise ContainerImageScanError(
                        "archive is neither an OCI image layout nor a Docker image archive"
                    )
        except (tarfile.TarError, OSError) as exc:
            if isinstance(exc, ContainerImageScanError):
                raise
            raise ContainerImageScanError("container image archive is unreadable") from exc

        if not layers:
            raise ContainerImageScanError("container image has no filesystem layers")
        if len(layers) > self.max_layers:
            raise ContainerImageScanError("container image exceeds configured layer-count limit")

        files: dict[str, _ImageFile] = {}
        entry_budget = 0
        scan_byte_budget = 0
        for layer in layers:
            entry_budget, scan_byte_budget = self._apply_layer(
                layer,
                files,
                entry_budget=entry_budget,
                scan_byte_budget=scan_byte_budget,
            )

        observations: list[CryptoObservation] = []
        logical_name = asset_name or archive.name
        for relative, image_file in sorted(files.items()):
            locator = f"container://{image_digest}/{relative}"
            certificate_observations = self._scan_certificates(
                image_file.content,
                locator=locator,
            )
            if certificate_observations:
                observations.extend(
                    self._annotate(
                        observation,
                        image_digest=image_digest,
                        image_format=image_format,
                        relative=relative,
                        layer_digest=image_file.layer_digest,
                    )
                    for observation in certificate_observations
                )
                continue

            try:
                text = image_file.content.decode("utf-8", errors="ignore")
            except UnicodeError:
                continue
            for observation in self.source_scanner.scan_text(
                text,
                asset_name=logical_name,
                locator=locator,
            ):
                observations.append(
                    self._annotate(
                        observation.model_copy(update={"asset_type": AssetType.CONTAINER}),
                        image_digest=image_digest,
                        image_format=image_format,
                        relative=relative,
                        layer_digest=image_file.layer_digest,
                    )
                )

        return ContainerImageCollection(
            observations=observations,
            image_digest=image_digest,
            image_format=image_format,
            layer_count=len(layers),
            scanned_files=len(files),
        )

    def _resolve_managed_locator(self, locator: str) -> Path:
        prefix = "image-archive:"
        if not locator.startswith(prefix):
            raise ContainerImageScanError(
                "container locator must use image-archive:<relative-path>"
            )
        if self.archive_root is None:
            raise ContainerImageScanError(
                "container image archive root is not configured for managed scans"
            )
        relative = locator[len(prefix) :].strip()
        if not relative:
            raise ContainerImageScanError("container image archive locator is empty")
        path = (self.archive_root / relative).resolve()
        try:
            path.relative_to(self.archive_root)
        except ValueError as exc:
            raise ContainerImageScanError(
                "container image archive path escapes the configured archive root"
            ) from exc
        return path

    def _validate_archive_path(self, archive: Path) -> None:
        if not archive.exists() or not archive.is_file() or archive.is_symlink():
            raise ContainerImageScanError("container image archive is not a regular file")
        try:
            size = archive.stat().st_size
        except OSError as exc:
            raise ContainerImageScanError(
                "container image archive metadata is unavailable"
            ) from exc
        if size <= 0:
            raise ContainerImageScanError("container image archive is empty")
        if size > self.max_archive_bytes:
            raise ContainerImageScanError("container image archive exceeds configured size limit")

    def _outer_members(self, outer: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
        members: dict[str, tarfile.TarInfo] = {}
        for index, member in enumerate(outer.getmembers(), start=1):
            if index > self.max_entries:
                raise ContainerImageScanError("container archive has too many entries")
            name = self._safe_path(member.name)
            if name in members:
                raise ContainerImageScanError(f"container archive contains duplicate path: {name}")
            members[name] = member
        return members

    def _load_oci_image(
        self,
        outer: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        *,
        oci_ref: str | None,
    ) -> tuple[str, list[_Layer]]:
        index = self._read_json_member(outer, members, "index.json", limit=4_000_000)
        descriptors = index.get("manifests")
        if not isinstance(descriptors, list) or not descriptors:
            raise ContainerImageScanError("OCI index contains no image manifests")
        descriptor = self._select_oci_descriptor(descriptors, oci_ref=oci_ref)
        manifest: dict = {}
        image_digest = ""
        for _ in range(5):
            digest = self._descriptor_digest(descriptor)
            payload = self._read_oci_blob(
                outer,
                members,
                digest,
                limit=8_000_000,
            )
            document = self._load_json(payload, label="OCI descriptor")
            media_type = str(descriptor.get("mediaType", ""))
            if "image.index" in media_type or (
                "manifests" in document and "layers" not in document
            ):
                nested = document.get("manifests")
                if not isinstance(nested, list) or not nested:
                    raise ContainerImageScanError("OCI nested image index is empty")
                descriptor = self._select_oci_descriptor(nested, oci_ref=oci_ref)
                continue
            manifest = document
            image_digest = digest
            break
        if not manifest or not image_digest:
            raise ContainerImageScanError("OCI image index nesting exceeds supported depth")
        layers = manifest.get("layers")
        if not isinstance(layers, list):
            raise ContainerImageScanError("OCI image manifest has invalid layer descriptors")
        result: list[_Layer] = []
        for descriptor in layers:
            if not isinstance(descriptor, dict):
                raise ContainerImageScanError("OCI image layer descriptor is invalid")
            digest = self._descriptor_digest(descriptor)
            size = descriptor.get("size")
            if isinstance(size, int) and size > self.max_layer_compressed_bytes:
                raise ContainerImageScanError("OCI image layer exceeds configured compressed limit")
            content = self._read_oci_blob(
                outer,
                members,
                digest,
                limit=self.max_layer_compressed_bytes,
            )
            result.append(
                _Layer(
                    digest=digest,
                    media_type=str(descriptor.get("mediaType", "")),
                    content=content,
                )
            )
        return image_digest, result

    def _load_docker_image(
        self,
        outer: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        *,
        image_ref: str | None,
    ) -> tuple[str, list[_Layer]]:
        manifest = self._read_json_member(outer, members, "manifest.json", limit=4_000_000)
        if not isinstance(manifest, list) or not manifest:
            raise ContainerImageScanError("Docker archive manifest is empty")
        entry = self._select_docker_manifest(manifest, image_ref=image_ref)
        config_name = self._safe_path(str(entry.get("Config", "")))
        config_bytes = self._read_member(outer, members, config_name, limit=8_000_000)
        image_digest = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"
        match = _DOCKER_CONFIG_PATTERN.search(config_name)
        if match and match.group(1) != image_digest.removeprefix("sha256:"):
            raise ContainerImageScanError("Docker image config digest does not match archive path")

        layer_names = entry.get("Layers")
        if not isinstance(layer_names, list):
            raise ContainerImageScanError("Docker archive manifest has invalid layer list")
        result: list[_Layer] = []
        for raw_name in layer_names:
            name = self._safe_path(str(raw_name))
            content = self._read_member(
                outer,
                members,
                name,
                limit=self.max_layer_compressed_bytes,
            )
            result.append(
                _Layer(
                    digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
                    media_type="application/vnd.docker.image.rootfs.diff.tar",
                    content=content,
                )
            )
        return image_digest, result

    def _select_oci_descriptor(self, descriptors: list, *, oci_ref: str | None) -> dict:
        valid = [item for item in descriptors if isinstance(item, dict)]
        if oci_ref:
            matches = [
                item
                for item in valid
                if isinstance(item.get("annotations"), dict)
                and item["annotations"].get("org.opencontainers.image.ref.name") == oci_ref
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise ContainerImageScanError("OCI reference name is ambiguous in archive")
            raise ContainerImageScanError("OCI reference name was not found in archive")

        platform_matches = []
        for item in valid:
            platform = item.get("platform")
            if not isinstance(platform, dict):
                continue
            if (
                str(platform.get("os", "")).lower() == self.platform_os
                and str(platform.get("architecture", "")).lower() == self.platform_arch
            ):
                platform_matches.append(item)
        if len(platform_matches) == 1:
            return platform_matches[0]
        if len(valid) == 1:
            return valid[0]
        if len(platform_matches) > 1:
            raise ContainerImageScanError(
                "OCI archive has multiple matching platform images; set the oci_ref asset tag"
            )
        raise ContainerImageScanError(
            "OCI archive is multi-image and has no unique configured platform match"
        )

    @staticmethod
    def _select_docker_manifest(manifest: list, *, image_ref: str | None) -> dict:
        valid = [item for item in manifest if isinstance(item, dict)]
        if image_ref:
            matches = [
                item
                for item in valid
                if image_ref in (item.get("RepoTags") or [])
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise ContainerImageScanError("Docker image reference is ambiguous in archive")
            raise ContainerImageScanError("Docker image reference was not found in archive")
        if len(valid) != 1:
            raise ContainerImageScanError(
                "Docker archive contains multiple images; set the image_ref asset tag"
            )
        return valid[0]

    def _apply_layer(
        self,
        layer: _Layer,
        files: dict[str, _ImageFile],
        *,
        entry_budget: int,
        scan_byte_budget: int,
    ) -> tuple[int, int]:
        whiteouts: list[tuple[str, str]] = []
        layer_uncompressed = 0
        with self._layer_tar(layer) as tar:
            for member in tar:
                entry_budget += 1
                if entry_budget > self.max_entries:
                    raise ContainerImageScanError("container image exceeds configured entry limit")
                layer_uncompressed += max(0, member.size)
                if layer_uncompressed > self.max_layer_uncompressed_bytes:
                    raise ContainerImageScanError(
                        "container image layer exceeds configured uncompressed limit"
                    )
                path = self._safe_path(member.name)
                basename = PurePosixPath(path).name
                if basename == ".wh..wh..opq":
                    whiteouts.append(("opaque", str(PurePosixPath(path).parent)))
                elif basename.startswith(".wh."):
                    target_name = basename[4:]
                    if not target_name:
                        raise ContainerImageScanError("container layer contains invalid whiteout")
                    parent = PurePosixPath(path).parent
                    target = (parent / target_name).as_posix()
                    whiteouts.append(("remove", target))

        for kind, target in whiteouts:
            if kind == "opaque":
                prefix = "" if target == "." else f"{target.rstrip('/')}/"
                for existing in list(files):
                    if existing.startswith(prefix):
                        files.pop(existing, None)
            else:
                self._remove_path(files, target)

        with self._layer_tar(layer) as tar:
            for member in tar:
                path = self._safe_path(member.name)
                basename = PurePosixPath(path).name
                if basename.startswith(".wh."):
                    continue
                if not member.isreg():
                    files.pop(path, None)
                    continue
                files.pop(path, None)
                if not self._supported_path(path):
                    continue
                if member.size < 0 or member.size > self.max_file_bytes:
                    continue
                scan_byte_budget += member.size
                if scan_byte_budget > self.max_scan_bytes:
                    raise ContainerImageScanError(
                        "container image exceeds configured cryptography scan-byte limit"
                    )
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                content = handle.read(self.max_file_bytes + 1)
                if len(content) > self.max_file_bytes:
                    raise ContainerImageScanError("container file exceeded declared scan limit")
                files[path] = _ImageFile(content=content, layer_digest=layer.digest)
        return entry_budget, scan_byte_budget

    @contextmanager
    def _layer_tar(self, layer: _Layer) -> Iterator[tarfile.TarFile]:
        media_type = layer.media_type.lower()
        raw = io.BytesIO(layer.content)
        reader: BinaryIO | None = None
        tar: tarfile.TarFile | None = None
        try:
            if media_type.endswith("+zstd") or layer.content.startswith(b"\x28\xb5\x2f\xfd"):
                reader = zstd.ZstdDecompressor().stream_reader(raw)
                tar = tarfile.open(fileobj=reader, mode="r|")
            else:
                tar = tarfile.open(fileobj=raw, mode="r:*")
            yield tar
        except (tarfile.TarError, zstd.ZstdError, OSError) as exc:
            raise ContainerImageScanError(
                "container image layer is not a valid tar changeset"
            ) from exc
        finally:
            if tar is not None:
                tar.close()
            if reader is not None:
                reader.close()

    def _scan_certificates(self, content: bytes, *, locator: str) -> list[CryptoObservation]:
        certificates: list[x509.Certificate] = []
        for block in _PEM_CERT_PATTERN.findall(content):
            try:
                certificates.append(x509.load_pem_x509_certificate(block))
            except ValueError:
                continue
        if not certificates and content and content[0] == 0x30:
            try:
                certificates.append(x509.load_der_x509_certificate(content))
            except ValueError:
                pass
        observations: list[CryptoObservation] = []
        for certificate in certificates[:100]:
            der = certificate.public_bytes(serialization.Encoding.DER)
            observations.extend(self.certificate_scanner.scan_der(der, locator=locator))
        return observations

    @staticmethod
    def _annotate(
        observation: CryptoObservation,
        *,
        image_digest: str,
        image_format: str,
        relative: str,
        layer_digest: str,
    ) -> CryptoObservation:
        evidence = observation.evidence.model_copy(
            update={
                "snippet": None,
                "metadata": {
                    **observation.evidence.metadata,
                    "container_image_digest": image_digest,
                    "container_image_format": image_format,
                    "container_path": relative,
                    "container_layer_digest": layer_digest,
                },
            }
        )
        return observation.model_copy(update={"evidence": evidence})

    def _read_json_member(
        self,
        outer: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        name: str,
        *,
        limit: int,
    ):
        return self._load_json(
            self._read_member(outer, members, name, limit=limit),
            label=name,
        )

    @staticmethod
    def _load_json(payload: bytes, *, label: str):
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContainerImageScanError(f"{label} contains invalid JSON") from exc

    def _read_oci_blob(
        self,
        outer: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        digest: str,
        *,
        limit: int,
    ) -> bytes:
        match = _SHA256_PATTERN.fullmatch(digest)
        if match is None:
            raise ContainerImageScanError("only sha256 OCI descriptors are supported")
        path = f"blobs/sha256/{match.group(1)}"
        payload = self._read_member(outer, members, path, limit=limit)
        if hashlib.sha256(payload).hexdigest() != match.group(1):
            raise ContainerImageScanError("OCI blob digest verification failed")
        return payload

    @staticmethod
    def _descriptor_digest(descriptor: dict) -> str:
        digest = descriptor.get("digest")
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            raise ContainerImageScanError("OCI descriptor has an invalid sha256 digest")
        return digest

    @staticmethod
    def _read_member(
        outer: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        name: str,
        *,
        limit: int,
    ) -> bytes:
        member = members.get(name)
        if member is None or not member.isreg():
            raise ContainerImageScanError(f"container archive member is missing: {name}")
        if member.size < 0 or member.size > limit:
            raise ContainerImageScanError(f"container archive member exceeds limit: {name}")
        handle = outer.extractfile(member)
        if handle is None:
            raise ContainerImageScanError(f"container archive member is unreadable: {name}")
        payload = handle.read(limit + 1)
        if len(payload) > limit:
            raise ContainerImageScanError(f"container archive member exceeds limit: {name}")
        return payload

    @staticmethod
    def _remove_path(files: dict[str, _ImageFile], target: str) -> None:
        prefix = f"{target.rstrip('/')}/"
        for existing in list(files):
            if existing == target or existing.startswith(prefix):
                files.pop(existing, None)

    @staticmethod
    def _safe_path(value: str) -> str:
        text = value.strip().replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        path = PurePosixPath(text)
        if not text or path.is_absolute() or ".." in path.parts or "\x00" in text:
            raise ContainerImageScanError("container archive contains an unsafe path")
        normalized = path.as_posix()
        if normalized in {"", "."}:
            raise ContainerImageScanError("container archive contains an invalid empty path")
        return normalized

    @staticmethod
    def _supported_path(relative: str) -> bool:
        path = PurePosixPath(relative)
        if any(part in IGNORED_DIRS for part in path.parts):
            return False
        suffix = path.suffix.lower()
        return (
            suffix in SUPPORTED_EXTENSIONS
            or suffix in _CERTIFICATE_EXTENSIONS
            or suffix == ".cnf"
        )

    def _validate_limits(self) -> None:
        values = {
            "max_archive_bytes": self.max_archive_bytes,
            "max_layers": self.max_layers,
            "max_layer_compressed_bytes": self.max_layer_compressed_bytes,
            "max_layer_uncompressed_bytes": self.max_layer_uncompressed_bytes,
            "max_entries": self.max_entries,
            "max_file_bytes": self.max_file_bytes,
            "max_scan_bytes": self.max_scan_bytes,
        }
        if any(value <= 0 for value in values.values()):
            raise ValueError("container image scanner limits must be positive")
        if not self.platform_os or not self.platform_arch:
            raise ValueError("container image platform OS and architecture are required")
