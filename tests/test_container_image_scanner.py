from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
import zstandard as zstd

from cryptohawk.domain.inventory import ManagedAsset, ManagedAssetKind, ScanKind
from cryptohawk.domain.models import AssetType
from cryptohawk.scanners.container_image import ContainerImageScanError, ContainerImageScanner
from cryptohawk.services.executor import AssetScanExecutor


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(payload))
    return buffer.getvalue()


def _write_outer(path: Path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, mode="w") as archive:
        for name, payload in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(payload))


def test_docker_archive_applies_whiteouts_before_crypto_discovery(tmp_path: Path) -> None:
    lower = _tar_bytes(
        {
            "app/legacy.py": b"import hashlib\nhashlib.md5(b'legacy')\n",
            "etc/keep.conf": b"cipher = AES-256\n",
        }
    )
    upper = _tar_bytes(
        {
            "app/.wh.legacy.py": b"",
            "app/main.py": b"import hashlib\nhashlib.sha256(b'current')\n",
        }
    )
    config = b'{"architecture":"amd64","os":"linux"}'
    config_hash = hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        [
            {
                "Config": f"{config_hash}.json",
                "RepoTags": ["acme/payments:1.0"],
                "Layers": ["layer-a/layer.tar", "layer-b/layer.tar"],
            }
        ],
        separators=(",", ":"),
    ).encode()
    archive_path = tmp_path / "payments.tar"
    _write_outer(
        archive_path,
        {
            "manifest.json": manifest,
            f"{config_hash}.json": config,
            "layer-a/layer.tar": lower,
            "layer-b/layer.tar": upper,
        },
    )

    collection = ContainerImageScanner().scan_path(
        archive_path,
        image_ref="acme/payments:1.0",
    )

    families = {item.family for item in collection.observations}
    assert "MD5" not in families
    assert "SHA-256" in families
    assert "AES" in families
    assert collection.image_format == "docker-archive"
    assert collection.image_digest == f"sha256:{config_hash}"
    assert collection.layer_count == 2
    assert collection.scanned_files == 2
    assert all(item.evidence.snippet is None for item in collection.observations)
    assert all(
        item.evidence.metadata["container_image_digest"] == collection.image_digest
        for item in collection.observations
    )
    assert all(item.asset_type == AssetType.CONTAINER for item in collection.observations)


def test_oci_archive_verifies_digest_and_scans_zstd_layer(tmp_path: Path) -> None:
    layer_tar = _tar_bytes({"etc/crypto.conf": b"cipher = ChaCha20\n"})
    layer = zstd.ZstdCompressor(level=1).compress(layer_tar)
    layer_digest = f"sha256:{hashlib.sha256(layer).hexdigest()}"
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{'0' * 64}",
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
                    "digest": layer_digest,
                    "size": len(layer),
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    manifest_digest = f"sha256:{hashlib.sha256(manifest).hexdigest()}"
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": manifest_digest,
                    "size": len(manifest),
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    archive_path = tmp_path / "oci.tar"
    _write_outer(
        archive_path,
        {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index,
            f"blobs/sha256/{manifest_digest.split(':', 1)[1]}": manifest,
            f"blobs/sha256/{layer_digest.split(':', 1)[1]}": layer,
        },
    )

    collection = ContainerImageScanner().scan_path(archive_path)

    assert collection.image_format == "oci"
    assert collection.image_digest == manifest_digest
    assert [item.family for item in collection.observations] == ["CHACHA20"]
    assert collection.observations[0].evidence.metadata["container_layer_digest"] == layer_digest


def test_oci_blob_digest_tampering_is_rejected(tmp_path: Path) -> None:
    payload = b"not-the-manifest"
    expected = "a" * 64
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{expected}",
                    "size": len(payload),
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        }
    ).encode()
    archive_path = tmp_path / "tampered.tar"
    _write_outer(
        archive_path,
        {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index,
            f"blobs/sha256/{expected}": payload,
        },
    )

    with pytest.raises(ContainerImageScanError, match="digest verification failed"):
        ContainerImageScanner().scan_path(archive_path)


def test_managed_container_locator_is_confined_to_archive_root(tmp_path: Path) -> None:
    root = tmp_path / "images"
    root.mkdir()
    scanner = ContainerImageScanner(archive_root=root)
    asset = ManagedAsset(
        workspace_id="workspace-1",
        name="image",
        kind=ManagedAssetKind.CONTAINER,
        locator="image-archive:../outside.tar",
    )

    with pytest.raises(ContainerImageScanError, match="escapes"):
        scanner.scan(asset)


def test_container_assets_have_first_class_scan_kind() -> None:
    asset = ManagedAsset(
        workspace_id="workspace-1",
        name="payments-image",
        kind=ManagedAssetKind.CONTAINER,
        locator="image-archive:payments.tar",
    )

    assert AssetScanExecutor.scan_kind(asset) == ScanKind.CONTAINER
