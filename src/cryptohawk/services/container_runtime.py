from __future__ import annotations

from cryptohawk.config import settings
from cryptohawk.scanners.container_image import ContainerImageScanner


def build_container_scanner() -> ContainerImageScanner:
    return ContainerImageScanner(
        archive_root=settings.container_archive_root or None,
        platform_os=settings.container_platform_os,
        platform_arch=settings.container_platform_arch,
        max_archive_bytes=settings.container_max_archive_bytes,
        max_layers=settings.container_max_layers,
        max_layer_compressed_bytes=settings.container_max_layer_compressed_bytes,
        max_layer_uncompressed_bytes=settings.container_max_layer_uncompressed_bytes,
        max_entries=settings.container_max_entries,
        max_file_bytes=settings.container_max_file_bytes,
        max_scan_bytes=settings.container_max_scan_bytes,
    )
