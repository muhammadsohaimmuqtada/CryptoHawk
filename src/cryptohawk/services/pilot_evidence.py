from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from cryptohawk.services.reporting import ReportingService
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.time import as_utc

_BUNDLE_SCHEMA = "cryptohawk-pilot-evidence/v1"
_DISCLAIMER = (
    "This bundle is a point-in-time export of CryptoHawk evidence. It does not "
    "certify that a commercial pilot, security assessment, or production-readiness "
    "gate has passed."
)


def _utc(value: datetime | None = None) -> datetime:
    return as_utc(value or datetime.now(UTC)) or datetime.now(UTC)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
            default=str,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _zip_info(path: str, generated_at: datetime) -> ZipInfo:
    # ZIP timestamps have two-second resolution and cannot represent years before 1980.
    stamp = generated_at.astimezone(UTC).replace(microsecond=0)
    second = stamp.second - (stamp.second % 2)
    info = ZipInfo(
        path,
        date_time=(
            max(stamp.year, 1980),
            stamp.month,
            stamp.day,
            stamp.hour,
            stamp.minute,
            second,
        ),
    )
    info.compress_type = ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info


class PilotEvidenceService:
    """Build a portable, integrity-verifiable evidence bundle for customer pilots."""

    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.reporting = ReportingService(inventory)

    def build_bundle(
        self,
        workspace_id: str,
        *,
        now: datetime | None = None,
    ) -> bytes:
        generated_at = _utc(now)
        executive = self.reporting.executive_report(workspace_id, now=generated_at)
        engineering = self.reporting.engineering_report(workspace_id, now=generated_at)
        cbom = self.reporting.current_cbom(workspace_id)

        files: dict[str, tuple[str, bytes]] = {
            "executive.json": (
                "application/json",
                _json_bytes(executive.model_dump(mode="json")),
            ),
            "engineering.json": (
                "application/json",
                _json_bytes(engineering.model_dump(mode="json")),
            ),
            "executive.csv": (
                "text/csv",
                self.reporting.executive_csv(
                    workspace_id,
                    now=generated_at,
                ).encode("utf-8"),
            ),
            "engineering.csv": (
                "text/csv",
                self.reporting.engineering_csv(
                    workspace_id,
                    now=generated_at,
                ).encode("utf-8"),
            ),
            "executive.html": (
                "text/html",
                self.reporting.executive_html(
                    workspace_id,
                    now=generated_at,
                ).encode("utf-8"),
            ),
            "cbom.cdx.json": (
                "application/vnd.cyclonedx+json",
                _json_bytes(cbom),
            ),
        }

        metadata = executive.metadata
        manifest = {
            "schema": _BUNDLE_SCHEMA,
            "generated_at": generated_at.isoformat(),
            "workspace": {
                "id": metadata.workspace_id,
                "name": metadata.workspace_name,
                "slug": metadata.workspace_slug,
            },
            "policy": metadata.policy.model_dump(mode="json"),
            "artifacts": [
                {
                    "path": path,
                    "media_type": media_type,
                    "bytes": len(content),
                    "sha256": _sha256(content),
                }
                for path, (media_type, content) in sorted(files.items())
            ],
            "disclaimer": _DISCLAIMER,
        }
        manifest_bytes = _json_bytes(manifest)

        buffer = BytesIO()
        with ZipFile(buffer, mode="w") as archive:
            archive.writestr(_zip_info("manifest.json", generated_at), manifest_bytes)
            for path, (_, content) in sorted(files.items()):
                archive.writestr(_zip_info(path, generated_at), content)
        return buffer.getvalue()
