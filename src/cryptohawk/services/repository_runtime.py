from __future__ import annotations

from cryptohawk.config import settings
from cryptohawk.scanners.repository import RepositoryScanner
from cryptohawk.security.secrets import VersionedAesGcmCipher
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.credentials import ConnectorCredentialRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.repositories import RepositoryAssetRepository


def build_connector_credentials(
    inventory: InventoryRepository,
) -> ConnectorCredentialRepository | None:
    if not settings.connector_encryption_keys.strip():
        return None
    cipher = VersionedAesGcmCipher.from_spec(
        settings.connector_encryption_keys,
        active_version=settings.connector_encryption_active_version,
    )
    return ConnectorCredentialRepository(inventory, cipher)


def build_repository_scanner(
    inventory: InventoryRepository,
    history: ContinuousRepository,
) -> RepositoryScanner:
    return RepositoryScanner(
        RepositoryAssetRepository(inventory),
        history,
        credentials=build_connector_credentials(inventory),
    )
