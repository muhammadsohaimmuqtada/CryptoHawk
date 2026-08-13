import base64
from pathlib import Path

import pytest
from sqlalchemy import select

from cryptohawk.domain.credentials import ConnectorCredentialKind
from cryptohawk.security.secrets import (
    SecretConfigurationError,
    SecretDecryptionError,
    VersionedAesGcmCipher,
)
from cryptohawk.storage.credentials import (
    ConnectorCredentialRecord,
    ConnectorCredentialRepository,
)
from cryptohawk.storage.inventory import InventoryRepository


def _encoded(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


def _cipher(*, active_version: int = 1, include_v2: bool = False) -> VersionedAesGcmCipher:
    entries = [f"1:{_encoded(b'A' * 32)}"]
    if include_v2:
        entries.append(f"2:{_encoded(b'B' * 32)}")
    return VersionedAesGcmCipher.from_spec(
        ",".join(entries),
        active_version=active_version,
    )


def _repository(tmp_path: Path, cipher: VersionedAesGcmCipher | None = None):
    url = f"sqlite:///{tmp_path / 'credentials.db'}"
    inventory = InventoryRepository(url)
    repository = ConnectorCredentialRepository(inventory, cipher or _cipher())
    repository.create_schema()
    workspace = inventory.create_workspace(name="Acme")
    return inventory, repository, workspace


def test_cipher_requires_256_bit_keys_and_active_version() -> None:
    with pytest.raises(SecretConfigurationError):
        VersionedAesGcmCipher.from_spec(
            f"1:{_encoded(b'short')}",
            active_version=1,
        )
    with pytest.raises(SecretConfigurationError):
        VersionedAesGcmCipher.from_spec(
            f"1:{_encoded(b'A' * 32)}",
            active_version=2,
        )


def test_secret_is_ciphertext_at_rest_and_metadata_is_redacted(tmp_path: Path) -> None:
    _, repository, workspace = _repository(tmp_path)
    token = "ghp_super-secret-value-that-must-never-be-stored-plaintext"

    metadata = repository.create(
        workspace_id=workspace.id,
        name="GitHub production",
        kind=ConnectorCredentialKind.GITHUB_TOKEN,
        secret={"token": token},
        created_by="session:user-1",
    )

    assert metadata.secret_fields == ["token"]
    assert "secret" not in metadata.model_dump()
    assert "token" not in metadata.model_dump()
    with repository.SessionLocal() as session:
        record = session.scalar(
            select(ConnectorCredentialRecord).where(
                ConnectorCredentialRecord.id == metadata.id
            )
        )
        assert record is not None
        assert token.encode() not in bytes(record.ciphertext)
        assert token not in record.secret_fields_json
        assert len(record.nonce) == 12
        assert record.key_version == 1

    assert repository.resolve_for_use(
        workspace_id=workspace.id,
        credential_id=metadata.id,
    ) == {"token": token}


def test_workspace_binding_blocks_cross_tenant_secret_access(tmp_path: Path) -> None:
    inventory, repository, workspace = _repository(tmp_path)
    other = inventory.create_workspace(name="Other")
    metadata = repository.create(
        workspace_id=workspace.id,
        name="GitHub",
        kind=ConnectorCredentialKind.GITHUB_TOKEN,
        secret={"token": "tenant-one-token"},
        created_by="session:user-1",
    )

    with pytest.raises(LookupError):
        repository.get_metadata(
            workspace_id=other.id,
            credential_id=metadata.id,
        )
    with pytest.raises(LookupError):
        repository.resolve_for_use(
            workspace_id=other.id,
            credential_id=metadata.id,
        )
    with pytest.raises(LookupError):
        repository.delete(
            workspace_id=other.id,
            credential_id=metadata.id,
        )


def test_authenticated_encryption_rejects_ciphertext_tampering(tmp_path: Path) -> None:
    _, repository, workspace = _repository(tmp_path)
    metadata = repository.create(
        workspace_id=workspace.id,
        name="Registry",
        kind=ConnectorCredentialKind.REGISTRY_BASIC,
        secret={"username": "scanner", "password": "very-secret"},
        created_by="session:user-1",
    )

    with repository.SessionLocal() as session:
        record = session.scalar(
            select(ConnectorCredentialRecord).where(
                ConnectorCredentialRecord.id == metadata.id
            )
        )
        assert record is not None
        tampered = bytearray(record.ciphertext)
        tampered[0] ^= 1
        record.ciphertext = bytes(tampered)
        session.commit()

    with pytest.raises(SecretDecryptionError):
        repository.resolve_for_use(
            workspace_id=workspace.id,
            credential_id=metadata.id,
        )


def test_key_rotation_reencrypts_with_active_version(tmp_path: Path) -> None:
    inventory, repository_v1, workspace = _repository(tmp_path, _cipher())
    metadata = repository_v1.create(
        workspace_id=workspace.id,
        name="Cloud",
        kind=ConnectorCredentialKind.CLOUD_ACCESS_KEY,
        secret={
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "cloud-secret",
        },
        created_by="session:user-1",
    )

    with repository_v1.SessionLocal() as session:
        before = session.scalar(
            select(ConnectorCredentialRecord).where(
                ConnectorCredentialRecord.id == metadata.id
            )
        )
        assert before is not None
        before_ciphertext = bytes(before.ciphertext)

    repository_v2 = ConnectorCredentialRepository(
        inventory,
        _cipher(active_version=2, include_v2=True),
    )
    rotated = repository_v2.rotate_encryption(
        workspace_id=workspace.id,
        credential_id=metadata.id,
    )

    assert rotated.key_version == 2
    with repository_v2.SessionLocal() as session:
        after = session.scalar(
            select(ConnectorCredentialRecord).where(
                ConnectorCredentialRecord.id == metadata.id
            )
        )
        assert after is not None
        assert after.key_version == 2
        assert bytes(after.ciphertext) != before_ciphertext

    assert repository_v2.resolve_for_use(
        workspace_id=workspace.id,
        credential_id=metadata.id,
    ) == {
        "access_key_id": "AKIAEXAMPLE",
        "secret_access_key": "cloud-secret",
    }


def test_credential_kind_rejects_unexpected_or_missing_fields(tmp_path: Path) -> None:
    _, repository, workspace = _repository(tmp_path)

    with pytest.raises(ValueError, match="missing required"):
        repository.create(
            workspace_id=workspace.id,
            name="SSH",
            kind=ConnectorCredentialKind.SSH_PRIVATE_KEY,
            secret={"username": "root"},
            created_by="session:user-1",
        )
    with pytest.raises(ValueError, match="unsupported secret fields"):
        repository.create(
            workspace_id=workspace.id,
            name="GitHub",
            kind=ConnectorCredentialKind.GITHUB_TOKEN,
            secret={"token": "safe", "password": "should-not-be-here"},
            created_by="session:user-1",
        )
