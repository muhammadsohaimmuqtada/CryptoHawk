from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.credentials import (
    ConnectorCredentialKind,
    ConnectorCredentialMetadata,
    validate_secret_material,
)
from cryptohawk.security.secrets import EncryptedSecret, VersionedAesGcmCipher
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.time import as_utc


class ConnectorCredentialRecord(Base):
    __tablename__ = "connector_credentials"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "name",
            name="uq_connector_credentials_workspace_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(50), index=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer, index=True)
    secret_fields_json: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(200), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )


class ConnectorCredentialRepository:
    def __init__(
        self,
        inventory: InventoryRepository,
        cipher: VersionedAesGcmCipher,
    ) -> None:
        self.inventory = inventory
        self.cipher = cipher
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def create(
        self,
        *,
        workspace_id: str,
        name: str,
        kind: ConnectorCredentialKind,
        secret: dict[str, str],
        created_by: str,
        now: datetime | None = None,
    ) -> ConnectorCredentialMetadata:
        workspace = self.inventory.get_workspace(workspace_id)
        if workspace is None:
            raise LookupError("workspace not found")
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("credential name is required")
        if len(clean_name) > 200:
            raise ValueError("credential name is too long")
        if not created_by.strip():
            raise ValueError("created_by is required")

        material = validate_secret_material(kind, secret)
        current = now or datetime.now(UTC)
        metadata = ConnectorCredentialMetadata(
            workspace_id=workspace_id,
            name=clean_name,
            kind=kind,
            key_version=self.cipher.active_version,
            secret_fields=sorted(material),
            created_by=created_by,
            created_at=current,
            updated_at=current,
        )
        encrypted = self.cipher.encrypt(
            material,
            workspace_id=workspace_id,
            credential_id=metadata.id,
            kind=kind.value,
        )
        with self.SessionLocal() as session:
            existing = session.scalar(
                select(ConnectorCredentialRecord.id).where(
                    ConnectorCredentialRecord.workspace_id == workspace_id,
                    ConnectorCredentialRecord.name == clean_name,
                )
            )
            if existing is not None:
                raise ValueError("credential name already exists in workspace")
            session.add(
                ConnectorCredentialRecord(
                    id=metadata.id,
                    workspace_id=workspace_id,
                    name=clean_name,
                    kind=kind.value,
                    ciphertext=encrypted.ciphertext,
                    nonce=encrypted.nonce,
                    key_version=encrypted.key_version,
                    secret_fields_json=json.dumps(metadata.secret_fields),
                    created_by=created_by,
                    created_at=current,
                    updated_at=current,
                    last_used_at=None,
                )
            )
            session.commit()
        return metadata

    def list_workspace(self, workspace_id: str) -> list[ConnectorCredentialMetadata]:
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(ConnectorCredentialRecord)
                .where(ConnectorCredentialRecord.workspace_id == workspace_id)
                .order_by(
                    ConnectorCredentialRecord.name,
                    ConnectorCredentialRecord.id,
                )
            ).all()
            return [self._metadata(row) for row in rows]

    def get_metadata(
        self,
        *,
        workspace_id: str,
        credential_id: str,
    ) -> ConnectorCredentialMetadata:
        with self.SessionLocal() as session:
            row = self._get_record(session, workspace_id, credential_id)
            return self._metadata(row)

    def replace(
        self,
        *,
        workspace_id: str,
        credential_id: str,
        secret: dict[str, str],
        name: str | None = None,
        now: datetime | None = None,
    ) -> ConnectorCredentialMetadata:
        current = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            row = self._get_record(session, workspace_id, credential_id)
            kind = ConnectorCredentialKind(row.kind)
            material = validate_secret_material(kind, secret)
            clean_name = row.name if name is None else name.strip()
            if not clean_name:
                raise ValueError("credential name is required")
            if len(clean_name) > 200:
                raise ValueError("credential name is too long")
            if clean_name != row.name:
                duplicate = session.scalar(
                    select(ConnectorCredentialRecord.id).where(
                        ConnectorCredentialRecord.workspace_id == workspace_id,
                        ConnectorCredentialRecord.name == clean_name,
                        ConnectorCredentialRecord.id != credential_id,
                    )
                )
                if duplicate is not None:
                    raise ValueError("credential name already exists in workspace")
            encrypted = self.cipher.encrypt(
                material,
                workspace_id=workspace_id,
                credential_id=credential_id,
                kind=row.kind,
            )
            row.name = clean_name
            row.ciphertext = encrypted.ciphertext
            row.nonce = encrypted.nonce
            row.key_version = encrypted.key_version
            row.secret_fields_json = json.dumps(sorted(material))
            row.updated_at = current
            session.commit()
            session.refresh(row)
            return self._metadata(row)

    def rotate_encryption(
        self,
        *,
        workspace_id: str,
        credential_id: str,
        now: datetime | None = None,
    ) -> ConnectorCredentialMetadata:
        current = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            row = self._get_record(session, workspace_id, credential_id)
            material = self.cipher.decrypt(
                EncryptedSecret(
                    ciphertext=bytes(row.ciphertext),
                    nonce=bytes(row.nonce),
                    key_version=row.key_version,
                ),
                workspace_id=workspace_id,
                credential_id=credential_id,
                kind=row.kind,
            )
            encrypted = self.cipher.encrypt(
                material,
                workspace_id=workspace_id,
                credential_id=credential_id,
                kind=row.kind,
            )
            row.ciphertext = encrypted.ciphertext
            row.nonce = encrypted.nonce
            row.key_version = encrypted.key_version
            row.updated_at = current
            session.commit()
            session.refresh(row)
            return self._metadata(row)

    def resolve_for_use(
        self,
        *,
        workspace_id: str,
        credential_id: str,
        now: datetime | None = None,
    ) -> dict[str, str]:
        current = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            row = self._get_record(session, workspace_id, credential_id)
            material = self.cipher.decrypt(
                EncryptedSecret(
                    ciphertext=bytes(row.ciphertext),
                    nonce=bytes(row.nonce),
                    key_version=row.key_version,
                ),
                workspace_id=workspace_id,
                credential_id=credential_id,
                kind=row.kind,
            )
            row.last_used_at = current
            session.commit()
            return material

    def delete(self, *, workspace_id: str, credential_id: str) -> None:
        with self.SessionLocal() as session:
            row = self._get_record(session, workspace_id, credential_id)
            session.delete(row)
            session.commit()

    @staticmethod
    def _get_record(session, workspace_id: str, credential_id: str) -> ConnectorCredentialRecord:
        row = session.scalar(
            select(ConnectorCredentialRecord).where(
                ConnectorCredentialRecord.id == credential_id,
                ConnectorCredentialRecord.workspace_id == workspace_id,
            )
        )
        if row is None:
            raise LookupError("credential not found in workspace")
        return row

    @staticmethod
    def _metadata(row: ConnectorCredentialRecord) -> ConnectorCredentialMetadata:
        fields = json.loads(row.secret_fields_json)
        return ConnectorCredentialMetadata(
            id=row.id,
            workspace_id=row.workspace_id,
            name=row.name,
            kind=ConnectorCredentialKind(row.kind),
            key_version=row.key_version,
            secret_fields=list(fields),
            created_by=row.created_by,
            created_at=as_utc(row.created_at),
            updated_at=as_utc(row.updated_at),
            last_used_at=as_utc(row.last_used_at) if row.last_used_at is not None else None,
        )
