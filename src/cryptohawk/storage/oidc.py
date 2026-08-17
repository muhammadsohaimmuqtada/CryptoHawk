from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.security.oidc import OidcTransactionCipher, OidcTransactionSecret
from cryptohawk.security.secrets import EncryptedSecret
from cryptohawk.storage.auth import UserRecord
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.time import as_utc


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class OidcIdentityRecord(Base):
    __tablename__ = "oidc_identities"
    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_oidc_identity_issuer_subject"),
        UniqueConstraint("issuer", "user_id", name="uq_oidc_identity_issuer_user"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(1000), index=True)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    email_at_link: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class OidcLoginTransactionRecord(Base):
    __tablename__ = "oidc_login_transactions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    browser_binding_hash: Mapped[str] = mapped_column(String(64), index=True)
    payload_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    payload_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class OidcLoginCompletionRecord(Base):
    __tablename__ = "oidc_login_completions"

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    browser_binding_hash: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


@dataclass(frozen=True)
class OidcLoginSecret:
    code_verifier: str
    nonce: str


class OidcRepository:
    def __init__(
        self,
        inventory: InventoryRepository,
        *,
        cipher: OidcTransactionCipher,
    ) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal
        self.cipher = cipher

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def begin_login(
        self,
        *,
        state: str,
        browser_binding: str,
        code_verifier: str,
        nonce: str,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        transaction_id = secrets.token_hex(16)
        encrypted = self.cipher.encrypt(
            OidcTransactionSecret(code_verifier=code_verifier, nonce=nonce),
            transaction_id=transaction_id,
        )
        with self.SessionLocal() as session:
            session.execute(
                delete(OidcLoginTransactionRecord).where(
                    OidcLoginTransactionRecord.expires_at <= current
                )
            )
            session.add(
                OidcLoginTransactionRecord(
                    id=transaction_id,
                    state_hash=_digest(state),
                    browser_binding_hash=_digest(browser_binding),
                    payload_ciphertext=encrypted.ciphertext,
                    payload_nonce=encrypted.nonce,
                    key_version=encrypted.key_version,
                    created_at=current,
                    expires_at=current + timedelta(seconds=ttl_seconds),
                )
            )
            session.commit()

    def consume_login(
        self,
        *,
        state: str,
        browser_binding: str,
        now: datetime | None = None,
    ) -> OidcLoginSecret:
        current = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            row = session.scalar(
                select(OidcLoginTransactionRecord)
                .where(OidcLoginTransactionRecord.state_hash == _digest(state))
                .with_for_update()
            )
            if row is None:
                raise PermissionError("invalid or already used OIDC state")
            if as_utc(row.expires_at) <= current:
                session.delete(row)
                session.commit()
                raise PermissionError("OIDC login transaction expired")
            if not secrets.compare_digest(
                row.browser_binding_hash,
                _digest(browser_binding),
            ):
                raise PermissionError("OIDC browser binding mismatch")
            secret = self.cipher.decrypt(
                EncryptedSecret(
                    ciphertext=row.payload_ciphertext,
                    nonce=row.payload_nonce,
                    key_version=row.key_version,
                ),
                transaction_id=row.id,
            )
            session.delete(row)
            session.commit()
            return OidcLoginSecret(
                code_verifier=secret.code_verifier,
                nonce=secret.nonce,
            )

    def resolve_identity(
        self,
        *,
        issuer: str,
        subject: str,
        email: str,
        now: datetime | None = None,
    ) -> str:
        current = now or datetime.now(UTC)
        normalized_email = email.strip().lower()
        with self.SessionLocal() as session:
            identity = session.scalar(
                select(OidcIdentityRecord).where(
                    OidcIdentityRecord.issuer == issuer,
                    OidcIdentityRecord.subject == subject,
                )
            )
            if identity is not None:
                user = session.get(UserRecord, identity.user_id)
                if user is None or not user.active:
                    raise PermissionError("linked CryptoHawk user is inactive")
                identity.last_login_at = current
                session.commit()
                return user.id

            user = session.scalar(select(UserRecord).where(UserRecord.email == normalized_email))
            if user is None or not user.active:
                raise PermissionError("SSO identity is not provisioned in CryptoHawk")
            existing_link = session.scalar(
                select(OidcIdentityRecord).where(
                    OidcIdentityRecord.issuer == issuer,
                    OidcIdentityRecord.user_id == user.id,
                )
            )
            if existing_link is not None:
                raise PermissionError("CryptoHawk user is already linked to another SSO subject")

            session.add(
                OidcIdentityRecord(
                    id=secrets.token_hex(16),
                    issuer=issuer,
                    subject=subject,
                    user_id=user.id,
                    email_at_link=normalized_email,
                    created_at=current,
                    last_login_at=current,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                resolved = session.scalar(
                    select(OidcIdentityRecord).where(
                        OidcIdentityRecord.issuer == issuer,
                        OidcIdentityRecord.subject == subject,
                    )
                )
                if resolved is not None and resolved.user_id == user.id:
                    return user.id
                raise PermissionError("OIDC identity link conflict") from exc
            return user.id

    def create_completion(
        self,
        *,
        user_id: str,
        browser_binding: str,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> str:
        current = now or datetime.now(UTC)
        raw_code = f"choc_{secrets.token_urlsafe(32)}"
        with self.SessionLocal() as session:
            session.execute(
                delete(OidcLoginCompletionRecord).where(
                    OidcLoginCompletionRecord.expires_at <= current
                )
            )
            session.add(
                OidcLoginCompletionRecord(
                    code_hash=_digest(raw_code),
                    browser_binding_hash=_digest(browser_binding),
                    user_id=user_id,
                    created_at=current,
                    expires_at=current + timedelta(seconds=ttl_seconds),
                )
            )
            session.commit()
        return raw_code

    def consume_completion(
        self,
        *,
        code: str,
        browser_binding: str,
        now: datetime | None = None,
    ) -> str:
        current = now or datetime.now(UTC)
        with self.SessionLocal() as session:
            row = session.scalar(
                select(OidcLoginCompletionRecord)
                .where(OidcLoginCompletionRecord.code_hash == _digest(code))
                .with_for_update()
            )
            if row is None:
                raise PermissionError("invalid or already used OIDC completion")
            if as_utc(row.expires_at) <= current:
                session.delete(row)
                session.commit()
                raise PermissionError("OIDC completion expired")
            if not secrets.compare_digest(
                row.browser_binding_hash,
                _digest(browser_binding),
            ):
                raise PermissionError("OIDC completion browser binding mismatch")
            user = session.get(UserRecord, row.user_id)
            if user is None or not user.active:
                session.delete(row)
                session.commit()
                raise PermissionError("SSO user is inactive")
            user_id = row.user_id
            session.delete(row)
            session.commit()
            return user_id


__all__ = [
    "OidcIdentityRecord",
    "OidcLoginCompletionRecord",
    "OidcLoginSecret",
    "OidcLoginTransactionRecord",
    "OidcRepository",
]
