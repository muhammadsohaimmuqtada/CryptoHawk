from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from cryptohawk.domain.auth import (
    ROLE_RANK,
    ApiKeyMetadata,
    IssuedApiKey,
    IssuedToken,
    Principal,
    PrincipalKind,
    User,
    WorkspaceMembership,
    WorkspaceRole,
)
from cryptohawk.domain.inventory import Workspace
from cryptohawk.security.passwords import hash_password, verify_password
from cryptohawk.storage.database import Base
from cryptohawk.storage.inventory import InventoryRepository, WorkspaceRecord
from cryptohawk.storage.time import as_utc


class UserRecord(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(512))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class WorkspaceMembershipRecord(Base):
    __tablename__ = "workspace_memberships"
    __table_args__ = (
        UniqueConstraint("workspace_id", "user_id", name="uq_membership_workspace_user"),
    )

    workspace_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(20), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SessionRecord(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ApiKeyRecord(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    prefix: Mapped[str] = mapped_column(String(24), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20), index=True)
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _normalize_email(email: str) -> str:
    value = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise ValueError("invalid email address")
    return value


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if len(slug) < 2:
        slug = f"ws-{slug or 'workspace'}"
    return slug[:80]


class AuthRepository:
    def __init__(self, inventory: InventoryRepository) -> None:
        self.inventory = inventory
        self.engine = inventory.engine
        self.SessionLocal = inventory.SessionLocal

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def has_users(self) -> bool:
        with self.SessionLocal() as session:
            return bool(session.scalar(select(func.count()).select_from(UserRecord)))

    def bootstrap(
        self,
        *,
        email: str,
        display_name: str,
        password: str,
        workspace_name: str,
        workspace_slug: str | None = None,
        session_hours: int = 12,
    ) -> IssuedToken:
        email = _normalize_email(email)
        workspace = Workspace(
            name=workspace_name,
            slug=workspace_slug or _slugify(workspace_name),
        )
        user = User(email=email, display_name=display_name)
        password_digest = hash_password(password)
        with self.SessionLocal() as session:
            if session.scalar(select(func.count()).select_from(UserRecord)):
                raise RuntimeError("bootstrap is disabled after the first user is created")
            session.add(
                WorkspaceRecord(
                    id=workspace.id,
                    name=workspace.name,
                    slug=workspace.slug,
                    created_at=workspace.created_at,
                )
            )
            session.add(
                UserRecord(
                    id=user.id,
                    email=user.email,
                    display_name=user.display_name,
                    password_hash=password_digest,
                    active=True,
                    created_at=user.created_at,
                )
            )
            try:
                # Bootstrap uses scalar foreign-key IDs rather than ORM relationships.
                # Flush the referenced rows first so strict databases such as
                # PostgreSQL never observe the membership before its parents.
                # The flush remains inside the same transaction, preserving atomicity.
                session.flush()
                session.add(
                    WorkspaceMembershipRecord(
                        workspace_id=workspace.id,
                        user_id=user.id,
                        role=WorkspaceRole.OWNER.value,
                        created_at=user.created_at,
                    )
                )
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError("bootstrap identity or workspace already exists") from exc
        issued = self.create_session(user.id, session_hours=session_hours)
        return issued.model_copy(update={"user": user, "workspace": workspace})

    def login(self, *, email: str, password: str, session_hours: int = 12) -> IssuedToken:
        email = _normalize_email(email)
        with self.SessionLocal() as session:
            record = session.scalar(select(UserRecord).where(UserRecord.email == email))
            valid = (
                record is not None
                and record.active
                and verify_password(password, record.password_hash)
            )
            if not valid:
                raise PermissionError("invalid email or password")
            user = self._user_from_record(record)
        issued = self.create_session(user.id, session_hours=session_hours)
        return issued.model_copy(update={"user": user})

    def create_session(self, user_id: str, *, session_hours: int = 12) -> IssuedToken:
        if not 1 <= session_hours <= 24 * 30:
            raise ValueError("session_hours must be between 1 and 720")
        token = f"chs_{secrets.token_urlsafe(32)}"
        now = datetime.now(UTC)
        expires = now + timedelta(hours=session_hours)
        session_id = secrets.token_hex(16)
        with self.SessionLocal() as session:
            user = session.get(UserRecord, user_id)
            if user is None or not user.active:
                raise LookupError("active user not found")
            session.add(
                SessionRecord(
                    id=session_id,
                    user_id=user_id,
                    token_hash=_token_hash(token),
                    created_at=now,
                    expires_at=expires,
                )
            )
            session.commit()
        return IssuedToken(token=token, expires_at=expires)

    def revoke_session(self, principal: Principal) -> None:
        if principal.kind != PrincipalKind.SESSION:
            return
        with self.SessionLocal() as session:
            record = session.get(SessionRecord, principal.subject_id)
            if record is not None and record.revoked_at is None:
                record.revoked_at = datetime.now(UTC)
                session.commit()

    def authenticate(self, token: str) -> Principal:
        now = datetime.now(UTC)
        digest = _token_hash(token)
        if token.startswith("chs_"):
            with self.SessionLocal() as session:
                row = session.scalar(
                    select(SessionRecord).where(SessionRecord.token_hash == digest)
                )
                expired = row is None or as_utc(row.expires_at) <= now if row else True
                if row is None or row.revoked_at is not None or expired:
                    raise PermissionError("invalid or expired session")
                user = session.get(UserRecord, row.user_id)
                if user is None or not user.active:
                    raise PermissionError("user is inactive")
                row.last_used_at = now
                session.commit()
                return Principal(
                    kind=PrincipalKind.SESSION,
                    subject_id=row.id,
                    user_id=row.user_id,
                )

        if token.startswith("chk_"):
            with self.SessionLocal() as session:
                row = session.scalar(select(ApiKeyRecord).where(ApiKeyRecord.token_hash == digest))
                if row is None or row.revoked_at is not None:
                    raise PermissionError("invalid API key")
                if row.expires_at is not None and as_utc(row.expires_at) <= now:
                    raise PermissionError("expired API key")
                row.last_used_at = now
                session.commit()
                return Principal(
                    kind=PrincipalKind.API_KEY,
                    subject_id=row.id,
                    api_key_id=row.id,
                    api_key_workspace_id=row.workspace_id,
                    api_key_role=WorkspaceRole(row.role),
                )
        raise PermissionError("unsupported authentication token")

    def authorize_workspace(
        self,
        principal: Principal,
        workspace_id: str,
        minimum_role: WorkspaceRole = WorkspaceRole.VIEWER,
    ) -> WorkspaceRole:
        if principal.kind == PrincipalKind.API_KEY:
            if principal.api_key_workspace_id != workspace_id or principal.api_key_role is None:
                raise PermissionError("API key is not valid for this workspace")
            role = principal.api_key_role
        else:
            if principal.user_id is None:
                raise PermissionError("session has no user identity")
            with self.SessionLocal() as session:
                row = session.scalar(
                    select(WorkspaceMembershipRecord).where(
                        WorkspaceMembershipRecord.workspace_id == workspace_id,
                        WorkspaceMembershipRecord.user_id == principal.user_id,
                    )
                )
                if row is None:
                    raise PermissionError("user is not a member of this workspace")
                role = WorkspaceRole(row.role)
        if ROLE_RANK[role] < ROLE_RANK[minimum_role]:
            raise PermissionError(f"{minimum_role.value} role or higher is required")
        return role

    def list_workspaces(self, principal: Principal) -> list[Workspace]:
        with self.SessionLocal() as session:
            if principal.kind == PrincipalKind.API_KEY:
                if principal.api_key_workspace_id is None:
                    return []
                rows = session.scalars(
                    select(WorkspaceRecord).where(
                        WorkspaceRecord.id == principal.api_key_workspace_id
                    )
                ).all()
            else:
                if principal.user_id is None:
                    return []
                rows = session.scalars(
                    select(WorkspaceRecord)
                    .join(
                        WorkspaceMembershipRecord,
                        WorkspaceMembershipRecord.workspace_id == WorkspaceRecord.id,
                    )
                    .where(WorkspaceMembershipRecord.user_id == principal.user_id)
                    .order_by(WorkspaceRecord.name)
                ).all()
            return [self._workspace_from_record(row) for row in rows]

    def get_user(self, user_id: str) -> User | None:
        with self.SessionLocal() as session:
            row = session.get(UserRecord, user_id)
            return self._user_from_record(row) if row else None

    def create_workspace(
        self,
        *,
        principal: Principal,
        name: str,
        slug: str | None = None,
    ) -> Workspace:
        if principal.kind != PrincipalKind.SESSION or principal.user_id is None:
            raise PermissionError("a user session is required to create a workspace")
        workspace = Workspace(name=name, slug=slug or _slugify(name))
        with self.SessionLocal() as session:
            user = session.get(UserRecord, principal.user_id)
            if user is None or not user.active:
                raise PermissionError("active user session is required")
            session.add(
                WorkspaceRecord(
                    id=workspace.id,
                    name=workspace.name,
                    slug=workspace.slug,
                    created_at=workspace.created_at,
                )
            )
            session.add(
                WorkspaceMembershipRecord(
                    workspace_id=workspace.id,
                    user_id=principal.user_id,
                    role=WorkspaceRole.OWNER.value,
                    created_at=workspace.created_at,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError("workspace already exists") from exc
        return workspace

    def provision_member(
        self,
        *,
        principal: Principal,
        workspace_id: str,
        email: str,
        display_name: str,
        role: WorkspaceRole,
        password: str,
    ) -> tuple[User, WorkspaceMembership]:
        caller_role = self.authorize_workspace(principal, workspace_id, WorkspaceRole.ADMIN)
        if ROLE_RANK[role] > ROLE_RANK[caller_role]:
            raise PermissionError("cannot assign a role higher than the caller")
        email = _normalize_email(email)
        password_digest = hash_password(password)
        user = User(email=email, display_name=display_name)
        membership = WorkspaceMembership(
            workspace_id=workspace_id,
            user_id=user.id,
            role=role,
        )
        with self.SessionLocal() as session:
            existing = session.scalar(select(UserRecord).where(UserRecord.email == email))
            if existing is not None:
                user = self._user_from_record(existing)
                membership = membership.model_copy(update={"user_id": user.id})
            else:
                session.add(
                    UserRecord(
                        id=user.id,
                        email=user.email,
                        display_name=user.display_name,
                        password_hash=password_digest,
                        active=True,
                        created_at=user.created_at,
                    )
                )
            session.add(
                WorkspaceMembershipRecord(
                    workspace_id=workspace_id,
                    user_id=user.id,
                    role=membership.role.value,
                    created_at=membership.created_at,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ValueError("membership already exists") from exc
        return user, membership

    def list_members(
        self,
        principal: Principal,
        workspace_id: str,
    ) -> list[tuple[User, WorkspaceMembership]]:
        self.authorize_workspace(principal, workspace_id, WorkspaceRole.VIEWER)
        with self.SessionLocal() as session:
            rows = session.execute(
                select(UserRecord, WorkspaceMembershipRecord)
                .join(
                    WorkspaceMembershipRecord,
                    WorkspaceMembershipRecord.user_id == UserRecord.id,
                )
                .where(WorkspaceMembershipRecord.workspace_id == workspace_id)
                .order_by(UserRecord.email)
            ).all()
            return [
                (
                    self._user_from_record(user),
                    WorkspaceMembership(
                        workspace_id=membership.workspace_id,
                        user_id=membership.user_id,
                        role=WorkspaceRole(membership.role),
                        created_at=as_utc(membership.created_at),
                    ),
                )
                for user, membership in rows
            ]

    def create_api_key(
        self,
        *,
        principal: Principal,
        workspace_id: str,
        name: str,
        role: WorkspaceRole,
        expires_days: int | None = None,
    ) -> IssuedApiKey:
        caller_role = self.authorize_workspace(principal, workspace_id, WorkspaceRole.ADMIN)
        if ROLE_RANK[role] > ROLE_RANK[caller_role]:
            raise PermissionError("cannot create an API key with a higher role than the caller")
        if role == WorkspaceRole.OWNER:
            raise ValueError("API keys cannot be workspace owners")
        if expires_days is not None and not 1 <= expires_days <= 3650:
            raise ValueError("expires_days must be between 1 and 3650")

        token = f"chk_{secrets.token_urlsafe(32)}"
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=expires_days) if expires_days else None
        metadata = ApiKeyMetadata(
            workspace_id=workspace_id,
            name=name,
            prefix=token[:16],
            role=role,
            created_by_user_id=principal.user_id,
            created_at=now,
            expires_at=expires_at,
        )
        with self.SessionLocal() as session:
            session.add(
                ApiKeyRecord(
                    id=metadata.id,
                    workspace_id=workspace_id,
                    name=metadata.name,
                    prefix=metadata.prefix,
                    token_hash=_token_hash(token),
                    role=metadata.role.value,
                    created_by_user_id=metadata.created_by_user_id,
                    created_at=metadata.created_at,
                    expires_at=metadata.expires_at,
                )
            )
            session.commit()
        return IssuedApiKey(token=token, metadata=metadata)

    def list_api_keys(self, principal: Principal, workspace_id: str) -> list[ApiKeyMetadata]:
        self.authorize_workspace(principal, workspace_id, WorkspaceRole.ADMIN)
        with self.SessionLocal() as session:
            rows = session.scalars(
                select(ApiKeyRecord)
                .where(ApiKeyRecord.workspace_id == workspace_id)
                .order_by(ApiKeyRecord.created_at.desc())
            ).all()
            return [self._api_key_from_record(row) for row in rows]

    def revoke_api_key(self, principal: Principal, workspace_id: str, key_id: str) -> None:
        self.authorize_workspace(principal, workspace_id, WorkspaceRole.ADMIN)
        with self.SessionLocal() as session:
            row = session.scalar(
                select(ApiKeyRecord).where(
                    ApiKeyRecord.id == key_id,
                    ApiKeyRecord.workspace_id == workspace_id,
                )
            )
            if row is None:
                raise LookupError("API key not found in workspace")
            if row.revoked_at is None:
                row.revoked_at = datetime.now(UTC)
                session.commit()

    @staticmethod
    def _user_from_record(row: UserRecord) -> User:
        return User(
            id=row.id,
            email=row.email,
            display_name=row.display_name,
            active=row.active,
            created_at=as_utc(row.created_at),
        )

    @staticmethod
    def _workspace_from_record(row: WorkspaceRecord) -> Workspace:
        return Workspace(
            id=row.id,
            name=row.name,
            slug=row.slug,
            created_at=as_utc(row.created_at),
        )

    @staticmethod
    def _api_key_from_record(row: ApiKeyRecord) -> ApiKeyMetadata:
        return ApiKeyMetadata(
            id=row.id,
            workspace_id=row.workspace_id,
            name=row.name,
            prefix=row.prefix,
            role=WorkspaceRole(row.role),
            created_by_user_id=row.created_by_user_id,
            created_at=as_utc(row.created_at),
            expires_at=as_utc(row.expires_at),
            last_used_at=as_utc(row.last_used_at),
            revoked_at=as_utc(row.revoked_at),
        )
