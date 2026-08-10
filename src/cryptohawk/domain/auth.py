from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from cryptohawk.domain.inventory import Workspace, utcnow


class WorkspaceRole(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    OWNER = "owner"


ROLE_RANK = {
    WorkspaceRole.VIEWER: 10,
    WorkspaceRole.ANALYST: 20,
    WorkspaceRole.ADMIN: 30,
    WorkspaceRole.OWNER: 40,
}


class PrincipalKind(StrEnum):
    SESSION = "session"
    API_KEY = "api-key"


class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=200)
    active: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class WorkspaceMembership(BaseModel):
    workspace_id: str
    user_id: str
    role: WorkspaceRole
    created_at: datetime = Field(default_factory=utcnow)


class Principal(BaseModel):
    kind: PrincipalKind
    subject_id: str
    user_id: str | None = None
    api_key_id: str | None = None
    api_key_workspace_id: str | None = None
    api_key_role: WorkspaceRole | None = None


class ApiKeyMetadata(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str
    name: str = Field(min_length=1, max_length=200)
    prefix: str
    role: WorkspaceRole
    created_by_user_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class IssuedToken(BaseModel):
    token: str
    expires_at: datetime
    user: User | None = None
    workspace: Workspace | None = None


class IssuedApiKey(BaseModel):
    token: str
    metadata: ApiKeyMetadata
