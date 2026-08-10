from pathlib import Path

import pytest
from sqlalchemy import select

from cryptohawk.domain.auth import PrincipalKind, WorkspaceRole
from cryptohawk.storage.auth import AuthRepository, SessionRecord
from cryptohawk.storage.inventory import InventoryRepository


def _auth(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'auth.db'}"
    inventory = InventoryRepository(url)
    auth = AuthRepository(inventory)
    auth.create_schema()
    return inventory, auth


def test_bootstrap_login_and_hashed_session_storage(tmp_path: Path) -> None:
    _, auth = _auth(tmp_path)
    issued = auth.bootstrap(
        email="owner@example.com",
        display_name="Owner",
        password="correct-horse-battery-staple",
        workspace_name="Acme",
    )
    assert issued.user is not None
    assert issued.workspace is not None
    assert issued.token.startswith("chs_")
    principal = auth.authenticate(issued.token)
    assert principal.kind == PrincipalKind.SESSION
    assert principal.user_id == issued.user.id
    assert auth.authorize_workspace(principal, issued.workspace.id) == WorkspaceRole.OWNER

    with auth.SessionLocal() as session:
        stored = session.scalar(select(SessionRecord))
        assert stored is not None
        assert stored.token_hash != issued.token
        assert len(stored.token_hash) == 64

    login = auth.login(
        email="OWNER@example.com",
        password="correct-horse-battery-staple",
    )
    assert login.token.startswith("chs_")

    with pytest.raises(PermissionError):
        auth.login(email="owner@example.com", password="incorrect-password")
    with pytest.raises(RuntimeError):
        auth.bootstrap(
            email="other@example.com",
            display_name="Other",
            password="another-secure-password",
            workspace_name="Other",
        )


def test_api_key_is_workspace_scoped_and_role_limited(tmp_path: Path) -> None:
    inventory, auth = _auth(tmp_path)
    issued = auth.bootstrap(
        email="owner@example.com",
        display_name="Owner",
        password="correct-horse-battery-staple",
        workspace_name="Acme",
    )
    assert issued.workspace is not None
    principal = auth.authenticate(issued.token)

    key = auth.create_api_key(
        principal=principal,
        workspace_id=issued.workspace.id,
        name="CI scanner",
        role=WorkspaceRole.ANALYST,
    )
    assert key.token.startswith("chk_")
    key_principal = auth.authenticate(key.token)
    assert auth.authorize_workspace(
        key_principal,
        issued.workspace.id,
        WorkspaceRole.ANALYST,
    ) == WorkspaceRole.ANALYST
    with pytest.raises(PermissionError):
        auth.authorize_workspace(
            key_principal,
            issued.workspace.id,
            WorkspaceRole.ADMIN,
        )

    other = inventory.create_workspace(name="Other")
    with pytest.raises(PermissionError):
        auth.authorize_workspace(key_principal, other.id)

    auth.revoke_api_key(principal, issued.workspace.id, key.metadata.id)
    with pytest.raises(PermissionError):
        auth.authenticate(key.token)


def test_password_minimum_and_role_ceiling(tmp_path: Path) -> None:
    _, auth = _auth(tmp_path)
    with pytest.raises(ValueError):
        auth.bootstrap(
            email="owner@example.com",
            display_name="Owner",
            password="too-short",
            workspace_name="Acme",
        )

    issued = auth.bootstrap(
        email="owner@example.com",
        display_name="Owner",
        password="correct-horse-battery-staple",
        workspace_name="Acme",
    )
    assert issued.workspace is not None
    principal = auth.authenticate(issued.token)
    with pytest.raises(ValueError):
        auth.create_api_key(
            principal=principal,
            workspace_id=issued.workspace.id,
            name="owner-key",
            role=WorkspaceRole.OWNER,
        )


def test_workspace_member_provisioning_and_role_boundary(tmp_path: Path) -> None:
    _, auth = _auth(tmp_path)
    issued = auth.bootstrap(
        email="owner@example.com",
        display_name="Owner",
        password="correct-horse-battery-staple",
        workspace_name="Acme",
    )
    assert issued.workspace is not None
    owner = auth.authenticate(issued.token)

    analyst, membership = auth.provision_member(
        principal=owner,
        workspace_id=issued.workspace.id,
        email="analyst@example.com",
        display_name="Analyst",
        role=WorkspaceRole.ANALYST,
        password="analyst-secure-password",
    )
    assert membership.user_id == analyst.id
    analyst_login = auth.login(
        email="analyst@example.com",
        password="analyst-secure-password",
    )
    analyst_principal = auth.authenticate(analyst_login.token)
    assert auth.authorize_workspace(
        analyst_principal,
        issued.workspace.id,
        WorkspaceRole.ANALYST,
    ) == WorkspaceRole.ANALYST
    with pytest.raises(PermissionError):
        auth.authorize_workspace(
            analyst_principal,
            issued.workspace.id,
            WorkspaceRole.ADMIN,
        )

    members = auth.list_members(owner, issued.workspace.id)
    assert {user.email for user, _ in members} == {
        "analyst@example.com",
        "owner@example.com",
    }

    second = auth.create_workspace(principal=owner, name="Research")
    assert auth.authorize_workspace(owner, second.id) == WorkspaceRole.OWNER
