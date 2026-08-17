import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from cryptohawk.security.oidc import OidcTransactionCipher
from cryptohawk.storage.auth import AuthRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.oidc import OidcIdentityRecord, OidcLoginTransactionRecord, OidcRepository


def _key_spec() -> str:
    encoded = base64.urlsafe_b64encode(b'O' * 32).decode().rstrip('=')
    return f'1:{encoded}'


def _repositories(tmp_path: Path):
    inventory = InventoryRepository(f"sqlite:///{tmp_path / 'oidc.db'}")
    cipher = OidcTransactionCipher.from_spec(_key_spec(), active_version=1)
    oidc = OidcRepository(inventory, cipher=cipher)
    oidc.create_schema()
    auth = AuthRepository(inventory)
    return inventory, auth, oidc


def test_login_transaction_is_encrypted_bound_and_single_use(tmp_path: Path) -> None:
    inventory, _auth, oidc = _repositories(tmp_path)
    now = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
    verifier = 'v' * 64
    nonce = 'nonce-value'
    oidc.begin_login(
        state='state-value',
        browser_binding='browser-a',
        code_verifier=verifier,
        nonce=nonce,
        ttl_seconds=600,
        now=now,
    )

    with inventory.SessionLocal() as session:
        row = session.scalar(select(OidcLoginTransactionRecord))
        assert row is not None
        assert verifier.encode() not in bytes(row.payload_ciphertext)
        assert nonce.encode() not in bytes(row.payload_ciphertext)
        assert row.state_hash != 'state-value'
        assert row.browser_binding_hash != 'browser-a'

    with pytest.raises(PermissionError, match='browser binding'):
        oidc.consume_login(
            state='state-value',
            browser_binding='browser-b',
            now=now + timedelta(seconds=1),
        )

    secret = oidc.consume_login(
        state='state-value',
        browser_binding='browser-a',
        now=now + timedelta(seconds=2),
    )
    assert secret.code_verifier == verifier
    assert secret.nonce == nonce
    with pytest.raises(PermissionError, match='already used'):
        oidc.consume_login(
            state='state-value',
            browser_binding='browser-a',
            now=now + timedelta(seconds=3),
        )


def test_expired_login_transaction_is_rejected_and_removed(tmp_path: Path) -> None:
    inventory, _auth, oidc = _repositories(tmp_path)
    now = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
    oidc.begin_login(
        state='expired-state',
        browser_binding='browser',
        code_verifier='v' * 64,
        nonce='nonce',
        ttl_seconds=60,
        now=now,
    )
    with pytest.raises(PermissionError, match='expired'):
        oidc.consume_login(
            state='expired-state',
            browser_binding='browser',
            now=now + timedelta(seconds=61),
        )
    with inventory.SessionLocal() as session:
        assert session.scalar(select(OidcLoginTransactionRecord)) is None


def test_identity_link_requires_preprovisioned_user_and_is_subject_stable(
    tmp_path: Path,
) -> None:
    inventory, auth, oidc = _repositories(tmp_path)
    issued = auth.bootstrap(
        email='owner@example.com',
        display_name='Owner',
        password='correct-horse-battery-staple',
        workspace_name='Acme',
        workspace_slug='acme',
    )
    assert issued.user is not None
    user_id = issued.user.id
    issuer = 'https://idp.example.com'

    with pytest.raises(PermissionError, match='not provisioned'):
        oidc.resolve_identity(
            issuer=issuer,
            subject='unknown-subject',
            email='missing@example.com',
        )

    linked = oidc.resolve_identity(
        issuer=issuer,
        subject='subject-1',
        email='OWNER@example.com',
    )
    assert linked == user_id

    # The stable key is issuer + subject. A later email change must not relink or
    # silently move access to another CryptoHawk account.
    assert (
        oidc.resolve_identity(
            issuer=issuer,
            subject='subject-1',
            email='renamed@example.com',
        )
        == user_id
    )
    with pytest.raises(PermissionError, match='another SSO subject'):
        oidc.resolve_identity(
            issuer=issuer,
            subject='subject-2',
            email='owner@example.com',
        )

    with inventory.SessionLocal() as session:
        identity = session.scalar(select(OidcIdentityRecord))
        assert identity is not None
        assert identity.user_id == user_id
        assert identity.subject == 'subject-1'
        assert identity.issuer == issuer
        assert len(identity.issuer_hash) == 64


def test_completion_code_is_browser_bound_and_single_use(tmp_path: Path) -> None:
    _inventory, auth, oidc = _repositories(tmp_path)
    issued = auth.bootstrap(
        email='owner@example.com',
        display_name='Owner',
        password='correct-horse-battery-staple',
        workspace_name='Acme',
        workspace_slug='acme',
    )
    assert issued.user is not None
    code = oidc.create_completion(
        user_id=issued.user.id,
        browser_binding='browser-a',
        ttl_seconds=120,
    )
    assert code.startswith('choc_')

    with pytest.raises(PermissionError, match='browser binding'):
        oidc.consume_completion(code=code, browser_binding='browser-b')
    assert oidc.consume_completion(code=code, browser_binding='browser-a') == issued.user.id
    with pytest.raises(PermissionError, match='already used'):
        oidc.consume_completion(code=code, browser_binding='browser-a')
