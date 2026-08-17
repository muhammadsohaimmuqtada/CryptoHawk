import asyncio
import base64
import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

import cryptohawk.services.oidc as oidc_module
from cryptohawk.config import Settings
from cryptohawk.services.oidc import OidcProviderMetadata, OidcService
from cryptohawk.storage.oidc import OidcLoginSecret


def _key_spec() -> str:
    encoded = base64.urlsafe_b64encode(b'O' * 32).decode().rstrip('=')
    return f'1:{encoded}'


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        oidc_enabled=True,
        oidc_issuer='https://idp.example.com',
        oidc_client_id='cryptohawk-client',
        oidc_client_secret='client-secret',
        oidc_redirect_uri='https://app.example.com/api/v1/auth/oidc/callback',
        oidc_frontend_url='https://app.example.com',
        connector_encryption_keys=_key_spec(),
    )


class _Repository:
    def __init__(self) -> None:
        self.login = None
        self.resolved = None
        self.completion = None

    def begin_login(self, **kwargs) -> None:
        self.login = kwargs

    def consume_login(self, **_kwargs) -> OidcLoginSecret:
        return OidcLoginSecret(code_verifier='v' * 64, nonce='expected-nonce')

    def resolve_identity(self, **kwargs) -> str:
        self.resolved = kwargs
        return 'user-1'

    def create_completion(self, **kwargs) -> str:
        self.completion = kwargs
        return 'choc_completion-code-value'

    def consume_completion(self, **_kwargs) -> str:
        return 'user-1'


async def _metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer='https://idp.example.com',
        authorization_endpoint='https://idp.example.com/authorize',
        token_endpoint='https://idp.example.com/token',
        jwks_uri='https://idp.example.com/jwks',
        signing_algorithms=('RS256',),
    )


def test_authorization_start_uses_pkce_s256_state_nonce_and_server_storage(
    monkeypatch,
) -> None:
    repository = _Repository()
    service = OidcService(_settings(), repository)  # type: ignore[arg-type]
    monkeypatch.setattr(service, '_discovery', _metadata)

    started = asyncio.run(service.begin_authorization())
    assert repository.login is not None
    query = parse_qs(urlsplit(started.authorization_url).query)
    assert query['response_type'] == ['code']
    assert query['client_id'] == ['cryptohawk-client']
    assert query['redirect_uri'] == ['https://app.example.com/api/v1/auth/oidc/callback']
    assert query['code_challenge_method'] == ['S256']
    assert query['state'] == [repository.login['state']]
    assert query['nonce'] == [repository.login['nonce']]
    assert started.browser_binding == repository.login['browser_binding']

    verifier = repository.login['code_verifier']
    digest = hashlib.sha256(verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).decode().rstrip('=')
    assert query['code_challenge'] == [expected]


def test_id_token_validation_rejects_wrong_audience_and_nonce(monkeypatch) -> None:
    repository = _Repository()
    service = OidcService(_settings(), repository)  # type: ignore[arg-type]
    metadata = asyncio.run(_metadata())
    now = datetime.now(UTC)

    async def fake_jwks(_metadata):
        return object()

    monkeypatch.setattr(service, '_jwks', fake_jwks)

    claims = {
        'iss': metadata.issuer,
        'sub': 'subject-1',
        'aud': 'another-client',
        'exp': int((now + timedelta(minutes=5)).timestamp()),
        'iat': int(now.timestamp()),
        'nonce': 'expected-nonce',
        'email': 'owner@example.com',
        'email_verified': True,
    }
    monkeypatch.setattr(
        oidc_module.jwt,
        'decode',
        lambda *_args, **_kwargs: SimpleNamespace(claims=claims, header={'alg': 'RS256'}),
    )
    with pytest.raises(PermissionError, match='ID token validation'):
        asyncio.run(
            service._validate_id_token(
                'token',
                metadata=metadata,
                nonce='expected-nonce',
                access_token=None,
            )
        )

    claims['aud'] = 'cryptohawk-client'
    claims['nonce'] = 'wrong-nonce'
    with pytest.raises(PermissionError, match='ID token validation'):
        asyncio.run(
            service._validate_id_token(
                'token',
                metadata=metadata,
                nonce='expected-nonce',
                access_token=None,
            )
        )

    claims['nonce'] = 'expected-nonce'
    validated = asyncio.run(
        service._validate_id_token(
            'token',
            metadata=metadata,
            nonce='expected-nonce',
            access_token=None,
        )
    )
    assert validated['sub'] == 'subject-1'


def test_permitted_id_token_algorithms_exclude_symmetric_and_none() -> None:
    assert 'HS256' not in oidc_module._SAFE_ID_TOKEN_ALGORITHMS
    assert 'none' not in oidc_module._SAFE_ID_TOKEN_ALGORITHMS
    assert 'RS256' in oidc_module._SAFE_ID_TOKEN_ALGORITHMS
    assert 'EdDSA' in oidc_module._SAFE_ID_TOKEN_ALGORITHMS
