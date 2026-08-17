from __future__ import annotations

import asyncio
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oidc.core import CodeIDToken
from joserfc import jwt
from joserfc.jwk import KeySet

from cryptohawk.config import Settings
from cryptohawk.security.network import resolve_target
from cryptohawk.storage.oidc import OidcRepository

_SAFE_ID_TOKEN_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class OidcConfigurationError(RuntimeError):
    pass


class OidcProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class OidcProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    signing_algorithms: tuple[str, ...]


@dataclass(frozen=True)
class OidcAuthorizationStart:
    authorization_url: str


class OidcService:
    def __init__(self, settings: Settings, repository: OidcRepository) -> None:
        self.settings = settings
        self.repository = repository

    @property
    def enabled(self) -> bool:
        return self.settings.oidc_enabled

    async def begin_authorization(self, *, browser_binding: str) -> OidcAuthorizationStart:
        self._require_enabled()
        if not browser_binding:
            raise ValueError("OIDC browser binding is required")
        metadata = await self._discovery()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)

        async with AsyncOAuth2Client(
            client_id=self.settings.oidc_client_id,
            client_secret=self.settings.oidc_client_secret,
            token_endpoint_auth_method=self.settings.oidc_token_endpoint_auth_method,
            redirect_uri=self.settings.oidc_redirect_uri,
            scope=self.settings.oidc_scope_list,
            code_challenge_method="S256",
            response_type="code",
            timeout=self.settings.oidc_http_timeout_seconds,
            follow_redirects=False,
        ) as client:
            authorization_url, _ = client.create_authorization_url(
                metadata.authorization_endpoint,
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
            )

        self.repository.begin_login(
            state=state,
            browser_binding=browser_binding,
            code_verifier=code_verifier,
            nonce=nonce,
            ttl_seconds=self.settings.oidc_transaction_ttl_seconds,
        )
        return OidcAuthorizationStart(authorization_url=authorization_url)

    async def complete_authorization(
        self,
        *,
        code: str,
        state: str,
        browser_binding: str,
    ) -> str:
        self._require_enabled()
        if not code or not state or not browser_binding:
            raise PermissionError("OIDC callback is incomplete")

        transaction = self.repository.consume_login(
            state=state,
            browser_binding=browser_binding,
        )
        metadata = await self._discovery()

        try:
            async with AsyncOAuth2Client(
                client_id=self.settings.oidc_client_id,
                client_secret=self.settings.oidc_client_secret,
                token_endpoint_auth_method=self.settings.oidc_token_endpoint_auth_method,
                redirect_uri=self.settings.oidc_redirect_uri,
                scope=self.settings.oidc_scope_list,
                code_challenge_method="S256",
                timeout=self.settings.oidc_http_timeout_seconds,
                follow_redirects=False,
            ) as client:
                token = await client.fetch_token(
                    metadata.token_endpoint,
                    code=code,
                    code_verifier=transaction.code_verifier,
                    redirect_uri=self.settings.oidc_redirect_uri,
                )
        except Exception as exc:
            raise OidcProviderError("OIDC token exchange failed") from exc

        id_token = token.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise PermissionError("OIDC provider did not return an ID token")
        claims = await self._validate_id_token(
            id_token,
            metadata=metadata,
            nonce=transaction.nonce,
            access_token=token.get("access_token"),
        )
        subject = claims.get("sub")
        email = claims.get("email")
        if not isinstance(subject, str) or not subject or len(subject) > 255:
            raise PermissionError("OIDC subject is invalid")
        if not isinstance(email, str) or not _EMAIL.fullmatch(email.strip().lower()):
            raise PermissionError("OIDC email claim is missing or invalid")
        if self.settings.oidc_require_verified_email and claims.get("email_verified") is not True:
            raise PermissionError("OIDC email is not verified")

        user_id = self.repository.resolve_identity(
            issuer=metadata.issuer,
            subject=subject,
            email=email,
        )
        return self.repository.create_completion(
            user_id=user_id,
            browser_binding=browser_binding,
            ttl_seconds=self.settings.oidc_completion_ttl_seconds,
        )

    def consume_completion(self, *, code: str, browser_binding: str) -> str:
        self._require_enabled()
        if not code or not browser_binding:
            raise PermissionError("OIDC completion is incomplete")
        return self.repository.consume_completion(
            code=code,
            browser_binding=browser_binding,
        )

    async def _discovery(self) -> OidcProviderMetadata:
        issuer = self.settings.oidc_issuer_normalized
        discovery_url = f"{issuer}/.well-known/openid-configuration"
        await self._validate_remote_url(discovery_url, "OIDC discovery endpoint")
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.oidc_http_timeout_seconds,
                follow_redirects=False,
                headers={"Accept": "application/json"},
            ) as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            raise OidcProviderError("OIDC discovery failed") from exc

        if not isinstance(payload, dict) or payload.get("issuer") != issuer:
            raise OidcProviderError("OIDC discovery issuer mismatch")

        authorization_endpoint = payload.get("authorization_endpoint")
        token_endpoint = payload.get("token_endpoint")
        jwks_uri = payload.get("jwks_uri")
        if not all(
            isinstance(value, str) and value
            for value in (authorization_endpoint, token_endpoint, jwks_uri)
        ):
            raise OidcProviderError("OIDC discovery metadata is incomplete")

        for endpoint, label in (
            (authorization_endpoint, "OIDC authorization endpoint"),
            (token_endpoint, "OIDC token endpoint"),
            (jwks_uri, "OIDC JWKS endpoint"),
        ):
            await self._validate_remote_url(endpoint, label)

        methods = payload.get("token_endpoint_auth_methods_supported")
        configured_method = self.settings.oidc_token_endpoint_auth_method
        if isinstance(methods, list) and configured_method not in methods:
            raise OidcProviderError(
                "configured OIDC token authentication method is unsupported"
            )
        response_types = payload.get("response_types_supported")
        if isinstance(response_types, list) and "code" not in response_types:
            raise OidcProviderError("OIDC provider does not support Authorization Code flow")
        pkce_methods = payload.get("code_challenge_methods_supported")
        if isinstance(pkce_methods, list) and "S256" not in pkce_methods:
            raise OidcProviderError("OIDC provider does not advertise PKCE S256")

        advertised_algorithms = payload.get("id_token_signing_alg_values_supported")
        if not isinstance(advertised_algorithms, list):
            raise OidcProviderError("OIDC provider did not advertise ID-token algorithms")
        signing_algorithms = tuple(
            algorithm
            for algorithm in advertised_algorithms
            if isinstance(algorithm, str) and algorithm in _SAFE_ID_TOKEN_ALGORITHMS
        )
        if not signing_algorithms:
            raise OidcProviderError("OIDC provider has no permitted ID-token signing algorithm")

        return OidcProviderMetadata(
            issuer=issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            jwks_uri=jwks_uri,
            signing_algorithms=signing_algorithms,
        )

    async def _jwks(self, metadata: OidcProviderMetadata) -> KeySet:
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.oidc_http_timeout_seconds,
                follow_redirects=False,
                headers={"Accept": "application/json"},
            ) as client:
                response = await client.get(metadata.jwks_uri)
                response.raise_for_status()
                payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError("JWKS document must be an object")
            return KeySet.import_key_set(payload)
        except Exception as exc:
            raise OidcProviderError("OIDC JWKS retrieval failed") from exc

    async def _validate_id_token(
        self,
        id_token: str,
        *,
        metadata: OidcProviderMetadata,
        nonce: str,
        access_token: object,
    ) -> CodeIDToken:
        key_set = await self._jwks(metadata)
        client_id = self.settings.oidc_client_id

        try:
            decoded = jwt.decode(
                id_token,
                key=key_set,
                algorithms=list(metadata.signing_algorithms),
            )
            claims = CodeIDToken(
                decoded.claims,
                decoded.header,
                options={
                    "iss": {"essential": True, "value": metadata.issuer},
                    "sub": {"essential": True},
                    "aud": {"essential": True, "value": client_id},
                    "exp": {"essential": True},
                    "iat": {"essential": True},
                    "nonce": {"essential": True},
                },
                params={
                    "nonce": nonce,
                    "client_id": client_id,
                    "access_token": access_token,
                },
            )
            claims.validate(leeway=60)
            authorized_party = claims.get("azp")
            if authorized_party is not None and authorized_party != client_id:
                raise PermissionError("OIDC authorized party mismatch")
            return claims
        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError("OIDC ID token validation failed") from exc

    async def _validate_remote_url(self, value: str, label: str) -> None:
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise OidcProviderError(f"{label} is invalid")
        if self.settings.is_production and parsed.scheme.lower() != "https":
            raise OidcProviderError(f"{label} must use HTTPS")
        if parsed.scheme.lower() not in {"http", "https"}:
            raise OidcProviderError(f"{label} must use HTTP or HTTPS")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        try:
            await asyncio.to_thread(
                resolve_target,
                parsed.hostname,
                port,
                allow_private=self.settings.oidc_allow_private_provider,
            )
        except Exception as exc:
            raise OidcProviderError(f"{label} failed outbound-target validation") from exc

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise OidcConfigurationError("OIDC is disabled")


__all__ = [
    "OidcAuthorizationStart",
    "OidcConfigurationError",
    "OidcProviderError",
    "OidcProviderMetadata",
    "OidcService",
]
