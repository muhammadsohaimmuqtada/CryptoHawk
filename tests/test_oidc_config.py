import pytest

from cryptohawk.config import RuntimeConfigurationError, Settings

_VALID_KEY = "1:a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"


def _oidc(**overrides) -> Settings:
    values = {
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example.com",
        "oidc_client_id": "cryptohawk",
        "oidc_client_secret": "client-secret",
        "oidc_redirect_uri": "https://cryptohawk.example.com/api/v1/auth/oidc/callback",
        "oidc_frontend_url": "https://cryptohawk.example.com",
        "connector_encryption_keys": _VALID_KEY,
        "connector_encryption_active_version": 1,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_oidc_known_good_configuration_passes() -> None:
    settings = _oidc()
    settings.validate_runtime()
    assert settings.oidc_scope_list == ["openid", "profile", "email"]
    assert settings.oidc_issuer_normalized == "https://idp.example.com"


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"oidc_issuer": ""}, "OIDC issuer is required"),
        ({"oidc_client_id": ""}, "OIDC client ID is required"),
        ({"oidc_client_secret": ""}, "OIDC client secret is required"),
        (
            {"oidc_redirect_uri": "https://cryptohawk.example.com/wrong"},
            "redirect URI path",
        ),
        (
            {
                "oidc_redirect_uri": (
                    "https://cryptohawk.example.com/api/v1/auth/oidc/callback?x=1"
                )
            },
            "must not contain a query",
        ),
        (
            {"oidc_frontend_url": "https://cryptohawk.example.com/app"},
            "must be a plain origin",
        ),
        ({"oidc_scopes": "openid profile"}, "must include openid and email"),
        ({"oidc_token_endpoint_auth_method": "none"}, "token endpoint auth method"),
        ({"oidc_transaction_ttl_seconds": 30}, "transaction TTL"),
        ({"oidc_completion_ttl_seconds": 10}, "completion TTL"),
        ({"connector_encryption_keys": ""}, "OIDC requires connector encryption keys"),
    ],
)
def test_oidc_rejects_incomplete_or_unsafe_configuration(override, expected: str) -> None:
    settings = _oidc(**override)
    with pytest.raises(RuntimeConfigurationError, match=expected):
        settings.validate_runtime()


def test_production_oidc_requires_https_and_non_loopback_urls() -> None:
    settings = _oidc(
        environment="production",
        database_url="postgresql+psycopg://cryptohawk:secret@db/cryptohawk",
        cors_origins="https://cryptohawk.example.com",
        auto_create_schema=False,
        oidc_issuer="http://localhost:8080",
        oidc_redirect_uri="http://localhost:8000/api/v1/auth/oidc/callback",
        oidc_frontend_url="http://localhost:5173",
    )
    with pytest.raises(RuntimeConfigurationError) as raised:
        settings.validate_runtime()
    message = str(raised.value)
    assert "OIDC issuer must use HTTPS" in message
    assert "OIDC issuer cannot use loopback" in message
    assert "OIDC redirect URI must use HTTPS" in message
    assert "OIDC frontend URL must use HTTPS" in message


def test_private_oidc_provider_requires_explicit_runtime_opt_in() -> None:
    settings = _oidc(oidc_allow_private_provider=True)
    settings.validate_runtime()
    assert settings.oidc_allow_private_provider is True
