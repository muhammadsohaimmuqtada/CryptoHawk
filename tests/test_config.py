import os
import subprocess
import sys

import pytest

from cryptohawk.config import RuntimeConfigurationError, Settings

_VALID_KEY = "1:a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"


def _production(**overrides) -> Settings:
    values = {
        "environment": "production",
        "database_url": "postgresql+psycopg://cryptohawk:secret@db/cryptohawk",
        "cors_origins": "https://cryptohawk.example.com",
        "allow_legacy_global_api": False,
        "auto_create_schema": False,
        "connector_encryption_keys": _VALID_KEY,
        "connector_encryption_active_version": 1,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_development_defaults_remain_available_for_local_use() -> None:
    settings = Settings(_env_file=None)

    settings.validate_runtime()

    assert settings.environment == "development"
    assert settings.database_url.startswith("sqlite")


def test_known_good_production_configuration_passes() -> None:
    settings = _production()

    settings.validate_runtime()

    assert settings.is_production is True
    assert settings.cors_origin_list == ["https://cryptohawk.example.com"]


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"database_url": "sqlite:///./prod.db"}, "production requires PostgreSQL"),
        ({"auto_create_schema": True}, "AUTO_CREATE_SCHEMA=false"),
        ({"allow_legacy_global_api": True}, "legacy global API"),
        ({"cors_origins": "*"}, "wildcard CORS"),
        ({"cors_origins": "http://cryptohawk.example.com"}, "must use HTTPS"),
        ({"cors_origins": "https://localhost"}, "loopback CORS"),
        ({"cors_origins": "https://app.example.com/path"}, "must not contain a path"),
        ({"connector_encryption_keys": ""}, "requires connector encryption keys"),
        (
            {"connector_encryption_keys": "1:not-a-32-byte-key"},
            "invalid connector encryption key configuration",
        ),
        (
            {"connector_encryption_active_version": 2},
            "active connector encryption key version is unavailable",
        ),
    ],
)
def test_production_rejects_unsafe_runtime_settings(override, expected: str) -> None:
    settings = _production(**override)

    with pytest.raises(RuntimeConfigurationError, match=expected):
        settings.validate_runtime()


def test_production_allows_empty_cors_for_same_origin_deployment() -> None:
    settings = _production(cors_origins="")

    settings.validate_runtime()

    assert settings.cors_origin_list == []


def test_global_settings_fail_closed_during_unsafe_production_import() -> None:
    env = os.environ.copy()
    env.update(
        {
            "CRYPTOHAWK_ENVIRONMENT": "production",
            "CRYPTOHAWK_DATABASE_URL": "sqlite:///./unsafe-production.db",
            "CRYPTOHAWK_CORS_ORIGINS": "https://cryptohawk.example.com",
            "CRYPTOHAWK_ALLOW_LEGACY_GLOBAL_API": "false",
            "CRYPTOHAWK_AUTO_CREATE_SCHEMA": "false",
            "CRYPTOHAWK_CONNECTOR_ENCRYPTION_KEYS": _VALID_KEY,
            "CRYPTOHAWK_CONNECTOR_ENCRYPTION_ACTIVE_VERSION": "1",
        }
    )

    result = subprocess.run(
        [sys.executable, "-c", "import cryptohawk.config"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "unsafe production configuration" in result.stderr
    assert "production requires PostgreSQL" in result.stderr
