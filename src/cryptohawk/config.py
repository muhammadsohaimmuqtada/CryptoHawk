from __future__ import annotations

from urllib.parse import urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict

from cryptohawk.security.secrets import SecretConfigurationError, VersionedAesGcmCipher


class RuntimeConfigurationError(RuntimeError):
    """Raised when a runtime environment violates CryptoHawk production invariants."""


class Settings(BaseSettings):
    app_name: str = "CryptoHawk"
    environment: str = "development"
    database_url: str = "sqlite:///./cryptohawk.db"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    allow_private_targets: bool = False
    allow_legacy_global_api: bool = False
    auto_create_schema: bool = True
    session_hours: int = 12
    principal_requests_per_minute: int = 600
    workspace_requests_per_minute: int = 300
    login_attempts_per_15_minutes: int = 10
    bootstrap_attempts_per_hour: int = 5
    scan_submissions_per_minute: int = 30
    workspace_scan_concurrency: int = 4
    log_level: str = "INFO"
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    otel_service_name: str = "cryptohawk"
    otel_traces_endpoint: str = ""
    otel_export_timeout_seconds: float = 5.0
    connector_encryption_keys: str = ""
    connector_encryption_active_version: int = 1
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    oidc_frontend_url: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_token_endpoint_auth_method: str = "client_secret_basic"
    oidc_require_verified_email: bool = True
    oidc_transaction_ttl_seconds: int = 600
    oidc_completion_ttl_seconds: int = 120
    oidc_http_timeout_seconds: float = 10.0
    oidc_allow_private_provider: bool = False
    repository_allowed_hosts: str = "github.com,gitlab.com"
    repository_fetch_depth: int = 100
    repository_git_timeout_seconds: int = 120
    repository_max_files: int = 20_000
    repository_max_scan_bytes: int = 100_000_000
    repository_max_file_bytes: int = 2_000_000
    container_archive_root: str = ""
    container_platform_os: str = "linux"
    container_platform_arch: str = "amd64"
    container_max_archive_bytes: int = 2_000_000_000
    container_max_layers: int = 128
    container_max_layer_compressed_bytes: int = 256_000_000
    container_max_layer_uncompressed_bytes: int = 1_000_000_000
    container_max_entries: int = 250_000
    container_max_file_bytes: int = 2_000_000
    container_max_scan_bytes: int = 150_000_000

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="CRYPTOHAWK_",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def oidc_scope_list(self) -> list[str]:
        return [scope.strip() for scope in self.oidc_scopes.split() if scope.strip()]

    @property
    def oidc_issuer_normalized(self) -> str:
        return self.oidc_issuer.strip().rstrip("/")

    @property
    def repository_allowed_host_list(self) -> list[str]:
        return [
            host.strip().lower().rstrip(".")
            for host in self.repository_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == "production"

    def _validate_oidc_url(
        self,
        value: str,
        *,
        label: str,
        plain_origin: bool = False,
    ) -> list[str]:
        parsed = urlsplit(value.strip())
        if not parsed.scheme or not parsed.hostname:
            return [f"{label} must be an absolute URL"]
        errors: list[str] = []
        if parsed.username or parsed.password or parsed.fragment:
            errors.append(f"{label} must not contain credentials or a fragment")
        if plain_origin and (parsed.query or parsed.path not in {"", "/"}):
            errors.append(f"{label} must be a plain origin")
        if self.is_production and parsed.scheme.lower() != "https":
            errors.append(f"{label} must use HTTPS in production")
        elif parsed.scheme.lower() not in {"http", "https"}:
            errors.append(f"{label} must use HTTP or HTTPS")
        hostname = parsed.hostname.lower().rstrip(".")
        if self.is_production and hostname in {"localhost", "127.0.0.1", "::1"}:
            errors.append(f"{label} cannot use loopback in production")
        return errors

    def _connector_key_error(self) -> str | None:
        if not self.connector_encryption_keys.strip():
            return "connector encryption keys are required"
        try:
            VersionedAesGcmCipher.from_spec(
                self.connector_encryption_keys,
                active_version=self.connector_encryption_active_version,
            )
        except SecretConfigurationError as exc:
            return f"invalid connector encryption key configuration: {exc}"
        return None

    def _oidc_errors(self) -> list[str]:
        if not self.oidc_enabled:
            return []
        errors: list[str] = []
        issuer = self.oidc_issuer_normalized
        if not issuer:
            errors.append("OIDC issuer is required when OIDC is enabled")
        else:
            if len(issuer) > 1000:
                errors.append("OIDC issuer must be at most 1000 characters")
            errors.extend(self._validate_oidc_url(issuer, label="OIDC issuer"))
        if not self.oidc_client_id.strip():
            errors.append("OIDC client ID is required when OIDC is enabled")
        if not self.oidc_client_secret.strip():
            errors.append("OIDC client secret is required when OIDC is enabled")
        if not self.oidc_redirect_uri.strip():
            errors.append("OIDC redirect URI is required when OIDC is enabled")
        else:
            errors.extend(
                self._validate_oidc_url(
                    self.oidc_redirect_uri,
                    label="OIDC redirect URI",
                )
            )
            redirect = urlsplit(self.oidc_redirect_uri.strip())
            if redirect.query:
                errors.append("OIDC redirect URI must not contain a query")
            if redirect.path != "/api/v1/auth/oidc/callback":
                errors.append("OIDC redirect URI path must be /api/v1/auth/oidc/callback")
        if not self.oidc_frontend_url.strip():
            errors.append("OIDC frontend URL is required when OIDC is enabled")
        else:
            errors.extend(
                self._validate_oidc_url(
                    self.oidc_frontend_url,
                    label="OIDC frontend URL",
                    plain_origin=True,
                )
            )
        if not {"openid", "email"}.issubset(set(self.oidc_scope_list)):
            errors.append("OIDC scopes must include openid and email")
        if self.oidc_token_endpoint_auth_method not in {
            "client_secret_basic",
            "client_secret_post",
        }:
            errors.append(
                "OIDC token endpoint auth method must be client_secret_basic or client_secret_post"
            )
        if not 60 <= self.oidc_transaction_ttl_seconds <= 900:
            errors.append("OIDC transaction TTL must be between 60 and 900 seconds")
        if not 30 <= self.oidc_completion_ttl_seconds <= 300:
            errors.append("OIDC completion TTL must be between 30 and 300 seconds")
        if not 1 <= self.oidc_http_timeout_seconds <= 30:
            errors.append("OIDC HTTP timeout must be between 1 and 30 seconds")
        key_error = self._connector_key_error()
        if key_error:
            errors.append(f"OIDC requires {key_error}")
        return errors

    def validate_runtime(self) -> None:
        """Reject configurations that can silently weaken security or durability."""
        errors = self._oidc_errors()
        if not self.is_production:
            if errors:
                raise RuntimeConfigurationError(
                    f"unsafe runtime configuration: {'; '.join(errors)}"
                )
            return

        database = self.database_url.strip().lower()
        if not database.startswith(("postgresql://", "postgresql+psycopg://")):
            errors.append("production requires PostgreSQL")
        if self.auto_create_schema:
            errors.append("production requires CRYPTOHAWK_AUTO_CREATE_SCHEMA=false")
        if self.allow_legacy_global_api:
            errors.append("legacy global API cannot be enabled in production")

        for origin in self.cors_origin_list:
            if origin == "*":
                errors.append("wildcard CORS origins are forbidden in production")
                continue
            parsed = urlsplit(origin)
            if parsed.scheme.lower() != "https" or not parsed.hostname:
                errors.append(f"production CORS origin must use HTTPS: {origin}")
                continue
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                errors.append(f"production CORS origin is not a plain origin: {origin}")
            if parsed.path not in {"", "/"}:
                errors.append(f"production CORS origin must not contain a path: {origin}")
            hostname = parsed.hostname.lower().rstrip(".")
            if hostname in {"localhost", "127.0.0.1", "::1"}:
                errors.append(f"loopback CORS origin is forbidden in production: {origin}")

        if not self.connector_encryption_keys.strip():
            errors.append("production requires connector encryption keys")
        else:
            try:
                VersionedAesGcmCipher.from_spec(
                    self.connector_encryption_keys,
                    active_version=self.connector_encryption_active_version,
                )
            except SecretConfigurationError as exc:
                errors.append(f"invalid connector encryption key configuration: {exc}")

        if errors:
            joined = "; ".join(errors)
            raise RuntimeConfigurationError(f"unsafe production configuration: {joined}")


settings = Settings()
settings.validate_runtime()
