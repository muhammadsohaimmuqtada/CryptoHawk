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
    def repository_allowed_host_list(self) -> list[str]:
        return [
            host.strip().lower().rstrip(".")
            for host in self.repository_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == "production"

    def validate_runtime(self) -> None:
        """Reject production configurations that can silently weaken security or durability."""
        if not self.is_production:
            return

        errors: list[str] = []
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
