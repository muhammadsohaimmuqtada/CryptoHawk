from pydantic_settings import BaseSettings, SettingsConfigDict


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

    model_config = SettingsConfigDict(env_file=".env", env_prefix="CRYPTOHAWK_", extra="ignore")

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


settings = Settings()
