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
    connector_encryption_keys: str = ""
    connector_encryption_active_version: int = 1

    model_config = SettingsConfigDict(env_file=".env", env_prefix="CRYPTOHAWK_", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
