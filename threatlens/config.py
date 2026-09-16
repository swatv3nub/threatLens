from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiClient(BaseModel):
    role: Literal["viewer", "analyst", "admin"] = "viewer"
    tenant_id: str | None = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_env: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    api_auth_enabled: bool = False
    api_key: SecretStr | None = None
    api_clients: dict[str, ApiClient] = Field(default_factory=dict)

    llm_provider: Literal["mock", "openai"] = "mock"
    llm_model: str = "gpt-4o-mini"
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"

    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    database_url: str = "sqlite:///./threatlens.db"
    database_auto_create: bool = True

    max_tool_calls: int = 10
    max_tool_retries: int = 3
    tool_timeout_seconds: float = 10.0
    rate_limit_per_minute: int = 120
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    redis_url: str | None = None

    mock_enrichment: bool = True

    max_payload_bytes: int = Field(default=1_048_576, ge=1024)

    otel_enabled: bool = False
    otel_service_name: str = "threatlens"
    otel_exporter_otlp_endpoint: str | None = None
    otel_exporter_otlp_headers: str | None = None

    retention_days: int = Field(default=90, ge=1)
    backup_dir: str = "backups"

    allowed_outbound_hosts: tuple[str, ...] = (
        "www.virustotal.com",
        "api.abuseipdb.com",
        "api.openai.com",
    )

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @model_validator(mode="after")
    def validate_production_safety(self) -> Settings:
        if not self.is_production:
            return self
        if self.llm_provider == "mock":
            raise ValueError("LLM_PROVIDER=mock is not allowed in production")
        if self.mock_enrichment:
            raise ValueError("MOCK_ENRICHMENT=true is not allowed in production")
        if (
            not self.api_auth_enabled
            or (
                self.api_key is None
                and not self.api_clients
            )
            or (
                self.api_key is not None
                and not self.api_key.get_secret_value().strip()
                and not self.api_clients
            )
        ):
            raise ValueError("production requires API_AUTH_ENABLED=true and API_KEY or API_CLIENTS")
        if (
            self.llm_provider == "openai"
            and (self.openai_api_key is None or not self.openai_api_key.strip())
        ):
            raise ValueError("production OpenAI configuration requires OPENAI_API_KEY")
        if (
            self.virustotal_api_key is None
            or not self.virustotal_api_key.strip()
            or self.abuseipdb_api_key is None
            or not self.abuseipdb_api_key.strip()
        ):
            raise ValueError(
                "production enrichment requires VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY"
            )
        if self.rate_limit_backend != "redis" or not self.redis_url:
            raise ValueError("production requires RATE_LIMIT_BACKEND=redis and REDIS_URL")
        if self.database_auto_create:
            raise ValueError("production requires DATABASE_AUTO_CREATE=false; run Alembic migrations")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
