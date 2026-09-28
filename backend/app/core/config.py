"""Application configuration settings for SentinelX."""

import os
from typing import Any, List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration management using Pydantic Settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # General Project Info
    PROJECT_NAME: str = "SentinelX SOC & Threat Detection Platform"
    VERSION: str = "0.1.0-alpha"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = Field(default="development")
    DEBUG: bool = Field(default=False)

    # Server Bindings
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # Security & Tokens
    SECRET_KEY: str = Field(
        default="sentinelx-insecure-development-secret-key-change-me-in-production-min-32-chars",
        description="Cryptographic secret key for signing JWT tokens",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    @field_validator("ACCESS_TOKEN_EXPIRE_MINUTES", mode="before")
    @classmethod
    def validate_access_token_expire(cls, v: Any) -> int:
        if isinstance(v, int):
            return v
        try:
            return int(str(v).strip())
        except (ValueError, TypeError):
            return 60

    @field_validator("REFRESH_TOKEN_EXPIRE_DAYS", mode="before")
    @classmethod
    def validate_refresh_token_expire(cls, v: Any) -> int:
        if isinstance(v, int):
            return v
        try:
            return int(str(v).strip())
        except (ValueError, TypeError):
            return 7

    # CORS
    CORS_ORIGINS: Union[str, List[str]] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, tuple)):
            return [str(i).strip() for i in v]
        return ["http://localhost:3000"]

    # Database (PostgreSQL)
    POSTGRES_SERVER: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "sentinelx"
    POSTGRES_PASSWORD: str = "sentinelx_secure_dev_password"
    POSTGRES_DB: str = "sentinelx_db"
    DATABASE_URL: Optional[str] = None
    DATABASE_URL_SYNC: Optional[str] = None

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], info) -> str:
        if v:
            return v
        data = info.data
        user = data.get("POSTGRES_USER", "sentinelx")
        password = data.get("POSTGRES_PASSWORD", "sentinelx_secure_dev_password")
        server = data.get("POSTGRES_SERVER", "postgres")
        port = data.get("POSTGRES_PORT", 5432)
        db = data.get("POSTGRES_DB", "sentinelx_db")
        return f"postgresql+asyncpg://{user}:{password}@{server}:{port}/{db}"

    @field_validator("DATABASE_URL_SYNC", mode="before")
    @classmethod
    def assemble_db_sync_connection(cls, v: Optional[str], info) -> str:
        if v:
            return v
        data = info.data
        user = data.get("POSTGRES_USER", "sentinelx")
        password = data.get("POSTGRES_PASSWORD", "sentinelx_secure_dev_password")
        server = data.get("POSTGRES_SERVER", "postgres")
        port = data.get("POSTGRES_PORT", 5432)
        db = data.get("POSTGRES_DB", "sentinelx_db")
        return f"postgresql://{user}:{password}@{server}:{port}/{db}"

    # Redis (Caching & Pub/Sub)
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    REDIS_URL: Optional[str] = None

    @field_validator("REDIS_URL", mode="before")
    @classmethod
    def assemble_redis_connection(cls, v: Optional[str], info) -> str:
        if v:
            return v
        data = info.data
        host = data.get("REDIS_HOST", "redis")
        port = data.get("REDIS_PORT", 6379)
        db = data.get("REDIS_DB", 0)
        password = data.get("REDIS_PASSWORD") or ""
        if password:
            return f"redis://:{password}@{host}:{port}/{db}"
        return f"redis://{host}:{port}/{db}"

    # Operational Controls
    RATE_LIMIT_PER_MINUTE: int = 120
    AUDIT_LOG_ENABLED: bool = True
    LOG_LEVEL: str = "INFO"

    # External Threat Intel Keys (Optional - gracefully disabled when empty)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    ALIENVAULT_OTX_KEY: Optional[str] = None


# Global singleton settings instance
settings = Settings()
