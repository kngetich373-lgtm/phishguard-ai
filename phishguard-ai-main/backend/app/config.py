"""Validated application settings loaded from the project-root .env file."""
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "PhishGuard AI"
    environment: str = Field(
        default="development",
        validation_alias=AliasChoices("APP_ENV", "ENVIRONMENT"),
    )
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    log_level: str = "INFO"

    secret_key: str = Field(default="", repr=False)
    access_token_expire_minutes: int = Field(default=60, gt=0)
    algorithm: str = Field(
        default="HS256",
        validation_alias=AliasChoices("JWT_ALGORITHM", "ALGORITHM"),
    )

    database_url: str = "sqlite+aiosqlite:///./phishguard.db"
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_pool_timeout: int = Field(default=30, ge=1, le=300)
    redis_url: str = ""
    auth_max_failed_attempts: int = Field(default=5, ge=1, le=20)
    auth_lockout_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=30, ge=1, le=180)
    password_reset_expire_minutes: int = Field(default=30, ge=1, le=1440)
    email_verification_expire_hours: int = Field(default=24, ge=1, le=168)
    email_verification_required: bool = False

    frontend_url: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/email/oauth/callback"

    anthropic_api_key: str = ""
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: str = Field(default="", repr=False)
    smtp_from_email: str = ""
    smtp_use_tls: bool = True

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
        hide_input_in_errors=True,
    )

    @property
    def cors_origin_list(self) -> list[str]:
        origins = [origin.strip().rstrip("/") for origin in self.cors_origins.split(",") if origin.strip()]
        frontend_url = self.frontend_url.strip().rstrip("/")
        if frontend_url and frontend_url not in origins:
            origins.append(frontend_url)
        return origins

    @model_validator(mode="after")
    def validate_settings(self):
        self.environment = self.environment.strip().lower()
        self.log_level = self.log_level.strip().upper()
        self.secret_key = self.secret_key.strip()

        if not self.secret_key:
            raise ValueError("SECRET_KEY is required; generate a random secret of at least 32 characters")
        normalized_secret = self.secret_key.lower()
        if len(self.secret_key) < 32 or len(set(self.secret_key)) < 8 or any(
            marker in normalized_secret
            for marker in (
                "change",
                "replace",
                "placeholder",
                "dev-only",
                "your-secret",
                "password",
                "example",
                "sample",
            )
        ):
            raise ValueError("SECRET_KEY must be a non-placeholder value of at least 32 characters")
        if self.environment not in {"development", "dev", "test", "production", "prod"}:
            raise ValueError("APP_ENV must be development, test, or production")
        if self.log_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("LOG_LEVEL must be one of CRITICAL, ERROR, WARNING, INFO, or DEBUG")
        if self.algorithm not in {"HS256", "HS384", "HS512"}:
            raise ValueError("JWT_ALGORITHM must be HS256, HS384, or HS512")
        if bool(self.google_client_id) != bool(self.google_client_secret):
            raise ValueError("Set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or leave both empty")
        if bool(self.smtp_username) != bool(self.smtp_password):
            raise ValueError("Set both SMTP_USERNAME and SMTP_PASSWORD, or leave both empty")
        if self.email_verification_required and not (
            self.smtp_host and self.smtp_from_email
        ):
            raise ValueError(
                "EMAIL_VERIFICATION_REQUIRED needs SMTP_HOST and SMTP_FROM_EMAIL"
            )
        if self.environment in {"production", "prod"} and not self.secret_key:
            raise ValueError("Production requires a configured SECRET_KEY")

        try:
            database_url = make_url(self.database_url)
        except (ArgumentError, TypeError):
            raise ValueError("DATABASE_URL is invalid; expected a supported async SQLite or PostgreSQL URL") from None

        if database_url.drivername not in {"sqlite+aiosqlite", "postgresql+asyncpg"}:
            raise ValueError(
                "DATABASE_URL must use sqlite+aiosqlite or postgresql+asyncpg"
            )
        if database_url.drivername == "postgresql+asyncpg" and not database_url.database:
            raise ValueError("DATABASE_URL for PostgreSQL must include a database name")

        if self.environment in {"production", "prod"}:
            if self.debug:
                raise ValueError("DEBUG must be false in production")
            if self.log_level == "DEBUG":
                raise ValueError("LOG_LEVEL must not be DEBUG in production")
            if database_url.drivername == "sqlite+aiosqlite":
                raise ValueError("Production requires PostgreSQL; SQLite is for development only")
            if not self.redis_url.startswith(("redis://", "rediss://")):
                raise ValueError("Production requires REDIS_URL using redis:// or rediss://")
            if len(self.secret_key) < 32:
                raise ValueError("Production SECRET_KEY must be at least 32 characters")
            origins = self.cors_origin_list
            if not origins or any(
                "*" in origin or "localhost" in origin.lower() or "127.0.0.1" in origin
                for origin in origins
            ):
                raise ValueError("Production CORS_ORIGINS must contain only explicit non-local origins")
            for origin in origins:
                try:
                    parsed_origin = urlsplit(origin)
                    parsed_origin.port
                except ValueError:
                    raise ValueError("Production CORS_ORIGINS contains an invalid origin") from None
                if (
                    parsed_origin.scheme != "https"
                    or not parsed_origin.hostname
                    or parsed_origin.path
                    or parsed_origin.query
                    or parsed_origin.fragment
                    or parsed_origin.username
                    or parsed_origin.password
                ):
                    raise ValueError("Production CORS_ORIGINS must contain HTTPS origins without paths or credentials")

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
