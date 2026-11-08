"""Application configuration loaded from environment variables.

Settings are validated at startup. Backend-only secrets (API keys) are never
prefixed with VITE_ or any frontend-exposed prefix.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_INSECURE_APP_SECRETS = {
    "change-me-to-a-random-secret",
    "secret",
    "changeme",
    "default",
    "password",
    "admin",
    "test",
    "development",
}

_KNOWN_PLACEHOLDER_PREFIXES = (
    "replace-with-",
    "your-",
    "change-me-",
    "placeholder-",
    "example-",
    "test-",
    "my-",
)

_DEFAULT_DATABASE_PATTERNS = [
    ":trustlens@",
    ":trustlens_password@",
    ":password@",
    ":changeme@",
    ":secret@",
    ":admin@",
    ":root@",
    ":example@",
    "user:pass@",
    "trustlens:trustlens@",
    "postgres:postgres@",
    "root:root@",
]


class Settings(BaseSettings):
    """Immutable application settings sourced from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://trustlens:trustlens@localhost:5432/trustlens"

    # ── OpenRouter (backend-only) ─────────────────────────────────────────
    openrouter_api_key: str = ""
    openrouter_model: str = "google/gemini-2.5-flash-preview-05-20"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_timeout: int = 30
    openrouter_max_tokens: int = 2048

    # ── Threat Intelligence Providers (backend-only) ──────────────────────
    google_safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""

    # ── Application ───────────────────────────────────────────────────────
    app_env: str = "development"
    app_debug: bool = True
    app_secret_key: str = "change-me-to-a-random-secret"
    cors_origins: str = "http://localhost:5173"

    # ── Production Auth Configuration ─────────────────────────────────────
    jwt_secret_key: str = ""

    # ── Rate Limits & Shared Storage ──────────────────────────────────────
    rate_limit_per_minute: int = 30
    scan_concurrency_limit: int = 5
    redis_url: str = ""

    # ── Evidence Storage ──────────────────────────────────────────────────
    evidence_storage_path: Path = Path("./evidence_store")
    evidence_retention_days: int = 90

    # ── Safety ────────────────────────────────────────────────────────────
    max_redirect_hops: int = 10
    http_timeout_seconds: int = 15
    max_response_bytes: int = 5_242_880  # 5 MiB
    safe_scan_enabled: bool = False
    safe_scan_allowed_ports: List[int] = [80, 443, 8080, 8443]

    # ── Feature Flags ─────────────────────────────────────────────────────
    crypto_scam_analysis_enabled: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @field_validator("app_secret_key")
    @classmethod
    def _warn_default_secret(cls, v: str) -> str:
        if v == "change-me-to-a-random-secret":
            import warnings

            warnings.warn(
                "APP_SECRET_KEY is set to the default value. "
                "Change it to a cryptographically random string before production.",
                stacklevel=2,
            )
        return v

    @model_validator(mode="after")
    def validate_production_security(self) -> Settings:
        """Enforce strict security requirements when running in production."""
        if self.is_production:
            # 1. Reject default or weak app secret
            secret = (self.app_secret_key or "").strip()
            if (
                not secret
                or secret in _INSECURE_APP_SECRETS
                or any(secret.lower().startswith(p) for p in _KNOWN_PLACEHOLDER_PREFIXES)
                or len(secret) < 32
            ):
                raise ValueError(
                    "Production startup failed: APP_SECRET_KEY is using a default or insecure value. "
                    "In production, APP_SECRET_KEY must be a cryptographically random secret of at least 32 characters."
                )

            # 2. Reject default or example database credentials
            db_url_lower = (self.database_url or "").lower()
            parsed_db = urlsplit(self.database_url or "")
            db_password = parsed_db.password or ""
            if (
                any(pattern in db_url_lower for pattern in _DEFAULT_DATABASE_PATTERNS)
                or (db_password and any(db_password.lower().startswith(p) for p in _KNOWN_PLACEHOLDER_PREFIXES))
                or db_password.lower() in _INSECURE_APP_SECRETS
            ):
                raise ValueError(
                    "Production startup failed: DATABASE_URL contains default or example credentials. "
                    "Configure a dedicated, secure production database password via environment variables."
                )

            # 3. Require production auth configuration
            jwt_secret = (self.jwt_secret_key or "").strip()
            if (
                not jwt_secret
                or jwt_secret in _INSECURE_APP_SECRETS
                or any(jwt_secret.lower().startswith(p) for p in _KNOWN_PLACEHOLDER_PREFIXES)
                or len(jwt_secret) < 32
            ):
                raise ValueError(
                    "Production startup failed: Required production auth configuration (JWT_SECRET_KEY) is missing or insecure. "
                    "Set a secure JWT signing secret of at least 32 characters."
                )

            # 4. Require explicit CORS allowlist (no wildcards)
            if not self.cors_origin_list or any("*" in o for o in self.cors_origin_list):
                raise ValueError(
                    "Production startup failed: CORS_ORIGINS must be an explicit origin allowlist in production "
                    "and cannot contain wildcard '*'."
                )

            # 5. Require Redis URL in production
            redis_url_str = (self.redis_url or "").strip()
            if not redis_url_str:
                raise ValueError(
                    "Production startup failed: REDIS_URL must be configured in production for shared rate limiting."
                )

        return self


settings = Settings()
