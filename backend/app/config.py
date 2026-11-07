"""Application configuration loaded from environment variables.

Settings are validated at startup. Backend-only secrets (API keys) are never
prefixed with VITE_ or any frontend-exposed prefix.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # ── Rate Limits ───────────────────────────────────────────────────────
    rate_limit_per_minute: int = 30
    scan_concurrency_limit: int = 5

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
        return self.app_env == "production"

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


settings = Settings()

