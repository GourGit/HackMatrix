"""Tests for deployment configuration, security startup enforcement, and migrations.

Verifies:
1. Alembic migrations generate valid PostgreSQL DDL from clean baseline to head.
2. Production startup strictly fails on default secrets, default DB credentials, missing auth, and wildcard CORS.
3. Production startup passes with securely configured settings.
4. Liveness (/health) and Readiness (/ready) probe endpoints.
5. Production rate limiting resolves shared Redis storage; dev/test resolves in-memory storage.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.config import Settings
from app.main import create_app
from app.middleware.rate_limit import get_storage_uri, limiter


@pytest.fixture(autouse=True)
def disable_rate_limit():
    limiter.enabled = False
    yield
    limiter.enabled = True


# ── 1. Alembic Migration Verification ──────────────────────────────────────────


def test_alembic_migration_sql_generation():
    """Verify that Alembic can generate clean PostgreSQL DDL from scratch to head offline."""
    backend_dir = Path(__file__).parent.parent
    cmd = [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"]

    result = subprocess.run(
        cmd,
        cwd=backend_dir,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, f"Alembic --sql failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"

    sql_output = result.stdout.lower()

    # Verify all 12 core tables are created in the generated DDL
    expected_tables = [
        "authorization_scopes",
        "assessments",
        "agent_runs",
        "evidence",
        "findings",
        "finding_evidence",
        "redirect_hops",
        "certificate_observations",
        "service_observations",
        "cookie_observations",
        "indicators",
        "audit_events",
    ]

    for table in expected_tables:
        assert f"create table {table}" in sql_output or f'create table "{table}"' in sql_output, (
            f"Table {table} not found in Alembic SQL output."
        )

    # Verify migration revision tracking table is present
    assert "alembic_version" in sql_output


# ── 2. Production Security Fail-Safe Startup ───────────────────────────────────


def test_production_startup_rejects_default_secret_key():
    """Startup must fail in production if default app secret is used."""
    with pytest.raises((ValueError, Exception), match="APP_SECRET_KEY is using a default or insecure value"):
        Settings(
            app_env="production",
            app_secret_key="change-me-to-a-random-secret",
            jwt_secret_key="a" * 32,
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
        )


def test_production_startup_rejects_short_secret_key():
    """Startup must fail in production if secret key is shorter than 32 characters."""
    with pytest.raises((ValueError, Exception), match="at least 32 characters"):
        Settings(
            app_env="production",
            app_secret_key="too-short-secret-key",
            jwt_secret_key="a" * 32,
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
        )


def test_production_startup_rejects_default_database_credentials():
    """Startup must fail in production if database credentials contain default/example passwords."""
    for insecure_url in [
        "postgresql+asyncpg://trustlens:trustlens@db:5432/trustlens",
        "postgresql+asyncpg://trustlens:trustlens_password@db:5432/trustlens",
        "postgresql+asyncpg://admin:password@db:5432/trustlens",
        "postgresql+asyncpg://root:root@db:5432/trustlens",
        "postgresql+asyncpg://user:pass@db:5432/trustlens",
    ]:
        with pytest.raises((ValueError, Exception), match="DATABASE_URL contains default or example credentials"):
            Settings(
                app_env="production",
                app_secret_key="a" * 32,
                jwt_secret_key="b" * 32,
                database_url=insecure_url,
                cors_origins="https://trustlens.app",
            )


def test_production_startup_rejects_missing_or_weak_jwt_secret():
    """Startup must fail in production if JWT secret is missing, default, or too short."""
    # Missing / empty
    with pytest.raises((ValueError, Exception), match="JWT_SECRET_KEY.*is missing or insecure"):
        Settings(
            app_env="production",
            app_secret_key="a" * 32,
            jwt_secret_key="",
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
        )

    # Short / default
    with pytest.raises((ValueError, Exception), match="JWT_SECRET_KEY.*is missing or insecure"):
        Settings(
            app_env="production",
            app_secret_key="a" * 32,
            jwt_secret_key="weak-secret",
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
        )


def test_production_startup_rejects_wildcard_cors():
    """Startup must fail in production if CORS origins allow wildcard or is empty."""
    with pytest.raises((ValueError, Exception), match="CORS_ORIGINS must be an explicit origin allowlist"):
        Settings(
            app_env="production",
            app_secret_key="a" * 32,
            jwt_secret_key="b" * 32,
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="*",
        )


def test_production_startup_rejects_missing_redis_url():
    """Startup must fail in production if REDIS_URL is missing or empty."""
    with pytest.raises((ValueError, Exception), match="REDIS_URL must be configured in production"):
        Settings(
            app_env="production",
            app_secret_key="a" * 32,
            jwt_secret_key="b" * 32,
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
            redis_url="",
        )


def test_production_startup_rejects_placeholder_prefixes():
    """Startup must fail in production if secrets or db passwords use placeholder prefixes."""
    # App secret with placeholder prefix
    with pytest.raises((ValueError, Exception), match="APP_SECRET_KEY is using a default or insecure value"):
        Settings(
            app_env="production",
            app_secret_key="replace-with-a-very-long-secret-key-that-is-32-chars",
            jwt_secret_key="b" * 32,
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
            redis_url="redis://redis:6379/0",
        )

    # JWT secret with placeholder prefix
    with pytest.raises((ValueError, Exception), match="JWT_SECRET_KEY.*is missing or insecure"):
        Settings(
            app_env="production",
            app_secret_key="a" * 32,
            jwt_secret_key="change-me-to-a-very-long-secret-key-32-chars",
            database_url="postgresql+asyncpg://admin:complex_password_123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
            redis_url="redis://redis:6379/0",
        )

    # DB password with placeholder prefix
    with pytest.raises((ValueError, Exception), match="DATABASE_URL contains default or example credentials"):
        Settings(
            app_env="production",
            app_secret_key="a" * 32,
            jwt_secret_key="b" * 32,
            database_url="postgresql+asyncpg://admin:placeholder-password-123@db:5432/trustlens",
            cors_origins="https://trustlens.app",
            redis_url="redis://redis:6379/0",
        )


def test_production_startup_succeeds_with_secure_config():
    """Production validation must pass when all production secrets and configurations are secure."""
    settings = Settings(
        app_env="production",
        app_secret_key="a" * 32,
        jwt_secret_key="b" * 32,
        database_url="postgresql+asyncpg://trustlens_prod:9xK8#mP2$vL5@db:5432/trustlens_prod",
        cors_origins="https://trustlens.internal,https://app.trustlens.io",
        redis_url="redis://redis:6379/0",
    )
    # Direct validation invocation succeeds
    settings.validate_production_security()


def test_development_defaults_allowed_in_dev_env():
    """Development environment must allow quick local iteration with dev defaults."""
    settings = Settings(
        app_env="development",
        app_secret_key="change-me-to-a-random-secret",
        jwt_secret_key="",
        database_url="postgresql+asyncpg://trustlens:trustlens@localhost:5432/trustlens",
        cors_origins="http://localhost:5173",
        redis_url="",
    )
    settings.validate_production_security()


# ── 3. Rate Limiting Storage Resolution ────────────────────────────────────────


def test_rate_limiting_storage_resolution():
    """Verify production uses Redis while development/testing uses in-memory storage."""
    # Development -> memory://
    dev_settings = Settings(app_env="development", redis_url="")
    assert get_storage_uri(dev_settings) == "memory://"

    # Testing -> memory://
    test_settings = Settings(app_env="testing", redis_url="")
    assert get_storage_uri(test_settings) == "memory://"

    # Production with redis_url -> redis URI
    prod_redis_settings = Settings(
        app_env="production",
        app_secret_key="a" * 32,
        jwt_secret_key="b" * 32,
        database_url="postgresql+asyncpg://admin:super_secret_1234@db:5432/trustlens",
        cors_origins="https://trustlens.internal",
        redis_url="redis://redis-cluster:6379/0",
    )
    assert get_storage_uri(prod_redis_settings) == "redis://redis-cluster:6379/0"

    # Production missing redis_url fails validation
    with pytest.raises((ValueError, Exception), match="REDIS_URL must be configured in production"):
        Settings(
            app_env="production",
            app_secret_key="a" * 32,
            jwt_secret_key="b" * 32,
            database_url="postgresql+asyncpg://admin:super_secret_1234@db:5432/trustlens",
            cors_origins="https://trustlens.internal",
            redis_url="",
        )

    # get_storage_uri fallback if unvalidated object passed
    mock_prod = Settings.model_construct(app_env="production", redis_url="")
    assert get_storage_uri(mock_prod) == "redis://redis:6379/0"


# ── 4. Health & Readiness Probes ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_liveness_probe_returns_200():
    """GET /health must return 200 OK with service metadata."""
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "trustlens-api"
        assert "version" in data


@pytest.mark.asyncio
async def test_readiness_probe_healthy():
    """GET /ready returns 200 when database and evidence storage are healthy."""
    app = create_app()

    # Mock async session factory to succeed
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=None)
    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_session
    mock_context.__aexit__.return_value = None
    mock_session_factory = MagicMock(return_value=mock_context)

    with patch("app.api.health.async_session_factory", mock_session_factory), \
         patch("app.api.health.settings.redis_url", ""):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/ready")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ready"
            assert data["checks"]["database"] == "connected"
            assert data["checks"]["storage"] == "available"


@pytest.mark.asyncio
async def test_readiness_probe_database_failure():
    """GET /ready returns 503 when the database is unreachable."""
    app = create_app()

    mock_session_factory = MagicMock(side_effect=Exception("Database connection refused"))

    with patch("app.api.health.async_session_factory", mock_session_factory), \
         patch("app.api.health.settings.redis_url", ""):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/ready")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "not_ready"
            assert data["checks"]["database"] == "unavailable"


@pytest.mark.asyncio
async def test_readiness_probe_redis_failure():
    """GET /ready returns 503 when configured Redis is unreachable."""
    app = create_app()

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=None)
    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_session
    mock_context.__aexit__.return_value = None
    mock_session_factory = MagicMock(return_value=mock_context)

    # Mock redis.asyncio to fail ping
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(side_effect=Exception("Redis connection timed out"))
    mock_aioredis = MagicMock()
    mock_aioredis.from_url.return_value = mock_redis

    with patch("app.api.health.async_session_factory", mock_session_factory), \
         patch("app.api.health.settings.redis_url", "redis://localhost:6379/0"), \
         patch.dict("sys.modules", {"redis.asyncio": mock_aioredis}):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/ready")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "not_ready"
            assert data["checks"]["redis"] == "unavailable"
