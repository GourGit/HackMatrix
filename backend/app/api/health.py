"""Health-check and readiness endpoints.

These sit outside ``/v1`` so that load-balancers and orchestrators can
probe them without versioned routing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import settings
from app.database import async_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    summary="Liveness probe",
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def health() -> JSONResponse:
    """Return a simple liveness indicator for container orchestration.

    Does not verify downstream dependencies — use ``/ready`` for dependency checks.
    """
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "healthy",
            "service": "trustlens-api",
            "version": "0.1.0",
            "environment": settings.app_env,
        },
    )


@router.get(
    "/ready",
    summary="Readiness probe",
    response_class=JSONResponse,
)
async def readiness() -> JSONResponse:
    """Verify that all required dependencies are reachable and ready to serve traffic.

    Checks:
    - Primary database connection pool
    - Evidence storage path writeability
    - Redis connection (when configured)

    Returns 200 when ready, or 503 if any required dependency is unavailable.
    """
    checks: dict[str, str] = {}
    is_ready = True

    # 1. Database check
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "connected"
    except Exception as exc:
        logger.warning("Readiness probe: database check failed: %s", exc)
        checks["database"] = "unavailable"
        is_ready = False

    # 2. Evidence storage check
    try:
        storage_dir = Path(settings.evidence_storage_path)
        storage_dir.mkdir(parents=True, exist_ok=True)
        test_file = storage_dir / ".ready_check"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        checks["storage"] = "available"
    except Exception as exc:
        logger.warning("Readiness probe: evidence storage check failed: %s", exc)
        checks["storage"] = "unavailable"
        is_ready = False

    # 3. Redis check (when configured)
    if settings.redis_url:
        r = None
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(settings.redis_url, socket_timeout=2.0)
            await r.ping()
            checks["redis"] = "connected"
        except Exception as exc:
            logger.warning("Readiness probe: redis check failed: %s", exc)
            checks["redis"] = "unavailable"
            is_ready = False
        finally:
            if r is not None:
                try:
                    await r.aclose()
                except Exception:
                    pass

    status_code = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if is_ready else "not_ready",
            "checks": checks,
        },
    )
