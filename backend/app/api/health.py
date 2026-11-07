"""Health-check and readiness endpoints.

These sit outside ``/v1`` so that load-balancers and orchestrators can
probe them without versioned routing.
"""

from __future__ import annotations

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.database import async_session_factory

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    summary="Liveness probe",
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def health() -> dict[str, str]:
    """Return a simple liveness indicator.

    This endpoint does **not** verify downstream dependencies — use
    ``/ready`` for full readiness checks.
    """
    return {"status": "healthy", "version": "0.1.0"}


@router.get(
    "/ready",
    summary="Readiness probe",
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def readiness() -> JSONResponse:
    """Verify that the database connection pool is reachable.

    Returns 200 when the application is ready to serve traffic, or 503
    with an error payload when a critical dependency is down.
    """
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ready", "database": "connected"},
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "database": "unavailable"},
        )
