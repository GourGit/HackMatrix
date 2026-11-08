"""Rate-limiting middleware using slowapi with Redis or in-memory storage.

Uses Redis for shared rate-limit state in production (or when REDIS_URL is provided);
keeps in-memory rate limiting strictly for local development and testing.
"""

from __future__ import annotations

import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import Settings, settings

logger = logging.getLogger(__name__)


def get_storage_uri(cfg: Settings | None = None) -> str:
    """Resolve rate limiter backend URI.

    In production: strictly uses Redis shared storage.
    In development/testing: falls back to in-memory storage unless REDIS_URL is explicitly set.
    """
    active_settings = cfg or settings
    if active_settings.is_production:
        return active_settings.redis_url or "redis://redis:6379/0"
    if active_settings.redis_url:
        return active_settings.redis_url
    return "memory://"


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"],
    storage_uri=get_storage_uri(),
)


def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return the TrustLens error envelope on 429 responses."""
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "code": "RATE_LIMITED",
                "message": "Rate limit exceeded. Please try again later.",
                **({"requestId": request_id} if request_id else {}),
            }
        },
    )


def setup_rate_limit(app: FastAPI) -> None:
    """Attach the rate-limiter and its custom 429 handler to *app*."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)  # type: ignore[arg-type]
