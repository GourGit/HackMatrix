"""Rate-limiting middleware using slowapi with in-memory storage.

For the MVP this uses a simple in-memory counter backed by
:class:`slowapi.util.get_remote_address` as the key function.  In
production, swap to a Redis-backed limiter.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"],
    storage_uri="memory://",
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
