"""Shared FastAPI dependencies re-exported for route handlers.

``get_db``
    Async database session (re-export from ``app.database``).
``get_request_id``
    Extracts or generates a unique request identifier for tracing.
``get_tenant_id``
    Returns the acting tenant — for the MVP this is a hard-coded anonymous
    UUID; real multi-tenancy will be plugged in behind this dependency.
"""

from __future__ import annotations

import uuid

from fastapi import Request

# Re-export so route modules can ``from app.api.deps import get_db``.
from app.database import get_db  # noqa: F401

# Fixed anonymous tenant ID used in MVP mode.
_MVP_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")


def get_request_id(request: Request) -> str:
    """Return the request-level correlation ID.

    If the client sends an ``X-Request-ID`` header the value is reused;
    otherwise a fresh UUID-4 is generated and stored on ``request.state``
    for the rest of the request lifecycle.
    """
    existing: str | None = request.headers.get("x-request-id")
    request_id = existing or str(uuid.uuid4())
    # Stash for downstream middleware / exception handlers.
    request.state.request_id = request_id
    return request_id


def get_tenant_id() -> uuid.UUID:
    """Return the tenant UUID for the current request.

    In the MVP this always returns the anonymous tenant.  Replace with a
    real authentication dependency when tenant isolation is added.
    """
    return _MVP_TENANT_ID
