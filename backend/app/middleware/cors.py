"""CORS middleware configuration.

Applies a strict, explicit origin allowlist from ``settings.cors_origin_list`` so
that only explicitly trusted frontends can make cross-origin requests.
Wildcards are disallowed in production.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings


def setup_cors(app: FastAPI) -> None:
    """Register the CORS middleware on *app* using the configured origin allowlist."""
    origins = settings.cors_origin_list

    # Ensure explicit allowlist: wildcard is disallowed in production
    if settings.is_production:
        if not origins or any(o == "*" for o in origins):
            raise ValueError(
                "In production, CORS_ORIGINS must be an explicit allowlist of origins and cannot contain '*'."
            )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if origins else ["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Tenant-ID", "X-Subject-ID"],
        max_age=600,
    )
