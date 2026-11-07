"""CORS middleware configuration.

Applies a strict origin allowlist from ``settings.cors_origin_list`` so
that only explicitly trusted frontends can make cross-origin requests.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings


def setup_cors(app: FastAPI) -> None:
    """Register the CORS middleware on *app* using the configured origin list."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
        max_age=600,
    )
