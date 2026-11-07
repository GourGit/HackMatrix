"""TrustLens API — FastAPI application factory.

Creates the ASGI application with:

* CORS, security headers, and rate-limiting middleware
* Versioned API router (``/v1``)
* Health / readiness probes
* Structured error handling (no stack traces exposed)
* Database engine lifecycle management
* Structured logging via ``structlog``
"""

from __future__ import annotations

import logging
import sys
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.config import settings
from app.core.errors import ErrorCode, TrustLensError
from app.database import engine

# ── Structured logging configuration ─────────────────────────────────────

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

# Set root log level based on debug flag.
logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=logging.DEBUG if settings.app_debug else logging.INFO,
)

logger: structlog.stdlib.BoundLogger = structlog.get_logger("trustlens")


# ── Application lifecycle ────────────────────────────────────────────────

@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage startup / shutdown tasks for the application.

    Startup: verify the database engine can connect.
    Shutdown: dispose of the engine's connection pool.
    """
    logger.info("startup", env=settings.app_env, debug=settings.app_debug)
    yield
    await engine.dispose()
    logger.info("shutdown")


# ── Application factory ──────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Build and return the fully-configured FastAPI application."""

    app = FastAPI(
        title="TrustLens API",
        version="0.1.0",
        description="AI-powered web threat detection and digital trust intelligence.",
        docs_url="/docs" if settings.app_debug else None,
        redoc_url="/redoc" if settings.app_debug else None,
        lifespan=_lifespan,
    )

    # ── Middleware (order matters — outermost runs first) ─────────────
    from app.middleware.cors import setup_cors
    from app.middleware.rate_limit import setup_rate_limit
    from app.middleware.security_headers import SecurityHeadersMiddleware

    # Security headers wrap every response.
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS must be applied after security headers so it can set its
    # own Access-Control-* headers.
    setup_cors(app)

    # Rate limiting.
    setup_rate_limit(app)

    # ── Routers ──────────────────────────────────────────────────────
    from app.api.health import router as health_router
    from app.api.v1.router import v1_router

    app.include_router(health_router)
    app.include_router(v1_router)

    # ── Exception handlers ───────────────────────────────────────────
    _register_exception_handlers(app)

    return app


# ── Error handlers ───────────────────────────────────────────────────────

def _get_request_id(request: Request) -> str:
    """Retrieve the request ID stashed by the dependency, or generate one."""
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


def _register_exception_handlers(app: FastAPI) -> None:
    """Attach application and fallback exception handlers."""

    @app.exception_handler(TrustLensError)
    async def _trustlens_error_handler(
        request: Request, exc: TrustLensError
    ) -> JSONResponse:
        """Map ``TrustLensError`` subclasses to the API error envelope."""
        request_id = _get_request_id(request)
        logger.warning(
            "app_error",
            code=exc.code,
            message=exc.message,
            status=exc.status_code,
            request_id=request_id,
            detail=exc.detail,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_response(request_id),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Translate Pydantic / FastAPI validation errors to the error envelope."""
        request_id = _get_request_id(request)
        logger.warning(
            "validation_error",
            errors=exc.errors(),
            request_id=request_id,
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": ErrorCode.VALIDATION_ERROR,
                    "message": "Request validation failed.",
                    "requestId": request_id,
                }
            },
        )

    @app.exception_handler(Exception)
    async def _generic_error_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Catch-all handler — never expose stack traces to the client."""
        request_id = _get_request_id(request)
        logger.error(
            "unhandled_exception",
            exc_info=exc,
            request_id=request_id,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR,
                    "message": "An internal error occurred.",
                    "requestId": request_id,
                }
            },
        )


# ── Module-level application instance for ASGI servers ───────────────────
app = create_app()
