"""Authentication and identity dependencies for TrustLens.

Implements an explicit, testable authentication strategy:
- Supports signed development bearer tokens or header-based identity for development/testing (`X-Tenant-ID`, `X-Subject-ID`).
- Rejects anonymous tenant access in production (`settings.is_production`).
- Provides `AuthenticatedIdentity` carrying `tenant_id` and `subject_id`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import settings
from app.core.auth import AuthenticatedIdentity, verify_token
from app.core.errors import ErrorCode, TrustLensError
from app.database import get_db  # noqa: F401


# Default dev identity for test environments
DEV_TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
DEV_SUBJECT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def get_request_id(request: Request) -> str:
    """Return the request correlation ID."""
    existing: str | None = request.headers.get("x-request-id")
    request_id = existing or str(uuid.uuid4())
    request.state.request_id = request_id
    return request_id


def get_current_identity(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_subject_id: Optional[str] = Header(None, alias="X-Subject-ID"),
) -> AuthenticatedIdentity:
    """Resolve and authenticate caller identity.

    In production, a valid Bearer token is strictly required.
    In development / test mode, headers or the fallback dev identity are used.
    """
    # 1. Bearer token check
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        if settings.is_production:
            # In production, verify token authenticity (e.g., JWT / secure token)
            # Dev tokens are strictly disallowed in production.
            if token.startswith("dev-token"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Development tokens are not permitted in production.",
                )
            return verify_token(token)

        # Non-production: accept explicitly permitted dev-token formats:
        # "dev-token" or "dev-token:<tenant_uuid>:<subject_uuid>"
        if token == "dev-token":
            return AuthenticatedIdentity(
                tenant_id=DEV_TENANT_ID,
                subject_id=DEV_SUBJECT_ID,
            )
        elif token.startswith("dev-token:"):
            parts = token.split(":")
            if len(parts) == 3 and parts[0] == "dev-token":
                try:
                    return AuthenticatedIdentity(
                        tenant_id=uuid.UUID(parts[1]),
                        subject_id=uuid.UUID(parts[2]),
                    )
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid development token format.",
                    )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid development token format. Expected dev-token or dev-token:<tenant_id>:<subject_id>.",
            )
        else:
            # If not a dev token, verify as a standard JWT token
            return verify_token(token)

    # 2. Explicit headers (allowed in dev / test)
    if x_tenant_id and not settings.is_production:
        try:
            t_id = uuid.UUID(x_tenant_id)
            s_id = uuid.UUID(x_subject_id) if x_subject_id else DEV_SUBJECT_ID
            return AuthenticatedIdentity(tenant_id=t_id, subject_id=s_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid X-Tenant-ID or X-Subject-ID UUID format.",
            )

    # 3. Development fallback
    if not settings.is_production:
        return AuthenticatedIdentity(
            tenant_id=DEV_TENANT_ID,
            subject_id=DEV_SUBJECT_ID,
        )

    # Strict production reject
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please provide a valid Bearer token.",
    )


def get_tenant_id(identity: AuthenticatedIdentity = Depends(get_current_identity)) -> uuid.UUID:
    """FastAPI dependency returning current authenticated tenant UUID."""
    return identity.tenant_id


def get_subject_id(identity: AuthenticatedIdentity = Depends(get_current_identity)) -> uuid.UUID:
    """FastAPI dependency returning current authenticated subject UUID."""
    return identity.subject_id
