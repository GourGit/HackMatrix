"""Authentication endpoints — anonymous visitor session initialization."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import create_visitor_token
from app.middleware.rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


def _to_camel(name: str) -> str:
    """Convert snake_case to camelCase for API serialization."""
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


class AnonymousSessionResponse(BaseModel):
    """Response payload returned when an anonymous visitor session is created."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    token: str = Field(
        ...,
        description="Cryptographically signed JWT Bearer token.",
    )
    access_token: str = Field(
        ...,
        description="Cryptographically signed JWT Bearer token (OAuth2 accessToken alias).",
    )
    token_type: str = Field(
        "Bearer",
        description="Token type — always 'Bearer'.",
    )
    expires_at: datetime = Field(
        ...,
        description="ISO-8601 UTC expiration timestamp.",
    )
    expires_in: int = Field(
        ...,
        description="Session duration in seconds.",
    )
    tenant_id: uuid.UUID = Field(
        ...,
        description="Unique, isolated tenant UUID assigned to this session.",
    )
    subject_id: uuid.UUID = Field(
        ...,
        description="Unique visitor subject UUID assigned to this session.",
    )


@router.post(
    "/anonymous",
    summary="Create anonymous visitor session",
    status_code=status.HTTP_201_CREATED,
    response_model=AnonymousSessionResponse,
)
@limiter.limit("30/minute")
async def create_anonymous_session(request: Request) -> AnonymousSessionResponse:
    """Initialize a secure anonymous visitor session.

    Generates isolated tenant and subject UUIDs and issues a signed JWT
    authorizing subsequent passive assessments.
    """
    tenant_id = uuid.uuid4()
    subject_id = uuid.uuid4()
    token, expires_at, expires_in = create_visitor_token(tenant_id, subject_id)

    return AnonymousSessionResponse(
        token=token,
        access_token=token,
        token_type="Bearer",
        expires_at=expires_at,
        expires_in=expires_in,
        tenant_id=tenant_id,
        subject_id=subject_id,
    )
