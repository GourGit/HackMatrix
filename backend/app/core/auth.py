"""Authentication utilities for JWT issuance and verification.

Supports production JWT signing and verification (HS256) for anonymous visitor
sessions and registered principals, enforcing issuer, audience, expiration,
and tenant identity claims.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from fastapi import HTTPException, status

from app.config import settings


@dataclass(frozen=True)
class AuthenticatedIdentity:
    """Authenticated principal context."""

    tenant_id: uuid.UUID
    subject_id: uuid.UUID
    is_admin: bool = False


def _get_signing_secret() -> str:
    """Get the active JWT signing key, with safe development fallback."""
    secret = (settings.jwt_secret_key or "").strip()
    if secret:
        return secret
    if not settings.is_production:
        return settings.app_secret_key or "insecure-dev-jwt-key-not-for-production"
    raise ValueError("JWT_SECRET_KEY is required in production.")


def create_visitor_token(
    tenant_id: uuid.UUID,
    subject_id: uuid.UUID,
    lifetime_seconds: int | None = None,
) -> tuple[str, datetime, int]:
    """Issue a cryptographically signed JWT for an anonymous visitor session.

    Args:
        tenant_id: Generated tenant UUID.
        subject_id: Generated visitor subject UUID.
        lifetime_seconds: Optional custom session duration (defaults to settings).

    Returns:
        Tuple of (encoded_jwt_str, expiry_datetime, lifetime_seconds).
    """
    secret = _get_signing_secret()
    lifetime = lifetime_seconds or settings.visitor_session_lifetime_seconds
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=lifetime)

    claims: Dict[str, Any] = {
        "sub": str(subject_id),
        "tenant_id": str(tenant_id),
        "type": "visitor",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    token = jwt.encode(claims, secret, algorithm=settings.jwt_algorithm)
    return token, expires_at, lifetime


def verify_token(token: str) -> AuthenticatedIdentity:
    """Verify a signed JWT and extract the authenticated principal identity.

    Args:
        token: Raw JWT string without 'Bearer ' prefix.

    Returns:
        AuthenticatedIdentity with verified tenant_id and subject_id.

    Raises:
        HTTPException(401): If the token is invalid, expired, malformed,
            or contains invalid identity claims.
    """
    if not token or not isinstance(token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed token.",
        )

    secret = _get_signing_secret()

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": ["exp", "iat", "sub", "tenant_id", "type", "iss", "aud"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please refresh your session.",
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer.",
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience.",
        )
    except (jwt.InvalidSignatureError, jwt.DecodeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature.",
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        )

    token_type = payload.get("type")
    if token_type not in ("visitor", "access"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported token type: {token_type}",
        )

    try:
        tenant_id = uuid.UUID(str(payload.get("tenant_id")))
        subject_id = uuid.UUID(str(payload.get("sub")))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token identity claims must be valid UUIDs.",
        )

    return AuthenticatedIdentity(
        tenant_id=tenant_id,
        subject_id=subject_id,
        is_admin=False,
    )

