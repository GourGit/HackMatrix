"""Authorization scope endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedIdentity, get_current_identity, get_db
from app.models.authorization import AuthorizationScope
from app.schemas.common import ScopeStatus
from app.schemas.scope import CreateScopeRequest, ScopeResponse

router = APIRouter(prefix="/scopes", tags=["authorization-scopes"])


@router.post("", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
async def create_scope(
    payload: CreateScopeRequest,
    db: AsyncSession = Depends(get_db),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> AuthorizationScope:
    """Create a new authorization scope for the authenticated tenant."""
    now = datetime.now(timezone.utc)
    if payload.valid_from is not None:
        valid_from = payload.valid_from if payload.valid_from.tzinfo is not None else payload.valid_from.replace(tzinfo=timezone.utc)
    else:
        valid_from = now

    if payload.valid_until is not None:
        valid_until = payload.valid_until if payload.valid_until.tzinfo is not None else payload.valid_until.replace(tzinfo=timezone.utc)
    else:
        valid_until = valid_from + timedelta(days=30)

    if valid_until <= valid_from:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="valid_until must be after valid_from",
        )

    scope = AuthorizationScope(
        id=uuid.uuid4(),
        tenant_id=identity.tenant_id,
        subject_id=identity.subject_id,
        targets_json=payload.targets,
        allowed_ports_json=payload.allowed_ports,
        valid_from=valid_from,
        valid_until=valid_until,
        attestation=payload.attestation,
        status=ScopeStatus.ACTIVE.value,
    )
    db.add(scope)
    await db.commit()
    await db.refresh(scope)
    return scope


@router.get("/{scope_id}", response_model=ScopeResponse)
async def get_scope(
    scope_id: uuid.UUID = Path(..., description="Scope UUID"),
    db: AsyncSession = Depends(get_db),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> AuthorizationScope:
    """Retrieve an authorization scope, enforcing tenant boundary."""
    stmt = select(AuthorizationScope).where(
        AuthorizationScope.id == scope_id,
        AuthorizationScope.tenant_id == identity.tenant_id,
    )
    res = await db.execute(stmt)
    scope = res.scalar_one_or_none()
    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authorization scope not found or belongs to another tenant.",
        )
    return scope

