"""Indicator endpoints — submit and query threat indicators.

Indicators are community- or tenant-contributed observables (URLs,
domains, IPs, hashes, …) enriched with confidence and provenance.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_request_id, get_tenant_id
from app.middleware.rate_limit import limiter
from app.schemas.common import IndicatorType, ReviewStatus, SharingPolicy

router = APIRouter(prefix="/indicators", tags=["indicators"])


@router.post(
    "",
    summary="Submit a new indicator",
    status_code=status.HTTP_201_CREATED,
    response_class=JSONResponse,
)
@limiter.limit("10/minute")
async def create_indicator(
    request: Any,
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    tenant_id: uuid.UUID = Depends(get_tenant_id),
) -> JSONResponse:
    """Submit a threat indicator with evidence links.

    The indicator starts in ``pending_review`` status.  Fields:

    - **value** — the observable (URL, domain, IP, hash, etc.)
    - **type** — one of ``IndicatorType``
    - **confidence** — 0.0‒1.0
    - **sharingPolicy** — private | tenant | community
    - **source** — free-text provenance note
    - **evidenceIds** — list of related evidence UUIDs
    """
    from app.models.indicator import Indicator  # type: ignore[import-untyped]

    body = await request.json()

    indicator_id = uuid.uuid4()
    indicator = Indicator(
        id=indicator_id,
        tenant_id=tenant_id,
        value=body["value"],
        indicator_type=body["type"],
        confidence=body.get("confidence", 0.5),
        sharing_policy=body.get("sharingPolicy", SharingPolicy.PRIVATE.value),
        source=body.get("source", ""),
        review_status=ReviewStatus.PENDING_REVIEW.value,
        evidence_ids=body.get("evidenceIds", []),
        created_at=datetime.now(timezone.utc),
    )
    db.add(indicator)
    await db.flush()

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "indicatorId": str(indicator_id),
            "status": ReviewStatus.PENDING_REVIEW.value,
        },
        headers={"X-Request-ID": request_id},
    )


@router.get(
    "",
    summary="Query indicators",
    response_class=JSONResponse,
)
@limiter.limit("30/minute")
async def list_indicators(
    request: Any,
    *,
    value: Optional[str] = Query(None, description="Observable value to search"),
    type: Optional[str] = Query(None, alias="type", description="Indicator type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    tenant_id: uuid.UUID = Depends(get_tenant_id),
) -> JSONResponse:
    """Return tenant-visible, provenance-labelled indicators.

    Supports filtering by ``value`` and ``type`` query parameters with
    cursor-based pagination.
    """
    from app.models.indicator import Indicator  # type: ignore[import-untyped]

    stmt = select(Indicator).where(
        (Indicator.tenant_id == tenant_id)
        | (Indicator.sharing_policy == SharingPolicy.COMMUNITY.value)
    )

    if value is not None:
        stmt = stmt.where(Indicator.value == value)
    if type is not None:
        stmt = stmt.where(Indicator.indicator_type == type)

    # Total count for pagination metadata.
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    # Apply pagination.
    offset = (page - 1) * page_size
    stmt = stmt.order_by(Indicator.created_at.desc()).offset(offset).limit(page_size)

    result = await db.execute(stmt)
    indicators = result.scalars().all()

    items = [
        {
            "indicatorId": str(ind.id),
            "value": ind.value,
            "type": ind.indicator_type,
            "confidence": ind.confidence,
            "sharingPolicy": ind.sharing_policy,
            "source": getattr(ind, "source", ""),
            "reviewStatus": ind.review_status,
            "createdAt": ind.created_at.isoformat(),
        }
        for ind in indicators
    ]

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "items": items,
            "total": total,
            "page": page,
            "pageSize": page_size,
        },
        headers={"X-Request-ID": request_id},
    )
