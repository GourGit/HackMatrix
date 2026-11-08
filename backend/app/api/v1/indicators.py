"""Indicator endpoints — submit and query threat indicators.

Indicators are community- or tenant-contributed observables (URLs,
domains, IPs, hashes, …) enriched with confidence and provenance.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedIdentity, get_current_identity, get_db, get_request_id
from app.core.errors import ErrorCode, EvidenceForbiddenError, NotFoundError, TrustLensError
from app.middleware.rate_limit import limiter
from app.models.assessment import Assessment
from app.models.evidence import Evidence
from app.models.indicator import Indicator
from app.schemas.common import IndicatorType, ReviewStatus, SharingPolicy
from app.schemas.indicator import CreateIndicatorRequest

router = APIRouter(prefix="/indicators", tags=["indicators"])


def normalize_indicator_value(val: str, ind_type: IndicatorType) -> str:
    """Normalize indicator value for deduplication and matching."""
    s = val.strip()
    if ind_type in (IndicatorType.DOMAIN, IndicatorType.EMAIL):
        return s.lower()
    elif ind_type == IndicatorType.URL:
        parsed = urlparse(s)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        return f"{scheme}://{netloc}{parsed.path}" if parsed.netloc else s
    elif ind_type in (IndicatorType.HASH, IndicatorType.CERTIFICATE_FINGERPRINT):
        return s.lower().replace(":", "").replace(" ", "")
    return s


@router.post(
    "",
    summary="Submit a new indicator",
    status_code=status.HTTP_201_CREATED,
    response_class=JSONResponse,
)
@limiter.limit("10/minute")
async def create_indicator(
    payload: CreateIndicatorRequest,
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Submit a threat indicator with evidence links.

    Validates that submitted evidence exists and belongs to the authenticated tenant.
    Normalizes the indicator value and begins in pending_review status.
    """
    tenant_id = identity.tenant_id

    # Validate supporting evidence existence and tenant ownership
    primary_evidence_id = None
    if payload.evidence_ids:
        for ev_id in payload.evidence_ids:
            stmt = select(Evidence).join(Assessment, Evidence.assessment_id == Assessment.id).where(
                Evidence.id == ev_id,
                Assessment.tenant_id == tenant_id,
            )
            res = await db.execute(stmt)
            evidence = res.scalar_one_or_none()
            if not evidence:
                raise TrustLensError(
                    code=ErrorCode.EVIDENCE_FORBIDDEN,
                    message=f"Evidence {ev_id} not found or access denied.",
                    status_code=403,
                )
            if primary_evidence_id is None:
                primary_evidence_id = evidence.id

    norm_val = normalize_indicator_value(payload.value, payload.type)

    indicator_id = uuid.uuid4()
    indicator = Indicator(
        id=indicator_id,
        tenant_id=tenant_id,
        type=payload.type.value,
        value_normalized=norm_val,
        confidence=payload.confidence,
        sharing_policy=payload.sharing_policy.value,
        review_status=ReviewStatus.PENDING_REVIEW.value,
        source_evidence_id=primary_evidence_id,
    )
    db.add(indicator)
    await db.commit()

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
    *,
    value: Optional[str] = Query(None, description="Observable value to search"),
    type: Optional[str] = Query(None, alias="type", description="Indicator type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Return tenant-visible, provenance-labelled indicators.

    Non-tenant private/tenant indicators are strictly hidden.
    Community indicators are visible only if reviewed or owned by the tenant.
    """
    tenant_id = identity.tenant_id

    stmt = select(Indicator).where(
        (Indicator.tenant_id == tenant_id)
        | (
            (Indicator.sharing_policy == SharingPolicy.COMMUNITY.value)
            & (Indicator.review_status == ReviewStatus.REVIEWED.value)
        )
    )

    if value is not None:
        stmt = stmt.where(Indicator.value_normalized == value.strip().lower())
    if type is not None:
        stmt = stmt.where(Indicator.type == type)

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
            "value": ind.value_normalized,
            "type": ind.type,
            "confidence": ind.confidence,
            "sharingPolicy": ind.sharing_policy,
            "reviewStatus": ind.review_status,
            "sourceEvidenceId": str(ind.source_evidence_id) if ind.source_evidence_id else None,
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
