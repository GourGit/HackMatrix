"""Indicator endpoints — submit and query threat indicators.

Indicators are community- or tenant-contributed observables (URLs,
domains, IPs, hashes, emails, certificate fingerprints) enriched with
confidence and provenance.
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedIdentity, get_current_identity, get_db, get_request_id
from app.core.errors import EvidenceForbiddenError
from app.core.indicator_normalizer import normalize_indicator_value
from app.middleware.rate_limit import limiter
from app.models.assessment import Assessment
from app.models.evidence import Evidence
from app.models.indicator import Indicator
from app.schemas.common import IndicatorType, ReviewStatus, SharingPolicy
from app.schemas.indicator import (
    CreateIndicatorRequest,
    CreateIndicatorResponse,
    IndicatorListResponse,
    IndicatorQueryParams,
)

router = APIRouter(prefix="/indicators", tags=["indicators"])


@router.post(
    "",
    summary="Submit a new indicator",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateIndicatorResponse,
)
@limiter.limit("10/minute")
async def create_indicator(
    request: Request,
    payload: CreateIndicatorRequest,
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Submit a threat indicator with evidence links.

    Validates that submitted evidence exists and belongs to the authenticated tenant.
    Normalizes the indicator value and begins in pending_review status.
    Deduplicates existing tenant indicators.
    """
    tenant_id = identity.tenant_id

    # 1. Validate supporting evidence existence and tenant ownership
    ids_to_check: list[uuid.UUID] = []
    if payload.source_evidence_id:
        ids_to_check.append(payload.source_evidence_id)
    if payload.evidence_ids:
        for eid in payload.evidence_ids:
            if eid not in ids_to_check:
                ids_to_check.append(eid)

    primary_evidence_id: uuid.UUID | None = payload.source_evidence_id
    if ids_to_check:
        stmt = (
            select(Evidence, Assessment)
            .outerjoin(Assessment, Evidence.assessment_id == Assessment.id)
            .where(Evidence.id.in_(ids_to_check))
        )
        res = await db.execute(stmt)
        rows = res.all()
        if len(rows) != len(ids_to_check):
            raise EvidenceForbiddenError("One or more evidence IDs not found or access denied.")
        for evidence, assessment in rows:
            if assessment is None or (assessment.tenant_id != tenant_id and not identity.is_admin):
                raise EvidenceForbiddenError(f"Evidence {evidence.id} not found or access denied.")
            if primary_evidence_id is None:
                primary_evidence_id = evidence.id

    # 2. Canonical normalization
    norm_val = normalize_indicator_value(payload.value, payload.type)
    ind_type_str = payload.type.value if hasattr(payload.type, "value") else str(payload.type)
    sharing_policy_str = (
        payload.sharing_policy.value
        if hasattr(payload.sharing_policy, "value")
        else str(payload.sharing_policy)
    )

    # 3. Duplicate handling
    stmt_dup = select(Indicator).where(
        Indicator.tenant_id == tenant_id,
        Indicator.type == ind_type_str,
        Indicator.value_normalized == norm_val,
    )
    res_dup = await db.execute(stmt_dup)
    existing = res_dup.scalar_one_or_none()
    if existing:
        # Deduplicate: update confidence if higher, link evidence if previously absent
        if payload.confidence > existing.confidence:
            existing.confidence = payload.confidence
        if primary_evidence_id and not existing.source_evidence_id:
            existing.source_evidence_id = primary_evidence_id
        await db.commit()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "indicatorId": str(existing.id),
                "status": existing.review_status,
                "isDuplicate": True,
            },
            headers={"X-Request-ID": request_id},
        )

    # 4. Insert new indicator (always starts in pending_review)
    indicator_id = uuid.uuid4()
    indicator = Indicator(
        id=indicator_id,
        tenant_id=tenant_id,
        type=ind_type_str,
        value_normalized=norm_val,
        confidence=payload.confidence,
        sharing_policy=sharing_policy_str,
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
            "isDuplicate": False,
        },
        headers={"X-Request-ID": request_id},
    )


@router.get(
    "",
    summary="Query indicators",
    response_model=IndicatorListResponse,
)
@limiter.limit("30/minute")
async def list_indicators(
    request: Request,
    params: IndicatorQueryParams = Depends(),
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Return tenant-visible, provenance-labelled indicators.

    Non-tenant private/tenant indicators are strictly hidden.
    Community indicators from other tenants are visible only if reviewed.
    """
    tenant_id = identity.tenant_id

    # Base visibility gate
    visibility_filter = (Indicator.tenant_id == tenant_id) | (
        (Indicator.sharing_policy == SharingPolicy.COMMUNITY.value)
        & (Indicator.review_status == ReviewStatus.REVIEWED.value)
    )
    stmt = select(Indicator).where(visibility_filter)

    # Filter by sharing policy
    if params.sharing_policy is not None:
        policy_str = (
            params.sharing_policy.value
            if hasattr(params.sharing_policy, "value")
            else str(params.sharing_policy)
        )
        stmt = stmt.where(Indicator.sharing_policy == policy_str)

    # Filter by type
    if params.type is not None:
        type_str = params.type.value if hasattr(params.type, "value") else str(params.type)
        stmt = stmt.where(Indicator.type == type_str)

    # Filter by value
    if params.value is not None:
        if params.type is not None:
            search_val = normalize_indicator_value(params.value, params.type)
            stmt = stmt.where(Indicator.value_normalized == search_val)
        else:
            candidates = {params.value.strip(), params.value.strip().lower()}
            for itype in IndicatorType:
                try:
                    candidates.add(normalize_indicator_value(params.value, itype))
                except Exception:
                    pass
            stmt = stmt.where(Indicator.value_normalized.in_(list(candidates)))

    # Total count for pagination metadata
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    # Pagination calculation
    limit = params.limit if params.limit is not None else params.page_size
    offset = params.offset if params.offset is not None else (params.page - 1) * limit
    page = (offset // limit) + 1 if limit > 0 else 1

    stmt = stmt.order_by(Indicator.created_at.desc()).offset(offset).limit(limit)
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
            "evidenceIds": [str(ind.source_evidence_id)] if ind.source_evidence_id else [],
            "createdAt": ind.created_at.isoformat(),
            "tenantId": str(ind.tenant_id),
            "source": getattr(ind, "source", None),
        }
        for ind in indicators
    ]

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "items": items,
            "total": total,
            "page": page,
            "pageSize": limit,
        },
        headers={"X-Request-ID": request_id},
    )
