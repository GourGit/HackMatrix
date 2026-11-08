"""Finding review endpoint.

Allows an authorized reviewer to record an accepted, disputed, or
false_positive verdict on a specific finding, creating an immutable
audit event with full actor lineage.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedIdentity, get_current_identity, get_db, get_request_id
from app.core.errors import ErrorCode, NotFoundError, TrustLensError
from app.middleware.rate_limit import limiter
from app.models.assessment import Assessment
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.schemas.common import FindingStatus
from app.schemas.finding import FindingReviewRequest

router = APIRouter(prefix="/findings", tags=["findings"])

_VALID_DECISIONS = {
    FindingStatus.ACCEPTED.value,
    FindingStatus.DISPUTED.value,
    FindingStatus.FALSE_POSITIVE.value,
}


@router.post(
    "/{finding_id}/review",
    summary="Record a review decision on a finding",
    status_code=status.HTTP_200_OK,
    response_class=JSONResponse,
)
@limiter.limit("20/minute")
async def review_finding(
    payload: FindingReviewRequest,
    finding_id: uuid.UUID = Path(..., description="Finding UUID"),
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Record a review decision on the specified finding.

    Persists the updated review status, reviewer actor ID, and an append-only
    audit event storing previous status and review rationale.
    """
    decision = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
    rationale = payload.rationale or ""

    if decision not in _VALID_DECISIONS:
        raise TrustLensError(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid decision '{decision}'. Must be one of: {', '.join(sorted(_VALID_DECISIONS))}.",
            status_code=422,
        )

    # Load finding and join assessment to enforce tenant boundary
    stmt = (
        select(Finding)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .where(
            Finding.id == finding_id,
            Assessment.tenant_id == identity.tenant_id,
        )
    )
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if finding is None:
        raise NotFoundError("Finding", detail=str(finding_id))

    prior_status = finding.status

    # Update status
    finding.status = decision
    review_time = datetime.now(timezone.utc)

    # Append-only audit trail
    audit = AuditEvent(
        id=uuid.uuid4(),
        tenant_id=identity.tenant_id,
        actor_id=identity.subject_id,
        action="finding.reviewed",
        entity_type="finding",
        entity_id=finding_id,
        metadata_json={
            "decision": decision,
            "rationale": rationale,
            "previous_status": prior_status,
        },
        occurred_at=review_time,
    )
    db.add(audit)
    await db.commit()

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "findingId": str(finding_id),
            "status": decision,
            "reviewedAt": review_time.isoformat(),
            "reviewerId": str(identity.subject_id),
        },
        headers={"X-Request-ID": request_id},
    )
