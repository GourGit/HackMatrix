"""Finding review endpoint.

Allows an authorized reviewer to record an accepted, disputed, or
false_positive verdict on a specific finding, creating an immutable
audit event with full actor lineage and updating persisted review fields.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Path, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedIdentity, get_current_identity, get_db, get_request_id
from app.core.errors import ErrorCode, NotFoundError, TrustLensError
from app.middleware.rate_limit import limiter
from app.models.assessment import Assessment
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.schemas.common import ReviewDecision
from app.schemas.finding import FindingReviewRequest, FindingReviewResponse

router = APIRouter(prefix="/findings", tags=["findings"])

_VALID_DECISIONS = {
    ReviewDecision.ACCEPTED.value,
    ReviewDecision.DISPUTED.value,
    ReviewDecision.FALSE_POSITIVE.value,
}


@router.post(
    "/{finding_id}/review",
    summary="Record a review decision on a finding",
    status_code=status.HTTP_200_OK,
    response_model=FindingReviewResponse,
)
@limiter.limit("20/minute")
async def review_finding(
    request: Request,
    payload: FindingReviewRequest,
    finding_id: uuid.UUID = Path(..., description="Finding UUID"),
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Record a review decision on the specified finding.

    Persists the updated review status, decision, rationale, reviewer actor ID,
    reviewed timestamp, and an append-only audit event storing previous status
    and review rationale.
    """
    decision = payload.decision.value if hasattr(payload.decision, "value") else str(payload.decision)
    rationale = payload.rationale.strip()

    if decision not in _VALID_DECISIONS:
        raise TrustLensError(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid decision '{decision}'. Must be one of: {', '.join(sorted(_VALID_DECISIONS))}.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # 1. Load finding and join assessment to enforce tenant boundary with row lock on finding
    stmt = (
        select(Finding, Assessment)
        .outerjoin(Assessment, Finding.assessment_id == Assessment.id)
        .where(Finding.id == finding_id)
        .with_for_update(of=Finding)
    )
    result = await db.execute(stmt)
    row = result.first()

    if row is None:
        raise NotFoundError("Finding", detail=str(finding_id))

    finding, assessment = row
    if assessment is None or (assessment.tenant_id != identity.tenant_id and not identity.is_admin):
        raise TrustLensError(
            code="FORBIDDEN",
            message="Access to this finding is not authorized.",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # 2. Capture previous_status BEFORE changing the finding
    previous_status = (
        finding.status.value
        if hasattr(finding.status, "value")
        else str(finding.status)
    )

    review_time = datetime.now(timezone.utc)

    # 3. Persist finding review fields
    finding.status = decision
    finding.decision = decision
    finding.reviewer_id = identity.subject_id
    finding.reviewed_at = review_time
    finding.rationale = rationale

    # 4. Build valid append-only audit event using actual model fields
    audit = AuditEvent(
        id=uuid.uuid4(),
        tenant_id=assessment.tenant_id,
        actor_id=identity.subject_id,
        action="finding.reviewed",
        entity_type="finding",
        entity_id=finding.id,
        metadata_json={
            "previous_status": previous_status,
            "new_status": decision,
            "decision": decision,
            "rationale": rationale,
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
            "decision": decision,
            "reviewedAt": review_time.isoformat(),
            "reviewerId": str(identity.subject_id),
            "reviewedBy": str(identity.subject_id),
            "rationale": rationale,
        },
        headers={"X-Request-ID": request_id},
    )
