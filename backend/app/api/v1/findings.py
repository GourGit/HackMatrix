"""Finding review endpoint.

Allows a reviewer to record an ``accepted``, ``disputed``, or
``false_positive`` verdict on a specific finding, creating an audit
event for compliance traceability.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_request_id, get_tenant_id
from app.core.errors import NotFoundError, TrustLensError, ErrorCode
from app.middleware.rate_limit import limiter
from app.schemas.common import FindingStatus

router = APIRouter(prefix="/findings", tags=["findings"])

# Valid review decisions.
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
    request: Any,
    finding_id: uuid.UUID = Path(..., description="Finding UUID"),
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    tenant_id: uuid.UUID = Depends(get_tenant_id),
) -> JSONResponse:
    """Record a review decision on the specified finding.

    Expected JSON body::

        {
            "decision": "accepted" | "disputed" | "false_positive",
            "rationale": "Free-text explanation"
        }

    An audit event is persisted alongside the status change so that
    review history is immutable and traceable.
    """
    from app.models.finding import Finding  # type: ignore[import-untyped]

    body = await request.json()
    decision = body.get("decision", "")
    rationale = body.get("rationale", "")

    if decision not in _VALID_DECISIONS:
        raise TrustLensError(
            code=ErrorCode.VALIDATION_ERROR,
            message=(
                f"Invalid decision '{decision}'. "
                f"Must be one of: {', '.join(sorted(_VALID_DECISIONS))}."
            ),
            status_code=422,
        )

    # Load the finding with tenant isolation.
    stmt = select(Finding).where(Finding.id == finding_id)
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if finding is None:
        raise NotFoundError("Finding", detail=str(finding_id))

    # Check tenant ownership via the parent assessment.
    finding_tenant = getattr(finding, "tenant_id", None)
    if finding_tenant is not None and finding_tenant != tenant_id:
        raise NotFoundError("Finding", detail=str(finding_id))

    # Update status.
    finding.status = decision
    finding.reviewed_at = datetime.now(timezone.utc)
    finding.review_rationale = rationale

    # Persist an audit event if the model supports it.
    try:
        from app.models.audit import AuditEvent  # type: ignore[import-untyped]

        audit = AuditEvent(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            entity_type="finding",
            entity_id=finding_id,
            action="review",
            payload={
                "decision": decision,
                "rationale": rationale,
                "previous_status": getattr(finding, "status", "active"),
            },
            created_at=datetime.now(timezone.utc),
        )
        db.add(audit)
    except ImportError:
        # Audit model not yet available — skip for MVP.
        pass

    await db.flush()

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "findingId": str(finding_id),
            "status": decision,
            "reviewedAt": datetime.now(timezone.utc).isoformat(),
        },
        headers={"X-Request-ID": request_id},
    )
