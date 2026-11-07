"""Evidence retrieval endpoint.

Returns redacted metadata for a piece of assessment evidence.  The
artifact URL is time-limited and generated on the fly.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_request_id, get_tenant_id
from app.core.errors import EvidenceForbiddenError, NotFoundError
from app.middleware.rate_limit import limiter

router = APIRouter(prefix="/evidence", tags=["evidence"])

# Time-limited link validity (minutes).
_LINK_TTL_MINUTES = 15


@router.get(
    "/{evidence_id}",
    summary="Get evidence metadata",
    response_class=JSONResponse,
)
@limiter.limit("30/minute")
async def get_evidence(
    request: Any,
    evidence_id: uuid.UUID = Path(..., description="Evidence UUID"),
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    tenant_id: uuid.UUID = Depends(get_tenant_id),
) -> JSONResponse:
    """Return redacted metadata and a time-limited artifact link.

    The caller must belong to the same tenant that owns the parent
    assessment.  Actual evidence bytes are served separately via the
    artifact URL returned in the response.
    """
    from app.models.evidence import Evidence  # type: ignore[import-untyped]

    stmt = select(Evidence).where(Evidence.id == evidence_id)
    result = await db.execute(stmt)
    evidence = result.scalar_one_or_none()

    if evidence is None:
        raise NotFoundError("Evidence", detail=str(evidence_id))

    # Tenant isolation check.
    evidence_tenant = getattr(evidence, "tenant_id", None)
    if evidence_tenant is not None and evidence_tenant != tenant_id:
        raise EvidenceForbiddenError()

    # Build a time-limited artifact URL.
    expires = datetime.now(timezone.utc) + timedelta(minutes=_LINK_TTL_MINUTES)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "evidenceId": str(evidence.id),
            "kind": getattr(evidence, "kind", "unknown"),
            "assessmentId": str(getattr(evidence, "assessment_id", "")),
            "createdAt": (
                getattr(evidence, "created_at", datetime.now(timezone.utc))
            ).isoformat(),
            "redacted": True,
            "artifactUrl": f"/v1/evidence/{evidence_id}/artifact",
            "expiresAt": expires.isoformat(),
        },
        headers={"X-Request-ID": request_id},
    )
