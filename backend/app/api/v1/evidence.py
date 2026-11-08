"""Evidence retrieval and artifact download endpoints.

Returns redacted metadata and serves authorized, redacted evidence artifacts.
"""

from __future__ import annotations

import io
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Path, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedIdentity, get_current_identity, get_db, get_request_id
from app.core.errors import EvidenceForbiddenError, NotFoundError
from app.core.evidence_store import EvidenceStore
from app.middleware.rate_limit import limiter
from app.models.assessment import Assessment
from app.models.evidence import Evidence

router = APIRouter(prefix="/evidence", tags=["evidence"])

_LINK_TTL_MINUTES = 15


@router.get(
    "/{evidence_id}",
    summary="Get evidence metadata",
    response_class=JSONResponse,
)
@limiter.limit("30/minute")
async def get_evidence(
    request: Request,
    evidence_id: uuid.UUID = Path(..., description="Evidence UUID"),
    *,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Return redacted metadata and an authorized artifact link.

    Caller must belong to the tenant owning the parent assessment.
    """
    stmt = (
        select(Evidence, Assessment)
        .outerjoin(Assessment, Evidence.assessment_id == Assessment.id)
        .where(Evidence.id == evidence_id)
    )
    result = await db.execute(stmt)
    row = result.first()

    if row is None:
        raise NotFoundError("Evidence", detail=str(evidence_id))

    evidence, assessment = row
    if assessment is None or (assessment.tenant_id != identity.tenant_id and not identity.is_admin):
        raise EvidenceForbiddenError("Access to this evidence is not authorized.")

    if evidence.retention_until and datetime.now(timezone.utc) > evidence.retention_until:
        raise NotFoundError("Evidence", detail="Evidence has expired per retention policy.")

    expires = datetime.now(timezone.utc) + timedelta(minutes=_LINK_TTL_MINUTES)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "evidenceId": str(evidence.id),
            "kind": getattr(evidence, "kind", "unknown"),
            "assessmentId": str(evidence.assessment_id),
            "contentHash": evidence.content_hash,
            "collectorVersion": evidence.collector_version,
            "collectedAt": evidence.collected_at.isoformat() if evidence.collected_at else None,
            "redacted": True,
            "artifactUrl": f"/v1/evidence/{evidence_id}/artifact",
            "expiresAt": expires.isoformat(),
        },
        headers={"X-Request-ID": request_id},
    )


@router.get(
    "/{evidence_id}/artifact",
    summary="Download redacted evidence artifact",
)
@limiter.limit("20/minute")
async def download_evidence_artifact(
    request: Request,
    evidence_id: uuid.UUID = Path(..., description="Evidence UUID"),
    *,
    db: AsyncSession = Depends(get_db),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> Response:
    """Stream authorized, redacted artifact blob from storage."""
    stmt = (
        select(Evidence, Assessment)
        .outerjoin(Assessment, Evidence.assessment_id == Assessment.id)
        .where(Evidence.id == evidence_id)
    )
    result = await db.execute(stmt)
    row = result.first()

    if row is None:
        raise NotFoundError("Evidence artifact", detail=str(evidence_id))

    evidence, assessment = row
    if assessment is None or (assessment.tenant_id != identity.tenant_id and not identity.is_admin):
        raise EvidenceForbiddenError("Access to this evidence is not authorized.")

    # Check retention expiry if set
    if evidence.retention_until and datetime.now(timezone.utc) > evidence.retention_until:
        raise NotFoundError("Evidence artifact", detail="Evidence artifact has expired per retention policy.")

    store = EvidenceStore()
    content_bytes = await store.retrieve(evidence.content_hash)
    if content_bytes is None:
        raise NotFoundError("Evidence artifact", detail="Evidence content not found in storage.")

    return Response(
        content=content_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="evidence-{evidence_id}.json"',
            "Cache-Control": "no-store",
        },
    )
