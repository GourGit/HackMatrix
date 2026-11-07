"""Assessment endpoints — create, execute, and retrieve security assessments.

The create endpoint validates the target URL, persists an assessment record,
triggers asynchronous agent orchestration in the background, and returns 202 Accepted.
The retrieval endpoint loads the full assessment graph including agent runs,
findings, checks, and risk contributions.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Path, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    AuthenticatedIdentity,
    get_current_identity,
    get_db,
    get_request_id,
    get_tenant_id,
)
from app.config import settings
from app.core.errors import (
    ErrorCode,
    InvalidURLError,
    NotFoundError,
    SafeScanNotAllowedError,
    UnauthorizedScopeError,
)
from app.core.scope_validator import validate_scope_authorization
from app.core.url_validator import normalize_url
from app.database import async_session_factory
from app.middleware.rate_limit import limiter
from app.models.assessment import Assessment
from app.models.authorization import AuthorizationScope
from app.orchestrator.engine import AssessmentOrchestrator
from app.schemas.assessment import CreateAssessmentRequest
from app.schemas.common import AssessmentStatus, CheckAvailability, ScopeStatus, score_to_band

router = APIRouter(prefix="/assessments", tags=["assessments"])


async def _run_orchestration_background(
    assessment_id: uuid.UUID,
    safe_scan_enabled: bool,
    safe_scan_ports: list[int],
    crypto_scam_analysis: bool,
):
    """Background task running orchestrator with a dedicated DB session."""
    async with async_session_factory() as session:
        try:
            orch = AssessmentOrchestrator(session)
            await orch.execute_assessment(
                assessment_id=assessment_id,
                safe_scan_enabled=safe_scan_enabled,
                safe_scan_ports=safe_scan_ports,
                crypto_scam_analysis=crypto_scam_analysis,
            )
        except Exception as e:
            stmt = select(Assessment).where(Assessment.id == assessment_id)
            res = await session.execute(stmt)
            rec = res.scalar_one_or_none()
            if rec:
                rec.status = AssessmentStatus.FAILED.value
                await session.commit()


@router.post(
    "",
    summary="Create a new assessment",
    status_code=status.HTTP_202_ACCEPTED,
    response_class=JSONResponse,
)
@limiter.limit("20/minute")
async def create_assessment(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: CreateAssessmentRequest,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> JSONResponse:
    """Queue a new security assessment for the given URL.

    Enforces scope ownership, active validity, target coverage,
    and safe scan permissions before scheduling execution.
    """
    raw_url = str(payload.url)
    try:
        norm_result = normalize_url(raw_url)
    except Exception as e:
        raise InvalidURLError(message=str(e), detail=raw_url)

    # 1. Attestation check
    if not payload.authorization or not payload.authorization.attested:
        raise UnauthorizedScopeError("Authorization attestation is required.")

    # 2. Scope validation
    scope_id = payload.authorization.scope_id if payload.authorization else None
    safe_scan_requested = bool(payload.safe_scan and payload.safe_scan.enabled)
    requested_ports = payload.safe_scan.ports if (payload.safe_scan and payload.safe_scan.ports) else []

    if scope_id:
        stmt = select(AuthorizationScope).where(
            AuthorizationScope.id == scope_id,
            AuthorizationScope.tenant_id == identity.tenant_id,
        )
        res = await db.execute(stmt)
        scope = res.scalar_one_or_none()
        if not scope:
            raise UnauthorizedScopeError(
                f"Authorization scope {scope_id} does not exist or belongs to another tenant."
            )
        # Validate rules on scope
        validate_scope_authorization(
            scope=scope,
            normalized_url=norm_result.normalized_str,
            safe_scan_requested=safe_scan_requested,
            requested_ports=requested_ports,
        )
    else:
        # Development auto-scope only permitted in non-production
        if settings.is_production:
            raise UnauthorizedScopeError("Explicit pre-registered scope_id is required in production.")

        now = datetime.now(timezone.utc)
        scope_id = uuid.uuid4()
        scope = AuthorizationScope(
            id=scope_id,
            tenant_id=identity.tenant_id,
            subject_id=identity.subject_id,
            targets_json=[norm_result.normalized_str],
            allowed_ports_json=requested_ports if safe_scan_requested else None,
            valid_from=now,
            valid_until=now + timedelta(days=7),
            attestation="Development auto-attestation",
            status=ScopeStatus.ACTIVE.value,
        )
        db.add(scope)
        await db.flush()

    # 3. Check Crypto Scam option against server feature flag
    crypto_analysis = bool(
        payload.options
        and payload.options.crypto_scam_analysis
        and settings.crypto_scam_analysis_enabled
    )

    assessment_id = uuid.uuid4()
    assessment = Assessment(
        id=assessment_id,
        tenant_id=identity.tenant_id,
        scope_id=scope_id,
        submitted_url=raw_url,
        normalized_url=norm_result.normalized_str,
        status=AssessmentStatus.QUEUED.value,
    )
    db.add(assessment)
    await db.commit()

    # Trigger background agent orchestration with approved immutable context
    background_tasks.add_task(
        _run_orchestration_background,
        assessment_id=assessment_id,
        safe_scan_enabled=safe_scan_requested,
        safe_scan_ports=requested_ports,
        crypto_scam_analysis=crypto_analysis,
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "assessmentId": str(assessment.id),
            "status": AssessmentStatus.QUEUED.value,
            "scopeId": str(scope_id),
        },
        headers={"X-Request-ID": request_id},
    )


@router.get(
    "/{assessment_id}",
    summary="Retrieve assessment details",
    response_class=JSONResponse,
)
@limiter.limit("60/minute")
async def get_assessment(
    request: Request,
    assessment_id: uuid.UUID = Path(..., description="Assessment UUID"),
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    tenant_id: uuid.UUID = Depends(get_tenant_id),
) -> JSONResponse:
    """Return the full assessment detail including risk score, findings, and checks."""
    stmt = (
        select(Assessment)
        .where(Assessment.id == assessment_id)
        .options(
            selectinload(Assessment.agent_runs),
            selectinload(Assessment.findings),
        )
    )
    result = await db.execute(stmt)
    assessment = result.scalar_one_or_none()

    if assessment is None:
        raise NotFoundError("Assessment", detail=str(assessment_id))

    agent_runs = assessment.agent_runs or []
    findings = assessment.findings or []

    # Risk contributions
    contributions = []
    total_score = assessment.score or 0
    for finding in findings:
        pts = finding.score_impact or 0
        if pts > 0:
            contributions.append({"findingId": str(finding.id), "points": pts})

    band = assessment.score_band or score_to_band(total_score).value

    findings_payload = []
    for f in findings:
        evidence_ids = [str(fe.evidence_id) for fe in getattr(f, "evidences", [])] if hasattr(f, "evidences") else []
        findings_payload.append({
            "findingId": str(f.id),
            "agent": f.agent_run_id and next((r.agent_name for r in agent_runs if r.id == f.agent_run_id), "") or "",
            "type": f.type,
            "severity": f.severity,
            "confidence": f.confidence,
            "title": f.summary,
            "evidenceIds": evidence_ids,
        })

    checks = {
        "ct": "passed" if total_score < 75 else "unknown",
        "revocation": "unknown",
        "safeScan": "not_requested",
    }
    for r in agent_runs:
        if r.agent_name == "certificate-intelligence" and r.status == "completed":
            checks["ct"] = "passed"
        if r.agent_name == "safe-surface" and r.status == "completed":
            checks["safeScan"] = "completed"

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "assessmentId": str(assessment.id),
            "status": assessment.status,
            "target": assessment.submitted_url,
            "normalizedUrl": assessment.normalized_url,
            "risk": {
                "score": total_score,
                "band": band,
                "version": assessment.score_version or "2026-1",
                "contributions": contributions,
            },
            "findings": findings_payload,
            "checks": checks,
            "createdAt": assessment.created_at.isoformat() if assessment.created_at else None,
            "completedAt": assessment.completed_at.isoformat() if assessment.completed_at else None,
        },
        headers={"X-Request-ID": request_id},
    )
