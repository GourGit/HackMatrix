"""Assessment endpoints — create, execute, and retrieve security assessments.

The create endpoint validates the target URL, persists an assessment record,
triggers asynchronous agent orchestration in the background, and returns 202 Accepted.
The retrieval endpoint loads the full assessment graph including agent runs,
findings, checks, and risk contributions.
"""

from __future__ import annotations

import asyncio
import ipaddress
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
    UnsafeTargetError,
)
from app.core.safety import validate_ip_safety
from app.core.scope_validator import validate_scope_authorization
from app.core.url_validator import normalize_url
from app.database import async_session_factory
from app.middleware.rate_limit import limiter
from app.models.assessment import Assessment
from app.models.authorization import AuthorizationScope
from app.models.finding import Finding
from app.orchestrator.engine import AssessmentOrchestrator
from app.schemas.assessment import CreateAssessmentRequest
from app.schemas.common import (
    AgentName,
    AgentRunStatus,
    AssessmentStatus,
    CertificateFieldStatus,
    CheckAvailability,
    RevocationStatus,
    ScopeStatus,
    score_to_band,
)

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

    # Reject private addresses and localhost upfront (SSRF guardrail)
    clean_host = norm_result.host.strip().lower().rstrip(".")
    if (
        clean_host in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback")
        or clean_host.endswith(".localhost")
    ):
        raise UnsafeTargetError(
            "The target hostname resolves to loopback/localhost and is not allowed.",
            detail={"hostname": norm_result.host, "reason": "localhost"},
        )
    ip_to_validate = None
    raw_ip_str = clean_host.strip("[]")
    try:
        ipaddress.ip_address(raw_ip_str)
        ip_to_validate = raw_ip_str
    except ValueError:
        pass

    if ip_to_validate is not None:
        validate_ip_safety(ip_to_validate)

    # 1. Attestation check
    if not payload.authorization or not payload.authorization.attested:
        raise UnauthorizedScopeError("Authorization attestation is required.")

    # 2. Scope validation
    scope_id = payload.authorization.scope_id if payload.authorization else None
    safe_scan_requested = bool(payload.safe_scan and payload.safe_scan.enabled)
    requested_ports = payload.safe_scan.ports if (payload.safe_scan and payload.safe_scan.ports) else []

    if safe_scan_requested:
        if not scope_id:
            raise UnauthorizedScopeError(
                "Active safe scanning requires an explicit authorized scope."
            )
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
            safe_scan_requested=True,
            requested_ports=requested_ports,
        )
    else:
        # Passive assessment: does not require an explicit scope
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
            validate_scope_authorization(
                scope=scope,
                normalized_url=norm_result.normalized_str,
                safe_scan_requested=False,
                requested_ports=[],
            )
        else:
            scope_id = None

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
            "scopeId": str(scope_id) if scope_id else None,
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
        .where(
            Assessment.id == assessment_id,
            Assessment.tenant_id == tenant_id,
        )
        .options(
            selectinload(Assessment.agent_runs),
            selectinload(Assessment.findings).selectinload(Finding.evidence_items),
            selectinload(Assessment.certificate_observations),
            selectinload(Assessment.service_observations),
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
        evidence_ids = [str(ev.id) for ev in (getattr(f, "evidence_items", []) or [])]
        findings_payload.append({
            "findingId": str(f.id),
            "agent": f.agent_run_id and next((r.agent_name for r in agent_runs if r.id == f.agent_run_id), "") or "",
            "type": f.type,
            "severity": f.severity,
            "confidence": f.confidence,
            "title": f.summary,
            "evidenceIds": evidence_ids,
        })

    # Durable / truthful check availability determination
    if getattr(assessment, "checks_json", None):
        checks = assessment.checks_json
    else:
        cert_obs = assessment.certificate_observations[0] if getattr(assessment, "certificate_observations", None) else None
        cert_run = next(
            (r for r in agent_runs if r.agent_name in (AgentName.CERTIFICATE_INTELLIGENCE.value, "certificate-intelligence")),
            None,
        )
        finding_types = {f.type for f in findings}

        # Safe surface scan status
        safe_scan_run = next(
            (r for r in agent_runs if r.agent_name in (AgentName.SAFE_SURFACE.value, "safe-surface")),
            None,
        )
        has_service_obs = bool(getattr(assessment, "service_observations", None))
        if safe_scan_run is None:
            safe_scan_state = CheckAvailability.NOT_REQUESTED.value
        elif safe_scan_run.status in (AgentRunStatus.FAILED.value, AgentRunStatus.TIMEOUT.value):
            safe_scan_state = CheckAvailability.FAILED.value
        elif safe_scan_run.status == AgentRunStatus.UNAVAILABLE.value:
            safe_scan_state = CheckAvailability.UNAVAILABLE.value
        elif safe_scan_run.status == AgentRunStatus.COMPLETED.value:
            safe_scan_state = CheckAvailability.PASSED.value if has_service_obs else CheckAvailability.NOT_REQUESTED.value
        else:
            safe_scan_state = CheckAvailability.UNKNOWN.value

        # Certificate & TLS checks
        target_url = assessment.submitted_url or assessment.normalized_url or ""
        is_http = target_url.startswith("http://") or "certificate.unencrypted_http" in finding_types

        if is_http:
            ct_state = CheckAvailability.NOT_REQUESTED.value
            rev_state = CheckAvailability.NOT_REQUESTED.value
            ca_state = CheckAvailability.NOT_REQUESTED.value
            host_state = CheckAvailability.NOT_REQUESTED.value
            val_state = CheckAvailability.NOT_REQUESTED.value
            tls_state = CheckAvailability.NOT_REQUESTED.value
            crypto_state = CheckAvailability.NOT_REQUESTED.value
        elif cert_run is None:
            ct_state = CheckAvailability.NOT_REQUESTED.value
            rev_state = CheckAvailability.NOT_REQUESTED.value
            ca_state = CheckAvailability.NOT_REQUESTED.value
            host_state = CheckAvailability.NOT_REQUESTED.value
            val_state = CheckAvailability.NOT_REQUESTED.value
            tls_state = CheckAvailability.NOT_REQUESTED.value
            crypto_state = CheckAvailability.NOT_REQUESTED.value
        elif cert_run.status in (AgentRunStatus.FAILED.value, AgentRunStatus.UNAVAILABLE.value, AgentRunStatus.TIMEOUT.value) and not cert_obs:
            ct_state = CheckAvailability.UNAVAILABLE.value
            rev_state = CheckAvailability.UNAVAILABLE.value
            ca_state = CheckAvailability.UNAVAILABLE.value
            host_state = CheckAvailability.UNAVAILABLE.value
            val_state = CheckAvailability.UNAVAILABLE.value
            tls_state = CheckAvailability.UNAVAILABLE.value
            crypto_state = CheckAvailability.UNAVAILABLE.value
        else:
            # CT presence
            if "certificate.missing_sct" in finding_types:
                ct_state = CheckAvailability.FAILED.value
            elif cert_obs and cert_obs.ct_status == CertificateFieldStatus.VALID:
                ct_state = CheckAvailability.PASSED.value
            else:
                ct_state = CheckAvailability.UNKNOWN.value

            # Revocation status (Never report good because a network request failed)
            if "certificate.revoked" in finding_types:
                rev_state = CheckAvailability.FAILED.value
            elif "certificate.revocation_unknown" in finding_types:
                rev_state = CheckAvailability.UNKNOWN.value
            elif cert_obs:
                if cert_obs.revocation_status == RevocationStatus.GOOD:
                    rev_state = CheckAvailability.PASSED.value
                elif cert_obs.revocation_status == RevocationStatus.REVOKED:
                    rev_state = CheckAvailability.FAILED.value
                elif cert_obs.revocation_status == RevocationStatus.UNAVAILABLE:
                    rev_state = CheckAvailability.UNAVAILABLE.value
                else:
                    rev_state = CheckAvailability.UNKNOWN.value
            else:
                rev_state = CheckAvailability.UNKNOWN.value

            # CA Chain
            if "certificate.untrusted_ca" in finding_types:
                ca_state = CheckAvailability.FAILED.value
            elif cert_obs and cert_obs.ca_status == CertificateFieldStatus.VALID:
                ca_state = CheckAvailability.PASSED.value
            elif cert_obs and cert_obs.ca_status == CertificateFieldStatus.INVALID:
                ca_state = CheckAvailability.FAILED.value
            elif cert_run.status == AgentRunStatus.COMPLETED.value:
                ca_state = CheckAvailability.PASSED.value
            else:
                ca_state = CheckAvailability.UNKNOWN.value

            # Hostname / SAN match
            if "certificate.san_mismatch" in finding_types:
                host_state = CheckAvailability.FAILED.value
            elif cert_obs and cert_obs.hostname_status == CertificateFieldStatus.VALID:
                host_state = CheckAvailability.PASSED.value
            elif cert_obs and cert_obs.hostname_status == CertificateFieldStatus.INVALID:
                host_state = CheckAvailability.FAILED.value
            elif cert_run.status == AgentRunStatus.COMPLETED.value:
                host_state = CheckAvailability.PASSED.value
            else:
                host_state = CheckAvailability.UNKNOWN.value

            # Validity dates
            if "certificate.expired" in finding_types or "certificate.not_yet_valid" in finding_types:
                val_state = CheckAvailability.FAILED.value
            elif cert_run.status == AgentRunStatus.COMPLETED.value:
                val_state = CheckAvailability.PASSED.value
            else:
                val_state = CheckAvailability.UNKNOWN.value

            # TLS version & cipher
            if "tls.obsolete_version" in finding_types or "tls.weak_cipher" in finding_types:
                tls_state = CheckAvailability.FAILED.value
            elif cert_run.status == AgentRunStatus.COMPLETED.value:
                tls_state = CheckAvailability.PASSED.value
            else:
                tls_state = CheckAvailability.UNKNOWN.value

            # Cryptographic strength
            if "certificate.weak_key" in finding_types or "certificate.weak_signature" in finding_types:
                crypto_state = CheckAvailability.FAILED.value
            elif cert_run.status == AgentRunStatus.COMPLETED.value:
                crypto_state = CheckAvailability.PASSED.value
            else:
                crypto_state = CheckAvailability.UNKNOWN.value

        checks = {
            "ct": ct_state,
            "revocation": rev_state,
            "safeScan": safe_scan_state,
            "hostnameMatch": host_state,
            "validityDates": val_state,
            "caChain": ca_state,
            "tlsConfiguration": tls_state,
            "cryptoStrength": crypto_state,
        }

    agent_runs_payload = [
        {
            "agentName": r.agent_name,
            "status": r.status,
            "startedAt": r.started_at.isoformat() if r.started_at else None,
            "endedAt": r.ended_at.isoformat() if r.ended_at else None,
            "errorCode": r.error_code,
        }
        for r in agent_runs
    ]

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
            "agentRuns": agent_runs_payload,
            "createdAt": assessment.created_at.isoformat() if assessment.created_at else None,
            "completedAt": assessment.completed_at.isoformat() if assessment.completed_at else None,
        },
        headers={"X-Request-ID": request_id},
    )
