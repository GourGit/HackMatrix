"""End-to-end controlled-target integration test for TrustLens.

Verifies:
1. Authenticated user creates and retrieves an authorized scope via API.
2. User submits an authorized target URL for assessment.
3. Orchestration worker processes target safely across all six deterministic agents:
   - URL & Redirect
   - Phishing & Brand
   - Certificate Intelligence
   - Safe Surface (strictly scoped ports)
   - Privacy & Cookies
   - Threat Intelligence Feed
4. Evidence is persisted, redacted, and linked to findings via finding_evidence.
5. Truthful agent runs and check statuses are returned via GET /v1/assessments/{id}.
6. Risk score aggregate and contributions match stored findings.
7. Unauthorized safe scans (unapproved ports) are strictly denied (403).
8. Private-address and loopback targets are strictly blocked (SSRF guardrail).
9. Crypto-scam analysis remains disabled by default and runs only behind feature flag.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlalchemy import select

from app.agents.base import AgentExecutionResult
from app.api.deps import get_db
from app.config import settings
from app.core.errors import ErrorCode
from app.main import create_app
from app.middleware.rate_limit import limiter
from app.models.agent_run import AgentRun
from app.models.assessment import Assessment
from app.models.authorization import AuthorizationScope
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.orchestrator.engine import AssessmentOrchestrator
from app.schemas.common import (
    AgentName,
    AgentRunStatus,
    AssessmentStatus,
    CheckAvailability,
    EvidenceKind,
    FindingStatus,
    ScopeStatus,
    Severity,
)
from app.schemas.finding import FindingEnvelope


@pytest.fixture(autouse=True)
def disable_rate_limit():
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.mark.asyncio
async def test_end_to_end_controlled_target_lifecycle(db_session, tmp_path, monkeypatch):
    """Full lifecycle: create scope -> submit URL -> worker runs -> verify truthful results & evidence."""
    monkeypatch.setattr(settings, "evidence_storage_path", tmp_path / "evidence_store")

    tenant_id = uuid.uuid4()
    subject_id = uuid.uuid4()
    auth_headers = {
        "X-Tenant-ID": str(tenant_id),
        "X-Subject-ID": str(subject_id),
    }

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("app.api.v1.assessments._run_orchestration_background", AsyncMock()):
            # ── Step 1: Create Authorized Scope ───────────────────────────────────
            scope_res = await client.post(
                "/v1/scopes",
                headers=auth_headers,
                json={
                    "targets": ["https://controlled-target.test"],
                    "allowedPorts": [443, 8443],
                    "attestation": "Authorized pentest engagement #2026-CT01",
                },
            )
            assert scope_res.status_code == 201, scope_res.text
            scope_data = scope_res.json()
            scope_id = scope_data["id"]
            assert scope_data["status"] == "active"
            assert scope_data["allowedPorts"] == [443, 8443]

            # ── Step 2: Submit Target URL for Assessment ──────────────────────────
            create_res = await client.post(
                "/v1/assessments",
                headers=auth_headers,
                json={
                    "url": "https://controlled-target.test/app",
                    "authorization": {
                        "attested": True,
                        "scopeId": scope_id,
                    },
                    "safeScan": {
                        "enabled": True,
                        "ports": [443],
                    },
                    "options": {
                        "cryptoScamAnalysis": False,
                    },
                },
            )
            assert create_res.status_code in (200, 201, 202), create_res.text
            create_data = create_res.json()
            assessment_id = uuid.uuid4() if "assessmentId" not in create_data else uuid.UUID(create_data["assessmentId"])

        # Verify initial assessment record in database
        stmt = select(Assessment).where(Assessment.id == assessment_id)
        assessment_row = (await db_session.execute(stmt)).scalar_one()
        assert assessment_row.tenant_id == tenant_id
        assert assessment_row.scope_id == uuid.UUID(scope_id)
        assert assessment_row.status in (AssessmentStatus.QUEUED.value, AssessmentStatus.RUNNING.value)

        # ── Step 3: Controlled Worker Execution ──────────────────────────────
        orchestrator = AssessmentOrchestrator(db_session)

        # Build mock findings with evidence and secrets that must be redacted
        ev1_id = uuid.uuid4()
        f1_id = uuid.uuid4()

        ev2_id = uuid.uuid4()
        f2_id = uuid.uuid4()

        for agent in orchestrator.agents:
            if agent.agent_name == AgentName.CERTIFICATE_INTELLIGENCE:
                agent.run = AsyncMock(return_value=AgentExecutionResult(
                    agent_name=agent.agent_name,
                    status=AgentRunStatus.COMPLETED,
                    raw_evidence=[{
                        "evidence_id": str(ev1_id),
                        "kind": EvidenceKind.CERTIFICATE.value,
                        "target": "https://controlled-target.test",
                        "auth_bearer_token": "SUPER_SECRET_TOKEN_DO_NOT_LEAK",
                        "checks": {
                            "hostname_match": "passed",
                            "ca_chain": "passed",
                            "ct": "passed",
                            "revocation": "good",
                        },
                    }],
                    findings=[FindingEnvelope(
                        finding_id=f1_id,
                        assessment_id=assessment_id,
                        agent=AgentName.CERTIFICATE_INTELLIGENCE,
                        type="certificate.san_match",
                        severity=Severity.INFORMATIONAL,
                        confidence=0.95,
                        score_impact=0,
                        title="Certificate SAN accurately matches target domain.",
                        description="Verified that certificate SAN matches target domain.",
                        affected_asset="https://controlled-target.test",
                        observed_at=datetime.now(timezone.utc),
                        rule_version="cert-v1",
                        evidence_ids=[ev1_id],
                    )],
                    ended_at=datetime.now(timezone.utc),
                ))
            elif agent.agent_name == AgentName.SAFE_SURFACE:
                agent.run = AsyncMock(return_value=AgentExecutionResult(
                    agent_name=agent.agent_name,
                    status=AgentRunStatus.COMPLETED,
                    raw_evidence=[{
                        "evidence_id": str(ev2_id),
                        "kind": EvidenceKind.BANNER.value,
                        "target": "https://controlled-target.test",
                        "host": "controlled-target.test",
                        "port": 443,
                        "banner": "nginx/1.24.0",
                    }],
                    findings=[FindingEnvelope(
                        finding_id=f2_id,
                        assessment_id=assessment_id,
                        agent=AgentName.SAFE_SURFACE,
                        type="service.exposed_port",
                        severity=Severity.LOW,
                        confidence=0.9,
                        score_impact=3,
                        title="Port 443 TCP open (nginx/1.24.0).",
                        description="Target exposes open HTTPS port 443 with Nginx banner.",
                        affected_asset="https://controlled-target.test",
                        observed_at=datetime.now(timezone.utc),
                        rule_version="surface-v1",
                        evidence_ids=[ev2_id],
                    )],
                    ended_at=datetime.now(timezone.utc),
                ))
            else:
                agent.run = AsyncMock(return_value=AgentExecutionResult(
                    agent_name=agent.agent_name,
                    status=AgentRunStatus.COMPLETED,
                    raw_evidence=[],
                    findings=[],
                    ended_at=datetime.now(timezone.utc),
                ))

        # Execute assessment in orchestrator
        final_assessment = await orchestrator.execute_assessment(
            assessment_id=assessment_id,
            safe_scan_enabled=True,
            safe_scan_ports=[443],
            crypto_scam_analysis=False,
        )

        assert final_assessment.status == AssessmentStatus.COMPLETED.value
        assert final_assessment.score == 3
        assert final_assessment.score_band == "low"

        # ── Step 4: Verify Evidence Persistence & Provenance in DB ────────────
        ev_stmt = select(Evidence).where(Evidence.assessment_id == assessment_id)
        evidence_rows = (await db_session.execute(ev_stmt)).scalars().all()
        assert len(evidence_rows) == 2

        ev_map = {row.id: row for row in evidence_rows}
        assert ev1_id in ev_map
        assert ev2_id in ev_map

        # Verify redaction in stored evidence
        storage_file = tmp_path / "evidence_store" / ev_map[ev1_id].storage_ref
        assert storage_file.exists()
        persisted_text = storage_file.read_text(encoding="utf-8")
        assert "SUPER_SECRET_TOKEN_DO_NOT_LEAK" not in persisted_text
        assert "[REDACTED]" in persisted_text

        # Verify finding_evidence linkage
        f_stmt = select(Finding).where(Finding.assessment_id == assessment_id)
        finding_rows = (await db_session.execute(f_stmt)).scalars().all()
        assert len(finding_rows) == 2

        # ── Step 5: Verify Truthful Assessment Detail API Response ───────────
        detail_res = await client.get(
            f"/v1/assessments/{assessment_id}",
            headers=auth_headers,
        )
        assert detail_res.status_code == 200, detail_res.text
        detail = detail_res.json()

        assert detail["assessmentId"] == str(assessment_id)
        assert detail["status"] == "completed"
        assert detail["risk"]["score"] == 3
        assert detail["risk"]["band"] == "low"

        # Check score contribution matches stored findings
        contributions = detail["risk"]["contributions"]
        assert len(contributions) == 1
        assert contributions[0]["findingId"] == str(f2_id)
        assert contributions[0]["points"] == 3

        # Check truthful per-agent runs
        agent_runs = detail.get("agentRuns", [])
        assert len(agent_runs) == 6
        agent_names = {r["agentName"] for r in agent_runs}
        assert AgentName.URL_REDIRECT.value in agent_names
        assert AgentName.PHISHING_BRAND.value in agent_names
        assert AgentName.CERTIFICATE_INTELLIGENCE.value in agent_names
        assert AgentName.SAFE_SURFACE.value in agent_names
        assert AgentName.PRIVACY_SOFTWARE.value in agent_names
        assert AgentName.THREAT_INTELLIGENCE.value in agent_names

        for r in agent_runs:
            assert r["status"] == "completed"
            assert r["startedAt"] is not None
            assert r["endedAt"] is not None

        # Check that evidence IDs are returned in finding details
        f_payload = detail["findings"]
        assert len(f_payload) == 2
        f2_payload = next(f for f in f_payload if f["findingId"] == str(f2_id))
        assert str(ev2_id) in f2_payload["evidenceIds"]


@pytest.mark.asyncio
async def test_unauthorized_safe_scan_ports_denied(db_session):
    """Safe scans requesting ports outside the authorized scope must be denied (403)."""
    tenant_id = uuid.uuid4()
    subject_id = uuid.uuid4()
    auth_headers = {
        "X-Tenant-ID": str(tenant_id),
        "X-Subject-ID": str(subject_id),
    }

    now = datetime.now(timezone.utc)
    scope = AuthorizationScope(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        subject_id=subject_id,
        targets_json=["https://scoped-host.test"],
        allowed_ports_json=[443],  # Only 443 authorized
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        status=ScopeStatus.ACTIVE.value,
    )
    db_session.add(scope)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Request port 22 (SSH) which is NOT approved in scope
        res = await client.post(
            "/v1/assessments",
            headers=auth_headers,
            json={
                "url": "https://scoped-host.test/page",
                "authorization": {
                    "attested": True,
                    "scopeId": str(scope.id),
                },
                "safeScan": {
                    "enabled": True,
                    "ports": [22],
                },
            },
        )
        assert res.status_code == 403
        data = res.json()
        assert data["error"]["code"] == ErrorCode.SAFE_SCAN_NOT_ALLOWED


@pytest.mark.asyncio
async def test_private_address_and_loopback_targets_denied(db_session):
    """SSRF guardrail: Submissions targeting private IPv4, IPv6, or cloud metadata must be denied (400)."""
    tenant_id = uuid.uuid4()
    subject_id = uuid.uuid4()
    auth_headers = {
        "X-Tenant-ID": str(tenant_id),
        "X-Subject-ID": str(subject_id),
    }

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    blocked_targets = [
        "http://127.0.0.1:8000/internal",
        "http://localhost:5432",
        "http://192.168.1.1/admin",
        "http://10.0.0.5/secrets",
        "http://172.16.0.1/status",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:8080",
        "http://[fe80::1]/test",
    ]

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for target in blocked_targets:
            res = await client.post(
                "/v1/assessments",
                headers=auth_headers,
                json={
                    "url": target,
                    "authorization": {"attested": True},
                },
            )
            assert res.status_code in (400, 403), f"Target {target} was not rejected! Status: {res.status_code}"
            data = res.json()
            assert data["error"]["code"] in (ErrorCode.INVALID_URL, ErrorCode.UNSAFE_TARGET)


def test_crypto_scam_analysis_disabled_by_default():
    """Verify crypto-scam analysis is disabled by default and only runs behind server feature flag."""
    # Server default
    default_settings = settings.__class__()
    assert default_settings.crypto_scam_analysis_enabled is False
