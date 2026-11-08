"""Tests for finding review, tenant enforcement, and append-only audit history.

Verifies:
1. Reviewing findings with accepted, disputed, and false_positive decisions.
2. Capturing previous_status before mutating finding status.
3. Persisting reviewer_id, reviewed_at, rationale, and decision on Finding.
4. Appending valid AuditEvent records with correct actor, tenant, action, entity, and metadata_json.
5. Rejection of invalid decisions (including 'active') and invalid rationale lengths (422).
6. Tenant ownership enforcement (cross-tenant review rejected with 403).
7. Append-only audit history preservation across multiple review cycles.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select

from app.api.deps import get_db
from app.core.errors import ErrorCode
from app.main import create_app
from app.middleware.rate_limit import limiter
from app.models.agent_run import AgentRun
from app.models.assessment import Assessment
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.schemas.common import AgentRunStatus, AssessmentStatus, FindingStatus, Severity


@pytest.fixture(autouse=True)
def disable_rate_limit():
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.mark.asyncio
async def test_review_accepted_disputed_false_positive(db_session):
    """Test full review workflow for accepted, disputed, and false_positive."""
    tenant_id = uuid.uuid4()
    reviewer_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    agent_run_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    now = datetime.now(timezone.utc)
    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=uuid.uuid4(),
        submitted_url="https://test.example",
        normalized_url="https://test.example",
        status=AssessmentStatus.COMPLETED.value,
    )
    db_session.add(assessment)

    agent_run = AgentRun(
        id=agent_run_id,
        assessment_id=assessment_id,
        agent_name="certificate-intelligence",
        status=AgentRunStatus.COMPLETED.value,
        started_at=now,
    )
    db_session.add(agent_run)

    finding = Finding(
        id=finding_id,
        assessment_id=assessment_id,
        agent_run_id=agent_run_id,
        type="certificate.revocation_unknown",
        severity=Severity.MEDIUM,
        confidence=0.8,
        status=FindingStatus.ACTIVE.value,
        asset="https://test.example",
        summary="Revocation Unknown",
    )
    db_session.add(finding)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Review decision: accepted
        resp1 = await client.post(
            f"/v1/findings/{finding_id}/review",
            headers={
                "X-Tenant-ID": str(tenant_id),
                "X-Subject-ID": str(reviewer_id),
            },
            json={
                "decision": "accepted",
                "rationale": "Verified via independent CRL check.",
            },
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["findingId"] == str(finding_id)
        assert data1["status"] == "accepted"
        assert data1["decision"] == "accepted"
        assert data1["reviewerId"] == str(reviewer_id)
        assert data1["rationale"] == "Verified via independent CRL check."
        assert "reviewedAt" in data1

        # Check DB Finding row
        f_stmt = select(Finding).where(Finding.id == finding_id)
        f_row = (await db_session.execute(f_stmt)).scalar_one()
        assert f_row.status == "accepted"
        assert f_row.decision == "accepted"
        assert f_row.reviewer_id == reviewer_id
        assert f_row.rationale == "Verified via independent CRL check."
        assert f_row.reviewed_at is not None

        # Check AuditEvent row in DB
        a_stmt = select(AuditEvent).where(AuditEvent.entity_id == finding_id).order_by(AuditEvent.occurred_at.asc())
        audits = (await db_session.execute(a_stmt)).scalars().all()
        assert len(audits) == 1
        assert audits[0].tenant_id == tenant_id
        assert audits[0].actor_id == reviewer_id
        assert audits[0].action == "finding.reviewed"
        assert audits[0].entity_type == "finding"
        assert audits[0].metadata_json["previous_status"] == "active"
        assert audits[0].metadata_json["decision"] == "accepted"
        assert audits[0].metadata_json["new_status"] == "accepted"
        assert audits[0].metadata_json["rationale"] == "Verified via independent CRL check."

        # 2. Review decision: disputed
        reviewer_2 = uuid.uuid4()
        resp2 = await client.post(
            f"/v1/findings/{finding_id}/review",
            headers={
                "X-Tenant-ID": str(tenant_id),
                "X-Subject-ID": str(reviewer_2),
            },
            json={
                "decision": "disputed",
                "rationale": "Responder returned network error; disputing status.",
            },
        )
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "disputed"

        await db_session.refresh(f_row)
        assert f_row.status == "disputed"
        assert f_row.decision == "disputed"
        assert f_row.reviewer_id == reviewer_2

        # Check that second audit captured previous_status == "accepted"
        audits = (await db_session.execute(a_stmt)).scalars().all()
        assert len(audits) == 2
        assert audits[1].metadata_json["previous_status"] == "accepted"
        assert audits[1].metadata_json["decision"] == "disputed"

        # 3. Review decision: false_positive (using 'status' field alias)
        resp3 = await client.post(
            f"/v1/findings/{finding_id}/review",
            headers={
                "X-Tenant-ID": str(tenant_id),
                "X-Subject-ID": str(reviewer_id),
            },
            json={
                "status": "false_positive",
                "rationale": "Internal test domain.",
            },
        )
        assert resp3.status_code == 200
        assert resp3.json()["status"] == "false_positive"

        await db_session.refresh(f_row)
        assert f_row.status == "false_positive"
        assert f_row.decision == "false_positive"

        audits = (await db_session.execute(a_stmt)).scalars().all()
        assert len(audits) == 3
        assert audits[2].metadata_json["previous_status"] == "disputed"
        assert audits[2].metadata_json["decision"] == "false_positive"


@pytest.mark.asyncio
async def test_invalid_decision_and_rationale_validation(db_session):
    """Test validation errors on invalid review decisions and missing/invalid rationale."""
    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=uuid.uuid4(),
        submitted_url="https://test.example",
        normalized_url="https://test.example",
        status=AssessmentStatus.COMPLETED.value,
    )
    db_session.add(assessment)

    finding = Finding(
        id=finding_id,
        assessment_id=assessment_id,
        agent_run_id=uuid.uuid4(),
        type="missing-hsts",
        severity=Severity.LOW,
        confidence=0.9,
        status=FindingStatus.ACTIVE.value,
    )
    db_session.add(finding)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    invalid_cases = [
        # Invalid decision value
        {"decision": "bogus_decision", "rationale": "Valid rationale"},
        # Attempting to set 'active' as a review decision
        {"decision": "active", "rationale": "Valid rationale"},
        # Missing decision and status
        {"rationale": "Valid rationale"},
        # Missing rationale
        {"decision": "accepted"},
        # Empty rationale
        {"decision": "accepted", "rationale": ""},
        # Whitespace-only rationale
        {"decision": "accepted", "rationale": "    \t \n   "},
        # Conflicting decision and status
        {"decision": "accepted", "status": "disputed", "rationale": "Valid rationale"},
        # Rationale exceeding 2000 characters
        {"decision": "accepted", "rationale": "x" * 2001},
    ]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for case in invalid_cases:
            resp = await client.post(
                f"/v1/findings/{finding_id}/review",
                headers={"X-Tenant-ID": str(tenant_id)},
                json=case,
            )
            assert resp.status_code == 422, f"Expected 422 for case {case}, got {resp.status_code}"
            assert resp.json()["error"]["code"] == ErrorCode.VALIDATION_ERROR


@pytest.mark.asyncio
async def test_tenant_denial_on_finding_review(db_session):
    """Test that reviewing a finding belonging to another tenant is denied with 403."""
    tenant_owner = uuid.uuid4()
    tenant_attacker = uuid.uuid4()
    assessment_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_owner,
        scope_id=uuid.uuid4(),
        submitted_url="https://victim.example",
        normalized_url="https://victim.example",
        status=AssessmentStatus.COMPLETED.value,
    )
    db_session.add(assessment)

    finding = Finding(
        id=finding_id,
        assessment_id=assessment_id,
        agent_run_id=uuid.uuid4(),
        type="missing-hsts",
        severity=Severity.LOW,
        confidence=0.9,
        status=FindingStatus.ACTIVE.value,
    )
    db_session.add(finding)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/v1/findings/{finding_id}/review",
            headers={"X-Tenant-ID": str(tenant_attacker)},
            json={
                "decision": "accepted",
                "rationale": "Attacker trying to review another tenant's finding.",
            },
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "FORBIDDEN"

        # Verify finding in DB was not touched
        f_row = (await db_session.execute(select(Finding).where(Finding.id == finding_id))).scalar_one()
        assert f_row.status == FindingStatus.ACTIVE.value
        assert f_row.decision is None
        assert f_row.reviewer_id is None

        # Verify no audit event was created
        audits = (await db_session.execute(select(AuditEvent).where(AuditEvent.entity_id == finding_id))).scalars().all()
        assert len(audits) == 0


@pytest.mark.asyncio
async def test_nonexistent_finding_returns_404(db_session):
    """Test that reviewing a nonexistent finding returns 404."""
    random_id = uuid.uuid4()
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/v1/findings/{random_id}/review",
            headers={"X-Tenant-ID": str(uuid.uuid4())},
            json={
                "decision": "accepted",
                "rationale": "Nonexistent finding review.",
            },
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == ErrorCode.NOT_FOUND


def test_alembic_migration_module():
    """Verify that the Alembic migration module defines valid upgrade and downgrade operations."""
    import importlib.util
    from pathlib import Path

    versions_dir = Path(__file__).resolve().parent.parent / "migrations" / "versions"
    migration_files = [f for f in versions_dir.glob("*.py") if not f.name.startswith("__")]
    assert len(migration_files) > 0, "No migration file exists"

    for migration_path in migration_files:
        spec = importlib.util.spec_from_file_location("migration_module", migration_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        assert hasattr(module, "upgrade")
        assert hasattr(module, "downgrade")
        assert hasattr(module, "revision")

