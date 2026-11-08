"""Comprehensive tests for evidence persistence, provenance, and artifact retrieval.

Verifies:
1. Agent raw_evidence serialization and redaction into EvidenceStore.
2. Creation of Evidence database rows with full provenance attributes.
3. Linking of findings to Evidence via the finding_evidence junction.
4. Real evidence IDs returned in GET /v1/assessments/{id}.
5. Durable assessment check statuses in checks_json.
6. Authorized retrieval of evidence metadata without exposing filesystem paths.
7. Authorized download of redacted artifact bytes.
8. Rejection of cross-tenant evidence access with 403 EVIDENCE_FORBIDDEN.
9. Rejection of nonexistent or retention-expired evidence with 404 NOT_FOUND.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.agents.base import AgentExecutionResult
from app.api.deps import DEV_SUBJECT_ID, get_db
from app.config import settings
from app.core.errors import ErrorCode
from app.core.evidence_store import EvidenceStore
from app.main import create_app
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
    EvidenceKind,
    FindingStatus,
    ScopeStatus,
    Severity,
)
from app.schemas.finding import FindingEnvelope


@pytest.mark.asyncio
async def test_evidence_persistence_and_provenance(db_session, tmp_path, monkeypatch):
    """Test full orchestration persistence of evidence and finding linkage."""
    monkeypatch.setattr(settings, "evidence_storage_path", tmp_path / "evidence_store")

    tenant_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    assessment_id = uuid.uuid4()

    now = datetime.now(timezone.utc)
    scope = AuthorizationScope(
        id=scope_id,
        tenant_id=tenant_id,
        subject_id=uuid.uuid4(),
        targets_json=["https://secure-target.example"],
        allowed_ports_json=[443],
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        status=ScopeStatus.ACTIVE.value,
    )
    db_session.add(scope)

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=scope_id,
        submitted_url="https://secure-target.example",
        normalized_url="https://secure-target.example",
        status=AssessmentStatus.QUEUED.value,
    )
    db_session.add(assessment)
    await db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    # Prepare mock agents with raw_evidence containing a secret that must be redacted
    cert_ev_id = uuid.uuid4()
    cert_finding_id = uuid.uuid4()

    for agent in orchestrator.agents:
        if agent.agent_name == AgentName.CERTIFICATE_INTELLIGENCE:
            raw_ev = [
                {
                    "evidence_id": str(cert_ev_id),
                    "kind": EvidenceKind.CERTIFICATE.value,
                    "target": "https://secure-target.example",
                    "subject": "CN=secure-target.example",
                    "api_key": "SECRET_TOKEN_12345",  # Must be redacted
                    "checks": {
                        "hostname_match": "passed",
                        "validity_dates": "passed",
                        "ca_chain": "passed",
                        "tls_configuration": "passed",
                        "crypto_strength": "passed",
                        "ct": "passed",
                        "revocation": "unknown",
                    },
                }
            ]
            findings = [
                FindingEnvelope(
                    finding_id=cert_finding_id,
                    assessment_id=assessment_id,
                    agent=AgentName.CERTIFICATE_INTELLIGENCE,
                    type="certificate.revocation_unknown",
                    severity=Severity.INFORMATIONAL,
                    confidence=0.8,
                    score_impact=0,
                    status=FindingStatus.ACTIVE,
                    title="Certificate Revocation Unknown",
                    description="Certificate revocation check unknown.",
                    affected_asset="https://secure-target.example",
                    evidence_ids=[cert_ev_id],
                    observed_at=datetime.now(timezone.utc),
                    rule_version="2026-1",
                )
            ]
        else:
            raw_ev = []
            findings = []

        mock_result = AgentExecutionResult(
            agent_name=agent.agent_name,
            status=AgentRunStatus.COMPLETED,
            findings=findings,
            raw_evidence=raw_ev,
            ended_at=datetime.now(timezone.utc),
        )
        agent.run = AsyncMock(return_value=mock_result)

    await orchestrator.execute_assessment(
        assessment_id=assessment_id,
        safe_scan_enabled=False,
        safe_scan_ports=None,
        crypto_scam_analysis=False,
    )

    # 1. Verify Evidence row in DB
    ev_stmt = select(Evidence).where(Evidence.id == cert_ev_id)
    ev_res = await db_session.execute(ev_stmt)
    evidence_row = ev_res.scalar_one_or_none()

    assert evidence_row is not None
    assert evidence_row.assessment_id == assessment_id
    assert evidence_row.kind == EvidenceKind.CERTIFICATE.value
    assert evidence_row.source_uri == "https://secure-target.example"
    assert evidence_row.collector_version is not None
    assert evidence_row.redaction_version == "1.0"
    assert evidence_row.retention_until is not None
    assert evidence_row.content_hash is not None
    assert evidence_row.storage_ref is not None

    # 2. Verify stored artifact is redacted and retrievable
    store = EvidenceStore(tmp_path / "evidence_store")
    raw_bytes = await store.retrieve(evidence_row.content_hash)
    assert raw_bytes is not None
    stored_json_str = raw_bytes.decode("utf-8")
    assert "SECRET_TOKEN_12345" not in stored_json_str
    assert "[REDACTED]" in stored_json_str

    # 3. Verify Finding is linked to Evidence via finding_evidence junction
    finding_stmt = (
        select(Finding)
        .where(Finding.id == cert_finding_id)
        .options(selectinload(Finding.evidence_items))
    )
    f_res = await db_session.execute(finding_stmt)
    finding_row = f_res.scalar_one_or_none()

    assert finding_row is not None
    assert len(finding_row.evidence_items) == 1
    assert finding_row.evidence_items[0].id == cert_ev_id

    # 4. Verify Assessment durable checks
    ass_stmt = select(Assessment).where(Assessment.id == assessment_id)
    ass_res = await db_session.execute(ass_stmt)
    ass_row = ass_res.scalar_one()

    assert ass_row.checks_json is not None
    assert ass_row.checks_json.get("hostnameMatch") == "passed"
    assert ass_row.checks_json.get("validityDates") == "passed"
    assert ass_row.checks_json.get("revocation") == "unknown"


@pytest.mark.asyncio
async def test_get_assessment_returns_real_evidence_ids(db_session, tmp_path, monkeypatch):
    """Test that GET /v1/assessments/{id} returns real linked evidenceIds."""
    monkeypatch.setattr(settings, "evidence_storage_path", tmp_path / "evidence_store")

    tenant_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    agent_run_id = uuid.uuid4()

    now = datetime.now(timezone.utc)
    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=scope_id,
        submitted_url="https://example.com",
        normalized_url="https://example.com",
        status=AssessmentStatus.COMPLETED.value,
        checks_json={
            "ct": "passed",
            "revocation": "unknown",
            "safeScan": "not_requested",
        },
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

    evidence = Evidence(
        id=ev_id,
        assessment_id=assessment_id,
        agent_run_id=agent_run_id,
        kind=EvidenceKind.CERTIFICATE.value,
        source_uri="https://example.com",
        content_hash="mock_hash_123",
        storage_ref="mock_storage_ref",
        collected_at=now,
        collector_version="2026-1",
        redaction_version="1.0",
        retention_until=now + timedelta(days=30),
    )
    db_session.add(evidence)

    finding = Finding(
        id=finding_id,
        assessment_id=assessment_id,
        agent_run_id=agent_run_id,
        type="certificate.revocation_unknown",
        severity="medium",
        confidence=0.7,
        status="active",
        asset="https://example.com",
        summary="Revocation Unknown",
        rule_version="2026-1",
        observed_at=now,
    )
    finding.evidence_items.append(evidence)
    db_session.add(finding)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            f"/v1/assessments/{assessment_id}",
            headers={"X-Tenant-ID": str(tenant_id)},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["assessmentId"] == str(assessment_id)
        assert len(data["findings"]) == 1
        assert str(ev_id) in data["findings"][0]["evidenceIds"]
        assert data["checks"]["revocation"] == "unknown"


@pytest.mark.asyncio
async def test_evidence_endpoints_authorized_and_path_concealed(db_session, tmp_path, monkeypatch):
    """Test GET /v1/evidence/{id} and GET /v1/evidence/{id}/artifact return data without paths."""
    store_dir = tmp_path / "evidence_store"
    monkeypatch.setattr(settings, "evidence_storage_path", store_dir)

    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    agent_run_id = uuid.uuid4()

    now = datetime.now(timezone.utc)
    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=uuid.uuid4(),
        submitted_url="https://example.com",
        normalized_url="https://example.com",
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

    # Store real artifact bytes via EvidenceStore
    store = EvidenceStore(store_dir)
    from app.core.evidence_store import EvidenceMetadata
    meta = EvidenceMetadata(source_uri="https://example.com", collector_version="2026-1")
    artifact_payload = {"evidence_id": str(ev_id), "redacted": True, "details": "sanitized_content"}
    stored = await store.store(json.dumps(artifact_payload).encode("utf-8"), meta)

    evidence = Evidence(
        id=ev_id,
        assessment_id=assessment_id,
        agent_run_id=agent_run_id,
        kind=EvidenceKind.CERTIFICATE.value,
        source_uri="https://example.com",
        content_hash=stored.content_hash,
        storage_ref=stored.storage_ref,
        collected_at=now,
        collector_version="2026-1",
        redaction_version="1.0",
        retention_until=now + timedelta(days=30),
    )
    db_session.add(evidence)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Metadata endpoint
        resp = await client.get(
            f"/v1/evidence/{ev_id}",
            headers={"X-Tenant-ID": str(tenant_id)},
        )
        assert resp.status_code == 200
        meta_data = resp.json()
        assert meta_data["evidenceId"] == str(ev_id)
        assert meta_data["contentHash"] == stored.content_hash
        assert meta_data["artifactUrl"] == f"/v1/evidence/{ev_id}/artifact"
        assert meta_data["redacted"] is True
        # Ensure filesystem path is never exposed in metadata
        assert "storage_ref" not in meta_data
        assert "storageRef" not in meta_data
        assert str(store_dir) not in json.dumps(meta_data)

        # 2. Artifact download endpoint
        art_resp = await client.get(
            f"/v1/evidence/{ev_id}/artifact",
            headers={"X-Tenant-ID": str(tenant_id)},
        )
        assert art_resp.status_code == 200
        assert art_resp.headers["content-disposition"] == f'attachment; filename="evidence-{ev_id}.json"'
        assert art_resp.headers["cache-control"] == "no-store"
        downloaded = art_resp.json()
        assert downloaded["details"] == "sanitized_content"
        # Ensure filesystem path is never exposed in artifact headers
        for h_key, h_val in art_resp.headers.items():
            assert str(store_dir) not in h_val


@pytest.mark.asyncio
async def test_evidence_cross_tenant_access_rejected(db_session):
    """Test that accessing evidence belonging to another tenant returns 403 EVIDENCE_FORBIDDEN."""
    tenant_owner = uuid.uuid4()
    tenant_attacker = uuid.uuid4()
    assessment_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    agent_run_id = uuid.uuid4()

    now = datetime.now(timezone.utc)
    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_owner,
        scope_id=uuid.uuid4(),
        submitted_url="https://victim.example",
        normalized_url="https://victim.example",
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

    evidence = Evidence(
        id=ev_id,
        assessment_id=assessment_id,
        agent_run_id=agent_run_id,
        kind=EvidenceKind.CERTIFICATE.value,
        source_uri="https://victim.example",
        content_hash="mock_hash_victim",
        storage_ref="mock_storage_victim",
        collected_at=now,
        collector_version="2026-1",
        redaction_version="1.0",
        retention_until=now + timedelta(days=30),
    )
    db_session.add(evidence)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Cross-tenant GET metadata
        resp_meta = await client.get(
            f"/v1/evidence/{ev_id}",
            headers={"X-Tenant-ID": str(tenant_attacker)},
        )
        assert resp_meta.status_code == 403
        data_meta = resp_meta.json()
        assert data_meta["error"]["code"] == ErrorCode.EVIDENCE_FORBIDDEN

        # Cross-tenant GET artifact
        resp_art = await client.get(
            f"/v1/evidence/{ev_id}/artifact",
            headers={"X-Tenant-ID": str(tenant_attacker)},
        )
        assert resp_art.status_code == 403
        data_art = resp_art.json()
        assert data_art["error"]["code"] == ErrorCode.EVIDENCE_FORBIDDEN


@pytest.mark.asyncio
async def test_evidence_nonexistent_returns_404(db_session):
    """Test that nonexistent evidence returns 404 NOT_FOUND."""
    random_ev_id = uuid.uuid4()
    caller_tenant = uuid.uuid4()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp_meta = await client.get(
            f"/v1/evidence/{random_ev_id}",
            headers={"X-Tenant-ID": str(caller_tenant)},
        )
        assert resp_meta.status_code == 404
        assert resp_meta.json()["error"]["code"] == ErrorCode.NOT_FOUND

        resp_art = await client.get(
            f"/v1/evidence/{random_ev_id}/artifact",
            headers={"X-Tenant-ID": str(caller_tenant)},
        )
        assert resp_art.status_code == 404
        assert resp_art.json()["error"]["code"] == ErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_evidence_retention_expiry_enforced(db_session):
    """Test that evidence past its retention deadline is rejected with 404."""
    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    agent_run_id = uuid.uuid4()

    now = datetime.now(timezone.utc)
    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=uuid.uuid4(),
        submitted_url="https://expired.example",
        normalized_url="https://expired.example",
        status=AssessmentStatus.COMPLETED.value,
    )
    db_session.add(assessment)

    agent_run = AgentRun(
        id=agent_run_id,
        assessment_id=assessment_id,
        agent_name="certificate-intelligence",
        status=AgentRunStatus.COMPLETED.value,
        started_at=now - timedelta(days=40),
    )
    db_session.add(agent_run)

    # retention_until was 5 days ago (expired)
    evidence = Evidence(
        id=ev_id,
        assessment_id=assessment_id,
        agent_run_id=agent_run_id,
        kind=EvidenceKind.CERTIFICATE.value,
        source_uri="https://expired.example",
        content_hash="mock_expired_hash",
        storage_ref="mock_expired_storage_ref",
        collected_at=now - timedelta(days=40),
        collector_version="2026-1",
        redaction_version="1.0",
        retention_until=now - timedelta(days=5),
    )
    db_session.add(evidence)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp_meta = await client.get(
            f"/v1/evidence/{ev_id}",
            headers={"X-Tenant-ID": str(tenant_id)},
        )
        assert resp_meta.status_code == 404
        assert resp_meta.json()["error"]["code"] == ErrorCode.NOT_FOUND

        resp_art = await client.get(
            f"/v1/evidence/{ev_id}/artifact",
            headers={"X-Tenant-ID": str(tenant_id)},
        )
        assert resp_art.status_code == 404
        assert resp_art.json()["error"]["code"] == ErrorCode.NOT_FOUND
