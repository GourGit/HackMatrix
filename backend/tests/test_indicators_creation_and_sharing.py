"""Tests for indicator creation, normalization, evidence validation, and sharing policies.

Verifies:
1. Valid indicator creation across all types (URL, domain, IP, email, hash, cert fingerprint).
2. Normalization to canonical forms in value_normalized.
3. Rejection of malformed indicator values.
4. Duplicate handling and deduplication without redundant database rows.
5. Evidence ownership validation (rejecting foreign or nonexistent evidence with 403 EVIDENCE_FORBIDDEN).
6. Community publication gating: unreviewed community indicators are hidden from other tenants.
7. Tenant isolation: private and tenant-only indicators are never exposed across tenants.
8. Sharing policy query filtering.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import func, select

from app.api.deps import get_db
from app.core.errors import ErrorCode
from app.main import create_app
from app.middleware.rate_limit import limiter
from app.models.agent_run import AgentRun
from app.models.assessment import Assessment
from app.models.evidence import Evidence
from app.models.indicator import Indicator
from app.schemas.common import (
    AgentRunStatus,
    AssessmentStatus,
    EvidenceKind,
    IndicatorType,
    ReviewStatus,
    SharingPolicy,
)


@pytest.fixture(autouse=True)
def disable_rate_limit():
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.mark.asyncio
async def test_valid_indicator_creation_all_types(db_session):
    """Test valid creation and canonical normalization of all supported indicator types."""
    tenant_id = uuid.uuid4()
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    test_cases = [
        (
            IndicatorType.URL,
            "https://EVIL.EXAMPLE.com:443/login?phish=1#section",
            "https://evil.example.com/login?phish=1",
        ),
        (
            IndicatorType.DOMAIN,
            "SUB.EVIL-DOMAIN.co.uk.",
            "sub.evil-domain.co.uk",
        ),
        (
            IndicatorType.IP,
            "2001:0db8:0000:0000:0000:ff00:0042:8329",
            "2001:db8::ff00:42:8329",
        ),
        (
            IndicatorType.EMAIL,
            "BadActor.Test@PHISHING.COM",
            "badactor.test@phishing.com",
        ),
        (
            IndicatorType.HASH,
            "44D8:8612:FEA8:A8F3:6DE8:2E12:78AB:B02F",
            "44d88612fea8a8f36de82e1278abb02f",
        ),
        (
            IndicatorType.CERTIFICATE_FINGERPRINT,
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
            "aabbccddeeff00112233445566778899aabbccdd",
        ),
    ]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for ind_type, raw_val, expected_norm in test_cases:
            resp = await client.post(
                "/v1/indicators",
                headers={"X-Tenant-ID": str(tenant_id)},
                json={
                    "value": raw_val,
                    "type": ind_type.value,
                    "confidence": 0.85,
                    "sharingPolicy": "private",
                    "source": "manual-test",
                },
            )
            assert resp.status_code == 201, f"Failed for {ind_type}: {resp.text}"
            data = resp.json()
            assert "indicatorId" in data
            assert data["status"] == ReviewStatus.PENDING_REVIEW.value

            # Verify in DB
            ind_uuid = uuid.UUID(data["indicatorId"])
            stmt = select(Indicator).where(Indicator.id == ind_uuid)
            ind_row = (await db_session.execute(stmt)).scalar_one()

            assert ind_row.type == ind_type.value
            assert ind_row.value_normalized == expected_norm
            assert ind_row.confidence == 0.85
            assert ind_row.sharing_policy == SharingPolicy.PRIVATE.value
            assert ind_row.review_status == ReviewStatus.PENDING_REVIEW.value
            assert ind_row.tenant_id == tenant_id


@pytest.mark.asyncio
async def test_malformed_input_rejection(db_session):
    """Test that malformed indicator values and invalid types are rejected with 422."""
    tenant_id = uuid.uuid4()
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    malformed_cases = [
        {"type": "ip", "value": "999.999.999.999", "confidence": 0.5},
        {"type": "ip", "value": "not-an-ip", "confidence": 0.5},
        {"type": "url", "value": "ftp://unsupported-scheme.com", "confidence": 0.5},
        {"type": "url", "value": "http://user:pass@evil.com", "confidence": 0.5},
        {"type": "url", "value": "no-scheme.com", "confidence": 0.5},
        {"type": "domain", "value": "evil domain with spaces", "confidence": 0.5},
        {"type": "domain", "value": "evil/path", "confidence": 0.5},
        {"type": "domain", "value": "singlelabel", "confidence": 0.5},
        {"type": "email", "value": "not-an-email", "confidence": 0.5},
        {"type": "email", "value": "@missing-local.com", "confidence": 0.5},
        {"type": "hash", "value": "not_hex_chars_1234567890abcdefgh", "confidence": 0.5},
        {"type": "hash", "value": "12345", "confidence": 0.5},  # too short
        {"type": "certificate_fingerprint", "value": "too_short", "confidence": 0.5},
        {"type": "domain", "value": "example.com", "confidence": 1.5},  # confidence > 1.0
        {"type": "domain", "value": "example.com", "confidence": -0.1},  # confidence < 0.0
        {"type": "unknown_type", "value": "example.com", "confidence": 0.5},  # unknown type
    ]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for case in malformed_cases:
            resp = await client.post(
                "/v1/indicators",
                headers={"X-Tenant-ID": str(tenant_id)},
                json=case,
            )
            assert resp.status_code == 422, f"Expected 422 for case {case}, got {resp.status_code}"
            assert resp.json()["error"]["code"] == ErrorCode.VALIDATION_ERROR


@pytest.mark.asyncio
async def test_duplicate_indicator_handling(db_session):
    """Test that submitting duplicate indicators for the same tenant is deduplicated."""
    tenant_id = uuid.uuid4()
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # First submission
        resp1 = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_id)},
            json={
                "value": "https://duplicate-test.com/login",
                "type": "url",
                "confidence": 0.5,
                "sharingPolicy": "private",
            },
        )
        assert resp1.status_code == 201
        ind_id_1 = resp1.json()["indicatorId"]

        # Second submission with different formatting (uppercase scheme/host, trailing slash)
        resp2 = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_id)},
            json={
                "value": "HTTPS://DUPLICATE-TEST.COM:443/login",
                "type": "url",
                "confidence": 0.9,  # higher confidence
                "sharingPolicy": "private",
            },
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["indicatorId"] == ind_id_1
        assert data2["isDuplicate"] is True

        # Verify only 1 row exists in DB and confidence was updated to 0.9
        count_stmt = select(func.count()).select_from(Indicator).where(Indicator.tenant_id == tenant_id)
        count = (await db_session.execute(count_stmt)).scalar_one()
        assert count == 1

        ind_stmt = select(Indicator).where(Indicator.id == uuid.UUID(ind_id_1))
        ind_row = (await db_session.execute(ind_stmt)).scalar_one()
        assert ind_row.confidence == 0.9


@pytest.mark.asyncio
async def test_evidence_access_denial(db_session):
    """Test evidence ownership validation: unauthorized evidence is rejected with 403."""
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
        agent_name="threat-intel",
        status=AgentRunStatus.COMPLETED.value,
        started_at=now,
    )
    db_session.add(agent_run)

    evidence = Evidence(
        id=ev_id,
        assessment_id=assessment_id,
        agent_run_id=agent_run_id,
        kind=EvidenceKind.PROVIDER_RESULT.value,
        source_uri="https://victim.example",
        content_hash="mock_hash_owner",
        storage_ref="mock_storage_owner",
        collected_at=now,
        collector_version="2026-1",
        redaction_version="1.0",
    )
    db_session.add(evidence)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Attacker tenant tries to link owner's evidence
        resp_foreign = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_attacker)},
            json={
                "value": "malicious-domain.com",
                "type": "domain",
                "confidence": 0.8,
                "evidenceIds": [str(ev_id)],
            },
        )
        assert resp_foreign.status_code == 403
        assert resp_foreign.json()["error"]["code"] == ErrorCode.EVIDENCE_FORBIDDEN

        # 2. Non-existent evidence ID
        random_ev_id = uuid.uuid4()
        resp_nonexistent = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_attacker)},
            json={
                "value": "malicious-domain.com",
                "type": "domain",
                "confidence": 0.8,
                "evidenceIds": [str(random_ev_id)],
            },
        )
        assert resp_nonexistent.status_code == 403
        assert resp_nonexistent.json()["error"]["code"] == ErrorCode.EVIDENCE_FORBIDDEN

        # 3. Legitimate owner links their evidence
        resp_owner = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_owner)},
            json={
                "value": "malicious-domain.com",
                "type": "domain",
                "confidence": 0.8,
                "evidenceIds": [str(ev_id)],
            },
        )
        assert resp_owner.status_code == 201
        ind_id = uuid.UUID(resp_owner.json()["indicatorId"])
        ind_row = (await db_session.execute(select(Indicator).where(Indicator.id == ind_id))).scalar_one()
        assert ind_row.source_evidence_id == ev_id


@pytest.mark.asyncio
async def test_community_publication_requires_review(db_session):
    """Test that community publication requires review before being visible to other tenants."""
    tenant_creator = uuid.uuid4()
    tenant_viewer = uuid.uuid4()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Creator submits indicator with sharingPolicy = community
        resp = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_creator)},
            json={
                "value": "community-phish.com",
                "type": "domain",
                "confidence": 0.9,
                "sharingPolicy": "community",
            },
        )
        assert resp.status_code == 201
        ind_id = uuid.UUID(resp.json()["indicatorId"])

        # Verify review_status is pending_review
        ind_row = (await db_session.execute(select(Indicator).where(Indicator.id == ind_id))).scalar_one()
        assert ind_row.review_status == ReviewStatus.PENDING_REVIEW.value

        # Viewer tenant queries community indicators -> MUST NOT see unreviewed community indicator
        viewer_resp1 = await client.get(
            "/v1/indicators?sharingPolicy=community",
            headers={"X-Tenant-ID": str(tenant_viewer)},
        )
        assert viewer_resp1.status_code == 200
        items1 = viewer_resp1.json()["items"]
        assert all(item["indicatorId"] != str(ind_id) for item in items1)

        # Creator tenant queries their own indicators -> DOES see pending indicator
        creator_resp = await client.get(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_creator)},
        )
        assert creator_resp.status_code == 200
        creator_items = creator_resp.json()["items"]
        assert any(item["indicatorId"] == str(ind_id) for item in creator_items)

        # Now simulate review approval
        ind_row.review_status = ReviewStatus.REVIEWED.value
        await db_session.commit()

        # Viewer tenant queries community indicators again -> NOW DOES see reviewed indicator
        viewer_resp2 = await client.get(
            "/v1/indicators?sharingPolicy=community",
            headers={"X-Tenant-ID": str(tenant_viewer)},
        )
        assert viewer_resp2.status_code == 200
        items2 = viewer_resp2.json()["items"]
        assert any(item["indicatorId"] == str(ind_id) for item in items2)


@pytest.mark.asyncio
async def test_tenant_isolation_and_sharing_policy_filtering(db_session):
    """Test that private and tenant-only indicators are never exposed to other tenants."""
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Tenant A creates:
        # 1. Private indicator
        r_priv = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_a)},
            json={"value": "tenant-a-private.com", "type": "domain", "confidence": 0.8, "sharingPolicy": "private"},
        )
        priv_id = r_priv.json()["indicatorId"]

        # 2. Tenant-only indicator
        r_tenant = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_a)},
            json={"value": "tenant-a-tenantonly.com", "type": "domain", "confidence": 0.8, "sharingPolicy": "tenant"},
        )
        tenant_id_ind = r_tenant.json()["indicatorId"]

        # 3. Community indicator (and mark reviewed)
        r_comm = await client.post(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_a)},
            json={"value": "tenant-a-community.com", "type": "domain", "confidence": 0.8, "sharingPolicy": "community"},
        )
        comm_id = uuid.UUID(r_comm.json()["indicatorId"])
        comm_row = (await db_session.execute(select(Indicator).where(Indicator.id == comm_id))).scalar_one()
        comm_row.review_status = ReviewStatus.REVIEWED.value
        await db_session.commit()

        # Tenant B queries all indicators
        b_all = await client.get(
            "/v1/indicators",
            headers={"X-Tenant-ID": str(tenant_b)},
        )
        assert b_all.status_code == 200
        b_all_ids = [item["indicatorId"] for item in b_all.json()["items"]]
        assert priv_id not in b_all_ids, "Private indicator leaked to other tenant!"
        assert tenant_id_ind not in b_all_ids, "Tenant-only indicator leaked to other tenant!"
        assert str(comm_id) in b_all_ids, "Reviewed community indicator should be visible"

        # Tenant B queries with sharingPolicy=private
        b_priv = await client.get(
            "/v1/indicators?sharingPolicy=private",
            headers={"X-Tenant-ID": str(tenant_b)},
        )
        assert b_priv.status_code == 200
        assert len(b_priv.json()["items"]) == 0

        # Tenant B queries with sharingPolicy=tenant
        b_ten = await client.get(
            "/v1/indicators?sharingPolicy=tenant",
            headers={"X-Tenant-ID": str(tenant_b)},
        )
        assert b_ten.status_code == 200
        assert len(b_ten.json()["items"]) == 0

        # Tenant A queries with sharingPolicy=private
        a_priv = await client.get(
            "/v1/indicators?sharingPolicy=private",
            headers={"X-Tenant-ID": str(tenant_a)},
        )
        assert a_priv.status_code == 200
        a_priv_ids = [item["indicatorId"] for item in a_priv.json()["items"]]
        assert priv_id in a_priv_ids
        assert tenant_id_ind not in a_priv_ids
        assert str(comm_id) not in a_priv_ids
