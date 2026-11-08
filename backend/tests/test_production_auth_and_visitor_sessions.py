"""Tests for production authentication, anonymous visitor sessions, and scope boundaries.

Verifies:
1. Anonymous visitor session issuance (POST /v1/auth/anonymous) with valid JWTs and UUIDs.
2. JWT signature validation, claim integrity, and expiration handling.
3. Visitors can submit and view passive assessments without a pre-registered scope.
4. Active safe scanning strictly requires an explicit, active, and matching authorized scope.
5. Strict tenant isolation: one visitor cannot view or modify another visitor's assessments.
6. Production authentication enforcement: rejects missing tokens, dev-tokens, and spoofed headers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import jwt
import pytest
from fastapi import HTTPException

from app.api.deps import get_db
from app.config import settings
from app.core.auth import _get_signing_secret, create_visitor_token, verify_token
from app.main import create_app
from app.middleware.rate_limit import limiter
from app.schemas.common import AssessmentStatus


@pytest.fixture(autouse=True)
def disable_rate_limit():
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.mark.asyncio
async def test_anonymous_session_issuance(db_session):
    """POST /v1/auth/anonymous issues a valid signed JWT and unique tenant/subject IDs."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # First visitor
        res1 = await client.post("/v1/auth/anonymous")
        assert res1.status_code == 201, res1.text
        data1 = res1.json()
        assert "accessToken" in data1
        assert data1["tokenType"] == "Bearer"
        assert data1["expiresIn"] == 86400
        tenant1 = uuid.UUID(data1["tenantId"])
        subject1 = uuid.UUID(data1["subjectId"])

        # Second visitor
        res2 = await client.post("/v1/auth/anonymous")
        assert res2.status_code == 201
        data2 = res2.json()
        tenant2 = uuid.UUID(data2["tenantId"])
        subject2 = uuid.UUID(data2["subjectId"])

        # Every visitor gets an isolated tenant and subject
        assert tenant1 != tenant2
        assert subject1 != subject2


def test_jwt_claims_and_signature_verification():
    """Verify cryptographic signing, claim validation, and expiration checks."""
    tenant_id = uuid.uuid4()
    subject_id = uuid.uuid4()

    token, expires_at, lifetime = create_visitor_token(tenant_id, subject_id, lifetime_seconds=3600)
    identity = verify_token(token)

    assert identity.tenant_id == tenant_id
    assert identity.subject_id == subject_id
    assert identity.is_admin is False

    # Tampered token should fail
    tampered = token[:-4] + "abcd"
    with pytest.raises(HTTPException) as exc_tampered:
        verify_token(tampered)
    assert exc_tampered.value.status_code == 401
    assert "Invalid token signature" in exc_tampered.value.detail

    # Expired token should fail
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": str(subject_id),
        "tenant_id": str(tenant_id),
        "type": "visitor",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int((now - timedelta(hours=2)).timestamp()),
        "exp": int((now - timedelta(hours=1)).timestamp()),
    }
    expired_token = jwt.encode(expired_payload, _get_signing_secret(), algorithm="HS256")
    with pytest.raises(HTTPException) as exc_expired:
        verify_token(expired_token)
    assert exc_expired.value.status_code == 401
    assert "Token has expired" in exc_expired.value.detail


@pytest.mark.asyncio
async def test_visitor_can_submit_and_view_passive_assessment(db_session):
    """A visitor can submit a passive website assessment without pre-registered scope."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("app.api.v1.assessments._run_orchestration_background", AsyncMock()):
            # 1. Obtain anonymous session
            auth_res = await client.post("/v1/auth/anonymous")
            assert auth_res.status_code == 201
            auth_data = auth_res.json()
            token = auth_data["accessToken"]
            headers = {"Authorization": f"Bearer {token}"}

            # 2. Submit passive assessment
            post_res = await client.post(
                "/v1/assessments",
                headers=headers,
                json={
                    "url": "https://example.com",
                    "authorization": {"attested": True},
                    "safeScan": {"enabled": False},
                },
            )
            assert post_res.status_code == 202, post_res.text
            post_data = post_res.json()
            assessment_id = post_data["assessmentId"]
            assert post_data["status"] == "queued"
            assert post_data["scopeId"] is None

            # 3. Retrieve assessment
            get_res = await client.get(f"/v1/assessments/{assessment_id}", headers=headers)
            assert get_res.status_code == 200, get_res.text
            get_data = get_res.json()
            assert get_data["assessmentId"] == assessment_id
            assert get_data["target"] == "https://example.com/"


@pytest.mark.asyncio
async def test_tenant_isolation_between_visitors(db_session):
    """Assessments submitted by Visitor A cannot be accessed by Visitor B."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("app.api.v1.assessments._run_orchestration_background", AsyncMock()):
            # Visitor A session
            res_a = await client.post("/v1/auth/anonymous")
            token_a = res_a.json()["accessToken"]

            # Visitor B session
            res_b = await client.post("/v1/auth/anonymous")
            token_b = res_b.json()["accessToken"]

            # Visitor A submits assessment
            create_res = await client.post(
                "/v1/assessments",
                headers={"Authorization": f"Bearer {token_a}"},
                json={
                    "url": "https://visitor-a-target.test",
                    "authorization": {"attested": True},
                },
            )
            assert create_res.status_code == 202
            assessment_id = create_res.json()["assessmentId"]

            # Visitor B attempts to view Visitor A's assessment -> 404 (isolated)
            b_view_res = await client.get(
                f"/v1/assessments/{assessment_id}",
                headers={"Authorization": f"Bearer {token_b}"},
            )
            assert b_view_res.status_code == 404


@pytest.mark.asyncio
async def test_safe_scan_strictly_requires_authorized_scope(db_session):
    """Safe surface scanning without scope is forbidden; valid scope allows safe scanning."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("app.api.v1.assessments._run_orchestration_background", AsyncMock()):
            auth_res = await client.post("/v1/auth/anonymous")
            token = auth_res.json()["accessToken"]
            headers = {"Authorization": f"Bearer {token}"}

            # 1. Active safe scan requested WITHOUT scope -> 403 Forbidden
            denied_res = await client.post(
                "/v1/assessments",
                headers=headers,
                json={
                    "url": "https://target.test",
                    "authorization": {"attested": True},
                    "safeScan": {"enabled": True, "ports": [443]},
                },
            )
            assert denied_res.status_code == 403
            assert "explicit authorized scope" in denied_res.json()["error"]["message"]

            # 2. Create scope for target
            scope_res = await client.post(
                "/v1/scopes",
                headers=headers,
                json={
                    "targets": ["https://target.test"],
                    "allowedPorts": [443, 8443],
                    "attestation": "Authorized owner of target.test",
                },
            )
            assert scope_res.status_code == 201
            scope_id = scope_res.json()["id"]

            # 3. Active safe scan WITH matching scope -> 202 Accepted
            allowed_res = await client.post(
                "/v1/assessments",
                headers=headers,
                json={
                    "url": "https://target.test",
                    "authorization": {"attested": True, "scopeId": scope_id},
                    "safeScan": {"enabled": True, "ports": [443]},
                },
            )
            assert allowed_res.status_code == 202
            assert allowed_res.json()["scopeId"] == scope_id


@pytest.mark.asyncio
async def test_production_mode_auth_enforcement(db_session, monkeypatch):
    """In production mode, missing tokens, dev-tokens, and spoofed headers are rejected."""
    monkeypatch.setattr(settings, "app_env", "production")

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. No Authorization header in production -> 401
        res_no_auth = await client.get("/v1/assessments/00000000-0000-0000-0000-000000000000")
        assert res_no_auth.status_code == 401

        # 2. dev-token in production -> 401
        res_dev_token = await client.get(
            "/v1/assessments/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": "Bearer dev-token"},
        )
        assert res_dev_token.status_code == 401
        assert "Development tokens are not permitted in production" in res_dev_token.json()["error"]["message"]

        # 3. Spoofed X-Tenant-ID header without token in production -> 401
        res_spoof = await client.get(
            "/v1/assessments/00000000-0000-0000-0000-000000000000",
            headers={"X-Tenant-ID": str(uuid.uuid4())},
        )
        assert res_spoof.status_code == 401

        # 4. Valid JWT in production -> successfully passes auth (reaches endpoint logic)
        auth_res = await client.post("/v1/auth/anonymous")
        assert auth_res.status_code == 201
        valid_token = auth_res.json()["accessToken"]

        res_valid = await client.get(
            "/v1/assessments/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        # Should NOT be 401; it reaches the route and returns 404 because ID doesn't exist
        assert res_valid.status_code == 404
