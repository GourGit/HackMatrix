"""Focused tests for authorization boundaries and scope validation."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from app.api.deps import get_db
from app.core.errors import ErrorCode, SafeScanNotAllowedError, UnauthorizedScopeError
from app.core.scope_validator import match_target, validate_scope_authorization
from app.main import create_app
from app.middleware.rate_limit import limiter
from app.models.authorization import AuthorizationScope
from app.schemas.common import ScopeStatus


@pytest.fixture(autouse=True)
def disable_rate_limit():
    limiter.enabled = False
    yield
    limiter.enabled = True


def test_match_target_exact_and_wildcard():
    allowed = ["https://example.com/login", "*.trustlens.security", "api.target.test"]

    assert match_target("https://example.com/login?foo=bar", allowed) is True
    assert match_target("https://example.com/login/subpath", allowed) is True
    assert match_target("https://sub.trustlens.security/path", allowed) is True
    assert match_target("https://trustlens.security/", allowed) is True
    assert match_target("https://api.target.test/v1", allowed) is True

    # Rejection cases:
    # 1. Evil/deceptive hosts
    assert match_target("https://evil.com/login", allowed) is False
    assert match_target("https://example.com.evil.com/login", allowed) is False
    # 2. Path not at segment boundary (/login vs /login-admin)
    assert match_target("https://example.com/login-admin", allowed) is False
    # 3. Mismatched scheme or port
    assert match_target("http://example.com/login", allowed) is False
    assert match_target("https://example.com:8443/login", allowed) is False
    # 4. Malformed port in target or pattern
    assert match_target("https://example.com:invalid_port/login", allowed) is False
    assert match_target("https://example.com/login", ["https://example.com:badport/login"]) is False


def test_validate_scope_expired():
    now = datetime.now(timezone.utc)
    scope = AuthorizationScope(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        targets_json=["https://example.com"],
        valid_from=now - timedelta(days=10),
        valid_until=now - timedelta(days=1),
        status=ScopeStatus.ACTIVE.value,
    )
    with pytest.raises(UnauthorizedScopeError, match="expired"):
        validate_scope_authorization(scope, "https://example.com", False, [])


def test_validate_scope_revoked():
    now = datetime.now(timezone.utc)
    scope = AuthorizationScope(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        targets_json=["https://example.com"],
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        status=ScopeStatus.REVOKED.value,
    )
    with pytest.raises(UnauthorizedScopeError, match="not active"):
        validate_scope_authorization(scope, "https://example.com", False, [])


def test_validate_scope_unauthorized_target():
    now = datetime.now(timezone.utc)
    scope = AuthorizationScope(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        targets_json=["https://allowed.com"],
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        status=ScopeStatus.ACTIVE.value,
    )
    with pytest.raises(UnauthorizedScopeError, match="not permitted"):
        validate_scope_authorization(scope, "https://not-allowed.com", False, [])


def test_validate_scope_unauthorized_safe_scan_ports():
    now = datetime.now(timezone.utc)
    scope = AuthorizationScope(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        targets_json=["https://allowed.com"],
        allowed_ports_json=[80, 443],
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        status=ScopeStatus.ACTIVE.value,
    )
    # 8080 is not authorized
    with pytest.raises(SafeScanNotAllowedError, match="exceed scope-approved"):
        validate_scope_authorization(scope, "https://allowed.com", True, [80, 8080])

    # 80 and 443 are authorized
    validate_scope_authorization(scope, "https://allowed.com", True, [80, 443])


@pytest.mark.asyncio
async def test_api_missing_authorization_returns_422(db_session):
    """Submitting an assessment without an 'authorization' object must return 422."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/v1/assessments",
            headers={"Authorization": "Bearer dev-token"},
            json={
                "url": "https://example.com",
            },
        )
        assert res.status_code == 422
        data = res.json()
        assert data["error"]["code"] == ErrorCode.VALIDATION_ERROR


@pytest.mark.asyncio
async def test_api_missing_attested_returns_422(db_session):
    """Submitting an assessment with authorization missing 'attested' must return 422."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/v1/assessments",
            headers={"Authorization": "Bearer dev-token"},
            json={
                "url": "https://example.com",
                "authorization": {},
            },
        )
        assert res.status_code == 422
        data = res.json()
        assert data["error"]["code"] == ErrorCode.VALIDATION_ERROR


@pytest.mark.asyncio
async def test_api_attested_false_is_rejected(db_session):
    """Submitting an assessment with attested=false must be rejected with 403."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/v1/assessments",
            headers={"Authorization": "Bearer dev-token"},
            json={
                "url": "https://example.com",
                "authorization": {"attested": False},
            },
        )
        assert res.status_code == 403
        data = res.json()
        assert data["error"]["code"] == ErrorCode.UNAUTHORIZED_SCOPE
        assert "attestation is required" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_api_explicit_attested_true_permits_passive_without_scope(db_session):
    """Explicitly providing attested=true allows passive assessment without a scope_id."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("app.api.v1.assessments._run_orchestration_background", AsyncMock()):
            res = await client.post(
                "/v1/assessments",
                headers={"Authorization": "Bearer dev-token"},
                json={
                    "url": "https://example.com",
                    "authorization": {"attested": True},
                    "safeScan": {"enabled": False},
                },
            )
            assert res.status_code == 202
            data = res.json()
            assert data["status"] == "queued"
            assert data["scopeId"] is None


@pytest.mark.asyncio
async def test_api_active_scan_without_scope_is_rejected(db_session):
    """Requesting active safe scan without an authorized scope is rejected with 403."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/v1/assessments",
            headers={"Authorization": "Bearer dev-token"},
            json={
                "url": "https://example.com",
                "authorization": {"attested": True},
                "safeScan": {"enabled": True, "ports": [443]},
            },
        )
        assert res.status_code == 403
        data = res.json()
        assert data["error"]["code"] == ErrorCode.UNAUTHORIZED_SCOPE
        assert "explicit authorized scope" in data["error"]["message"]

