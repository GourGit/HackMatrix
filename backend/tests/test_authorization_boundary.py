"""Focused tests for authorization boundaries and scope validation."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from app.core.errors import SafeScanNotAllowedError, UnauthorizedScopeError
from app.core.scope_validator import match_target, validate_scope_authorization
from app.models.authorization import AuthorizationScope
from app.schemas.common import ScopeStatus


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

