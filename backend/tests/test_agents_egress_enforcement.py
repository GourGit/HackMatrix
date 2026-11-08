"""Tests ensuring that all security agents pass exclusively through the safe egress layer."""

from unittest.mock import AsyncMock
import pytest
from app.agents.base import AgentExecutionContext
from app.agents.certificate_intel import CertificateIntelAgent
from app.agents.phishing_brand import PhishingBrandAgent
from app.agents.privacy_software import PrivacySoftwareAgent
from app.agents.safe_surface import SafeSurfaceAgent
from app.agents.url_redirect import UrlRedirectAgent
from app.core.egress import SafeHttpResponse, SafeTlsObservation
from app.schemas.common import EvidenceKind
import uuid
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_url_redirect_agent_uses_egress(monkeypatch):
    agent = UrlRedirectAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com/start",
        normalized_url="https://example.com/start",
    )

    calls = []
    async def mock_fetch_url(url, follow_redirects=False):
        calls.append(url)
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"OK",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
            redirect_location=None,
        )

    monkeypatch.setattr("app.agents.url_redirect.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert len(calls) == 1
    assert calls[0] == "https://example.com/start"
    assert res.status.value == "completed"


@pytest.mark.asyncio
async def test_phishing_agent_uses_egress(monkeypatch):
    agent = PhishingBrandAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com/login",
        normalized_url="https://example.com/login",
    )

    calls = []
    async def mock_fetch_url(url, follow_redirects=True):
        calls.append(url)
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"<html><form><input type='password' name='pwd'/></form></html>",
            elapsed_ms=15,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.phishing_brand.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert len(calls) == 1
    assert calls[0] == "https://example.com/login"
    assert res.status.value == "completed"
    assert any("credential_harvesting_form" in f.type for f in res.findings)


@pytest.mark.asyncio
async def test_certificate_agent_uses_egress(monkeypatch):
    agent = CertificateIntelAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    calls = []
    async def mock_probe_tls(hostname, port):
        calls.append((hostname, port))
        return SafeTlsObservation(
            hostname=hostname,
            peer_ip="93.184.216.34",
            port=port,
            subject="CN=example.com",
            issuer="CN=DigiCert",
            not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            san_list=["example.com"],
            has_sct=True,
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_size=2048,
            raw_der=b"mock_der",
        )

    monkeypatch.setattr("app.agents.certificate_intel.default_egress.probe_tls", mock_probe_tls)
    res = await agent.run(ctx)

    assert len(calls) == 1
    assert calls[0] == ("example.com", 443)
    assert res.status.value == "completed"
    assert res.check_availability.get("ct") == "passed"


@pytest.mark.asyncio
async def test_safe_surface_agent_uses_egress_and_strictly_bounds_ports(monkeypatch):
    agent = SafeSurfaceAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
        safe_scan_enabled=True,
        safe_scan_ports=[8443],
    )

    probe_calls = []
    async def mock_probe_tcp_port(hostname, port, approved_ports):
        probe_calls.append((hostname, port, approved_ports))
        return True

    async def mock_fetch_url(url, method="GET"):
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={"server": "Apache/2.4.52"},
            body=b"",
            elapsed_ms=5,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.safe_surface.default_egress.probe_tcp_port", mock_probe_tcp_port)
    monkeypatch.setattr("app.agents.safe_surface.default_egress.fetch_url", mock_fetch_url)

    res = await agent.run(ctx)

    assert len(probe_calls) == 1
    assert probe_calls[0] == ("example.com", 8443, [8443])
    assert res.status.value == "completed"


@pytest.mark.asyncio
async def test_privacy_software_agent_uses_egress(monkeypatch):
    agent = PrivacySoftwareAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    calls = []
    async def mock_fetch_url(url, follow_redirects=True):
        calls.append(url)
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
            },
            body=b"<html><body>Clean</body></html>",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.privacy_software.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert len(calls) == 1
    assert calls[0] == "https://example.com"
    assert res.status.value == "completed"


@pytest.mark.asyncio
async def test_certificate_intel_key_strength_evaluates_rsa_only(monkeypatch):
    agent = CertificateIntelAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    # 1. EC 256-bit key should NOT be flagged as weak RSA key
    async def mock_probe_ec(hostname, port):
        return SafeTlsObservation(
            hostname=hostname,
            peer_ip="93.184.216.34",
            port=port,
            subject="CN=example.com",
            issuer="CN=DigiCert",
            not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            san_list=["example.com"],
            has_sct=True,
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_size=256,
            key_type="EC",
            raw_der=b"mock_der",
        )

    monkeypatch.setattr("app.agents.certificate_intel.default_egress.probe_tls", mock_probe_ec)
    res_ec = await agent.run(ctx)
    assert res_ec.status.value == "completed"
    assert not any(f.type == "certificate.weak_key" for f in res_ec.findings)

    # 2. Missing key_size (None) should not raise an error or flag weak key
    async def mock_probe_none(hostname, port):
        return SafeTlsObservation(
            hostname=hostname,
            peer_ip="93.184.216.34",
            port=port,
            subject="CN=example.com",
            issuer="CN=DigiCert",
            not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            san_list=["example.com"],
            has_sct=True,
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_size=None,
            key_type=None,
            raw_der=b"mock_der",
        )

    monkeypatch.setattr("app.agents.certificate_intel.default_egress.probe_tls", mock_probe_none)
    res_none = await agent.run(ctx)
    assert res_none.status.value == "completed"
    assert not any(f.type == "certificate.weak_key" for f in res_none.findings)

    # 3. Weak RSA key (1024-bit) SHOULD be flagged
    async def mock_probe_weak_rsa(hostname, port):
        return SafeTlsObservation(
            hostname=hostname,
            peer_ip="93.184.216.34",
            port=port,
            subject="CN=example.com",
            issuer="CN=DigiCert",
            not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            san_list=["example.com"],
            has_sct=True,
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_size=1024,
            key_type="RSA",
            raw_der=b"mock_der",
        )

    monkeypatch.setattr("app.agents.certificate_intel.default_egress.probe_tls", mock_probe_weak_rsa)
    res_weak = await agent.run(ctx)
    assert res_weak.status.value == "completed"
    assert any(f.type == "certificate.weak_key" for f in res_weak.findings)


@pytest.mark.asyncio
async def test_privacy_software_differently_cased_headers(monkeypatch):
    agent = PrivacySoftwareAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    async def mock_fetch_url(url, follow_redirects=True):
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "CONTENT-SECURITY-POLICY": "default-src 'none'",
            },
            body=b"<html><body>Clean</body></html>",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.privacy_software.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert res.status.value == "completed"
    assert not any(f.type == "headers.missing_hsts" for f in res.findings)
    assert not any(f.type == "headers.missing_csp" for f in res.findings)


@pytest.mark.asyncio
async def test_privacy_software_multiple_set_cookie_headers(monkeypatch):
    agent = PrivacySoftwareAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    # Response with two Set-Cookie headers joined with newline
    async def mock_fetch_url(url, follow_redirects=True):
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Set-Cookie": "session_alpha=123; HttpOnly; Path=/\nsession_beta=456; Secure; Path=/",
            },
            body=b"<html><body>Clean</body></html>",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.privacy_software.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert res.status.value == "completed"
    # session_alpha lacks Secure -> cookie.missing_secure_flag
    assert any(f.type == "cookie.missing_secure_flag" for f in res.findings)
    # session_beta lacks HttpOnly -> cookie.missing_httponly_flag
    assert any(f.type == "cookie.missing_httponly_flag" for f in res.findings)


@pytest.mark.asyncio
async def test_privacy_software_multiple_cookies_with_expires_dates(monkeypatch):
    agent = PrivacySoftwareAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    # Response with comma-joined Set-Cookie containing Expires date comma
    async def mock_fetch_url(url, follow_redirects=True):
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Set-Cookie": "session_one=abc; Expires=Wed, 21 Oct 2027 07:28:00 GMT; Path=/; HttpOnly, session_two=xyz; Secure; Path=/",
            },
            body=b"<html><body>Clean</body></html>",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.privacy_software.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert res.status.value == "completed"
    # session_one lacks Secure -> cookie.missing_secure_flag
    assert any(f.type == "cookie.missing_secure_flag" for f in res.findings)
    # session_two lacks HttpOnly -> cookie.missing_httponly_flag
    assert any(f.type == "cookie.missing_httponly_flag" for f in res.findings)


@pytest.mark.asyncio
async def test_privacy_software_cookie_value_with_commas_on_newlines(monkeypatch):
    """Test that production newline-delimited Set-Cookie does not split on commas inside values."""
    agent = PrivacySoftwareAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    async def mock_fetch_url(url, follow_redirects=True):
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Set-Cookie": 'session_data="val1, val2=sub"; Path=/\nother=1; Secure; HttpOnly',
            },
            body=b"<html><body>Clean</body></html>",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.privacy_software.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert res.status.value == "completed"
    # Should evaluate exactly two cookies: session_data and other
    cookie_evidence = next(e for e in res.raw_evidence if e["kind"] == EvidenceKind.COOKIE_SET)
    assert cookie_evidence["cookie_count"] == 2
    # session_data lacks Secure over HTTPS
    assert any(f.type == "cookie.missing_secure_flag" for f in res.findings)


@pytest.mark.asyncio
async def test_privacy_software_cookie_empty_value_comma_separated(monkeypatch):
    """Test that comma-separated cookies with empty values (e.g. b=; Secure) remain intact."""
    agent = PrivacySoftwareAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    async def mock_fetch_url(url, follow_redirects=True):
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Set-Cookie": "a=1; Path=/, b=; Secure",
            },
            body=b"<html><body>Clean</body></html>",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.privacy_software.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert res.status.value == "completed"
    cookie_evidence = next(e for e in res.raw_evidence if e["kind"] == EvidenceKind.COOKIE_SET)
    assert cookie_evidence["cookie_count"] == 2
    # cookie 'a' lacks Secure over HTTPS
    assert any(f.type == "cookie.missing_secure_flag" for f in res.findings)


@pytest.mark.asyncio
async def test_privacy_software_multiple_cookies_per_line_with_quotes(monkeypatch):
    """Test splitting each nonempty line into individual cookies while preserving quoted commas."""
    agent = PrivacySoftwareAgent()
    ctx = AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url="https://example.com",
        normalized_url="https://example.com",
    )

    async def mock_fetch_url(url, follow_redirects=True):
        return SafeHttpResponse(
            url=url,
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Set-Cookie": 'c1="val1, val2=sub"; Path=/, c2=; Secure\nc3="foo, bar"; HttpOnly, c4=clean; Secure; HttpOnly',
            },
            body=b"<html><body>Clean</body></html>",
            elapsed_ms=10,
            peer_ip="93.184.216.34",
        )

    monkeypatch.setattr("app.agents.privacy_software.default_egress.fetch_url", mock_fetch_url)
    res = await agent.run(ctx)

    assert res.status.value == "completed"
    cookie_evidence = next(e for e in res.raw_evidence if e["kind"] == EvidenceKind.COOKIE_SET)
    # Exactly 4 cookies across the 2 lines: c1, c2, c3, c4
    assert cookie_evidence["cookie_count"] == 4





