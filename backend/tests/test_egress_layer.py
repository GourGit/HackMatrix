"""Focused tests for the centralized SSRF-safe outbound egress layer."""

import httpx
import pytest
from app.core.egress import SafeEgressLayer
from app.core.errors import InvalidURLError, SafeScanNotAllowedError, UnsafeTargetError


@pytest.mark.asyncio
async def test_egress_rejects_private_and_localhost_ipv4():
    """Verify loopback, RFC 1918 private, link-local, and cloud metadata IPv4 are blocked."""
    egress = SafeEgressLayer()

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://127.0.0.1:8080/admin")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://localhost/test")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://localhost./test")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://sub.localhost/test")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://10.0.0.1/internal")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://192.168.1.1/")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://172.16.0.1/")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://169.254.169.254/latest/meta-data")


@pytest.mark.asyncio
async def test_egress_rejects_blocked_ipv6_ranges():
    """Verify IPv6 loopback (::1), unique-local (fc00::/7), link-local (fe80::/10), and documentation."""
    egress = SafeEgressLayer()

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://[::1]/status")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://[fd00::1]/service")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://[fe80::1]/link")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://[2001:db8::1]/doc")


@pytest.mark.asyncio
async def test_egress_rejects_userinfo():
    egress = SafeEgressLayer()
    with pytest.raises(InvalidURLError, match="userinfo"):
        await egress.fetch_url("https://admin:pass@example.com")


@pytest.mark.asyncio
async def test_egress_rejects_unallowed_methods():
    egress = SafeEgressLayer()
    with pytest.raises(InvalidURLError, match="GET and HEAD"):
        await egress.fetch_url("https://example.com", method="POST")

    with pytest.raises(InvalidURLError, match="GET and HEAD"):
        await egress.fetch_url("https://example.com", method="DELETE")


@pytest.mark.asyncio
async def test_egress_probe_tcp_port_checks_approval():
    egress = SafeEgressLayer()
    # Unapproved port 22
    with pytest.raises(SafeScanNotAllowedError, match="not in scope-approved"):
        await egress.probe_tcp_port("example.com", 22, approved_ports=[80, 443])

    # Unapproved port 8080
    with pytest.raises(SafeScanNotAllowedError, match="not in scope-approved"):
        await egress.probe_tcp_port("example.com", 8080, approved_ports=[80, 443])


@pytest.mark.asyncio
async def test_egress_dns_rebinding_prevention(monkeypatch):
    """Confirm DNS rebinding prevention: connection uses only validated IP, not re-resolving."""
    egress = SafeEgressLayer()

    # If DNS returns a benign IP initially, caller connects directly to that IP
    validated_ip = "93.184.216.34"
    async def mock_resolve(hostname: str):
        return [validated_ip]

    monkeypatch.setattr("app.core.egress.resolve_and_validate", mock_resolve)

    sent_requests = []

    class MockStreamingResponse:
        status_code = 200
        headers = {"content-type": "text/html"}
        is_redirect = False

        async def aiter_bytes(self):
            yield b"<html>Safe content</html>"

        async def aclose(self):
            pass

    async def mock_send(self, request, stream=False):
        sent_requests.append(request)
        return MockStreamingResponse()

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    resp = await egress.fetch_url("http://rebind-attack.example.com/check")

    # Connection was pinned directly to validated IP
    assert len(sent_requests) == 1
    assert str(sent_requests[0].url) in (f"http://{validated_ip}:80/check", f"http://{validated_ip}/check")
    assert sent_requests[0].headers.get("Host") == "rebind-attack.example.com"
    assert resp.peer_ip == validated_ip


@pytest.mark.asyncio
async def test_egress_redirect_to_private_target_blocked(monkeypatch):
    """Confirm that a redirect leading to a private IP is intercepted and blocked."""
    egress = SafeEgressLayer()

    # First hop resolves to public IP; redirect target resolves to 127.0.0.1
    async def mock_resolve(hostname: str):
        if "benign" in hostname:
            return ["93.184.216.34"]
        return ["127.0.0.1"]

    monkeypatch.setattr("app.core.egress.resolve_and_validate", mock_resolve)

    class MockRedirectResponse:
        status_code = 302
        headers = {"location": "http://127.0.0.1/admin"}
        is_redirect = True

        async def aiter_bytes(self):
            yield b""

        async def aclose(self):
            pass

    async def mock_send(self, request, stream=False):
        return MockRedirectResponse()

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    # When follow_redirects=True, the redirect to 127.0.0.1 must be rejected by SSRF checks
    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://benign.com/login", follow_redirects=True)


@pytest.mark.asyncio
async def test_egress_response_size_limits(monkeypatch):
    """Confirm streaming response size limits bound memory usage."""
    max_bytes = 15
    egress = SafeEgressLayer(max_response_bytes=max_bytes)

    async def mock_resolve(hostname: str):
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.egress.resolve_and_validate", mock_resolve)

    class MockOversizedResponse:
        status_code = 200
        headers = {"content-type": "application/octet-stream"}
        is_redirect = False

        async def aiter_bytes(self):
            yield b"1234567890"  # 10 bytes
            yield b"1234567890"  # 10 more bytes
            yield b"1234567890"  # 10 more bytes

        async def aclose(self):
            pass

    async def mock_send(self, request, stream=False):
        return MockOversizedResponse()

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    resp = await egress.fetch_url("http://example.com/bigfile")
    assert len(resp.body) == max_bytes
    assert resp.body == b"123456789012345"


@pytest.mark.asyncio
async def test_egress_https_hostname_sni_behavior(monkeypatch):
    """Confirm HTTPS connections preserve hostname in SNI extension and Host header."""
    egress = SafeEgressLayer()

    resolved_ip = "93.184.216.34"
    async def mock_resolve(hostname: str):
        return [resolved_ip]

    monkeypatch.setattr("app.core.egress.resolve_and_validate", mock_resolve)

    captured_requests = []

    class MockHttpsResponse:
        status_code = 200
        headers = {"content-type": "text/html"}
        is_redirect = False

        async def aiter_bytes(self):
            yield b"OK"

        async def aclose(self):
            pass

    async def mock_send(self, request, stream=False):
        captured_requests.append(request)
        return MockHttpsResponse()

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    resp = await egress.fetch_url("https://secure.example.com/app")

    assert len(captured_requests) == 1
    req = captured_requests[0]
    # URL pinned to IP
    assert str(req.url) in (f"https://{resolved_ip}:443/app", f"https://{resolved_ip}/app")
    # Host header preserves original hostname
    assert req.headers.get("Host") == "secure.example.com"
    # SNI extension contains original hostname
    assert req.extensions.get("sni_hostname") == "secure.example.com"
