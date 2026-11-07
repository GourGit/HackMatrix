"""Focused tests for the centralized SSRF-safe outbound egress layer."""

import pytest
from app.core.egress import SafeEgressLayer
from app.core.errors import InvalidURLError, SafeScanNotAllowedError, UnsafeTargetError


@pytest.mark.asyncio
async def test_egress_rejects_private_and_localhost_targets():
    egress = SafeEgressLayer()

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://127.0.0.1:8080/admin")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://localhost/test")

    with pytest.raises(UnsafeTargetError):
        await egress.fetch_url("http://169.254.169.254/latest/meta-data")


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


@pytest.mark.asyncio
async def test_egress_probe_tcp_port_checks_approval():
    egress = SafeEgressLayer()
    # Unapproved port 22
    with pytest.raises(SafeScanNotAllowedError, match="not in scope-approved"):
        await egress.probe_tcp_port("example.com", 22, approved_ports=[80, 443])


@pytest.mark.asyncio
async def test_egress_ip_pinning_and_streaming(monkeypatch):
    """Confirm connection uses the validated IP and enforces streaming response size limit."""
    egress = SafeEgressLayer(max_response_bytes=10)

    # Mock resolve_and_validate to return a public IP without external DNS
    resolved_ip = "93.184.216.34"
    async def mock_resolve(hostname: str):
        return [resolved_ip]

    monkeypatch.setattr("app.core.egress.resolve_and_validate", mock_resolve)

    # Mock httpx.AsyncClient.send to inspect requested URL and provide a streaming body
    connected_urls = []

    class MockStreamingResponse:
        status_code = 200
        headers = {"content-type": "text/plain"}
        is_redirect = False

        async def aiter_bytes(self):
            # Emit 100 bytes in chunks; egress should clamp to max_response_bytes (10)
            yield b"1234567890"
            yield b"more-content-that-should-be-truncated"

        async def aclose(self):
            pass

    async def mock_send(self, request, stream=False):
        connected_urls.append(str(request.url))
        assert request.headers.get("Host") == "example.com"
        return MockStreamingResponse()

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    resp = await egress.fetch_url("http://example.com/test")

    # Verify connection was sent directly to resolved IP
    assert len(connected_urls) == 1
    assert connected_urls[0] == f"http://{resolved_ip}:80/test"
    assert resp.peer_ip == resolved_ip
    # Verify response body was clamped to exactly max_response_bytes
    assert len(resp.body) == 10
    assert resp.body == b"1234567890"

