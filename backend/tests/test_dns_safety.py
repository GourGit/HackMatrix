"""Regression tests for DNS resolution safety and mixed-response validation.

Verifies that app.core.safety.resolve_and_validate() strictly rejects a hostname
if ANY resolved A or AAAA address belongs to a prohibited or private network range.
DNS resolution is fully mocked to prevent real network requests.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import pytest

from app.core.errors import UnsafeTargetError
from app.core.safety import resolve_and_validate

# Ensure compatibility if dnspython asyncresolver does not re-export NoNameservers
if not hasattr(dns.asyncresolver, "NoNameservers"):
    dns.asyncresolver.NoNameservers = dns.resolver.NoNameservers


@dataclass(frozen=True)
class MockDNSAnswer:
    address: str


@pytest.mark.asyncio
async def test_resolve_and_validate_rejects_mixed_public_and_private_a_records():
    """Verify rejection when DNS returns both public and private IPv4 A records."""
    hostname = "mixed-ipv4.example.test"

    async def fake_resolve(qname: str, rdtype: dns.rdatatype.RdataType):
        if rdtype == dns.rdatatype.A:
            return [
                MockDNSAnswer(address="93.184.216.34"),  # public IPv4
                MockDNSAnswer(address="10.0.0.5"),        # private IPv4 (RFC 1918)
            ]
        elif rdtype == dns.rdatatype.AAAA:
            raise dns.asyncresolver.NoAnswer()
        raise dns.asyncresolver.NoAnswer()

    with patch("dns.asyncresolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver.resolve = fake_resolve
        mock_resolver_cls.return_value = mock_resolver

        with pytest.raises(UnsafeTargetError) as exc_info:
            await resolve_and_validate(hostname)

        assert "resolved IP address is not allowed" in str(exc_info.value.message)
        assert exc_info.value.detail.get("ip") == "10.0.0.5"


@pytest.mark.asyncio
async def test_resolve_and_validate_rejects_public_a_with_loopback_aaaa():
    """Verify rejection when DNS returns a public IPv4 A record and an IPv6 loopback AAAA record."""
    hostname = "mixed-v4-v6.example.test"

    async def fake_resolve(qname: str, rdtype: dns.rdatatype.RdataType):
        if rdtype == dns.rdatatype.A:
            return [
                MockDNSAnswer(address="93.184.216.34"),  # public IPv4
            ]
        elif rdtype == dns.rdatatype.AAAA:
            return [
                MockDNSAnswer(address="::1"),            # IPv6 loopback
            ]
        raise dns.asyncresolver.NoAnswer()

    with patch("dns.asyncresolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver.resolve = fake_resolve
        mock_resolver_cls.return_value = mock_resolver

        with pytest.raises(UnsafeTargetError) as exc_info:
            await resolve_and_validate(hostname)

        assert "resolved IP address is not allowed" in str(exc_info.value.message)
        assert exc_info.value.detail.get("ip") == "::1"


@pytest.mark.asyncio
async def test_resolve_and_validate_permits_all_public_addresses():
    """Verify that resolution succeeds and returns all IPs when all A and AAAA records are public."""
    hostname = "all-public.example.test"

    async def fake_resolve(qname: str, rdtype: dns.rdatatype.RdataType):
        if rdtype == dns.rdatatype.A:
            return [
                MockDNSAnswer(address="93.184.216.34"),
            ]
        elif rdtype == dns.rdatatype.AAAA:
            return [
                MockDNSAnswer(address="2606:4700:4700::1111"),
            ]
        raise dns.asyncresolver.NoAnswer()

    with patch("dns.asyncresolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver.resolve = fake_resolve
        mock_resolver_cls.return_value = mock_resolver

        result = await resolve_and_validate(hostname)

        assert result == ["93.184.216.34", "2606:4700:4700::1111"]
