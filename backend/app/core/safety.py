"""SSRF prevention: IP classification, DNS resolution, and port validation.

Implements docs/authentication-and-security.md §4 controls 4–10:
 4. Reject localhost and prohibited IP literals.
 5. Resolve A/AAAA records, validate every returned IP.
 6. Reject private, loopback, link-local, multicast, reserved, unspecified.
 7. DNS rebinding defense — callers pin the validated IPs.
 8. Revalidate each redirect destination.
 9. Limit ports.
10. Deny cloud metadata endpoints.

All IP classification uses the stdlib :mod:`ipaddress` module for
correctness; additional cloud-metadata CIDRs are checked explicitly.
"""

from __future__ import annotations

import ipaddress
from typing import Final, Sequence

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from app.config import settings
from app.core.errors import InvalidURLError, UnsafeTargetError

# ── Blocked networks ─────────────────────────────────────────────────────
# Collected once at import time for O(1) membership checks.

_BLOCKED_IPV4_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.IPv4Network("0.0.0.0/8"),        # "this" network / unspecified
    ipaddress.IPv4Network("10.0.0.0/8"),        # RFC 1918 private
    ipaddress.IPv4Network("100.64.0.0/10"),     # Carrier-grade NAT (RFC 6598)
    ipaddress.IPv4Network("127.0.0.0/8"),       # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),    # link-local
    ipaddress.IPv4Network("172.16.0.0/12"),     # RFC 1918 private
    ipaddress.IPv4Network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.IPv4Network("192.0.2.0/24"),      # documentation (TEST-NET-1)
    ipaddress.IPv4Network("192.88.99.0/24"),    # 6to4 relay anycast
    ipaddress.IPv4Network("192.168.0.0/16"),    # RFC 1918 private
    ipaddress.IPv4Network("198.18.0.0/15"),     # benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),   # documentation (TEST-NET-2)
    ipaddress.IPv4Network("203.0.113.0/24"),    # documentation (TEST-NET-3)
    ipaddress.IPv4Network("224.0.0.0/4"),       # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),       # reserved for future use
    ipaddress.IPv4Network("255.255.255.255/32"),# limited broadcast
)

_BLOCKED_IPV6_NETWORKS: Final[tuple[ipaddress.IPv6Network, ...]] = (
    ipaddress.IPv6Network("::1/128"),           # loopback
    ipaddress.IPv6Network("::/128"),            # unspecified
    ipaddress.IPv6Network("::ffff:0:0/96"),     # IPv4-mapped (re-check mapped addr)
    ipaddress.IPv6Network("64:ff9b::/96"),      # NAT64
    ipaddress.IPv6Network("100::/64"),          # discard-only (RFC 6666)
    ipaddress.IPv6Network("2001:db8::/32"),     # documentation
    ipaddress.IPv6Network("fc00::/7"),          # unique local (private)
    ipaddress.IPv6Network("fe80::/10"),         # link-local
    ipaddress.IPv6Network("ff00::/8"),          # multicast
)

# Cloud metadata IP — checked as an exact address, plus covered by the
# link-local block above.  Explicit check is a defense-in-depth measure.
_CLOUD_METADATA_IPV4: Final[ipaddress.IPv4Address] = ipaddress.IPv4Address("169.254.169.254")


# ── Public API ───────────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Return ``True`` if *ip* belongs to any blocked range.

    Checked ranges include:
    - RFC 1918 private (10/8, 172.16/12, 192.168/16)
    - Loopback (127/8, ::1)
    - Link-local (169.254/16, fe80::/10)
    - Multicast (224/4, ff00::/8)
    - Reserved / future use (240/4)
    - Unspecified (0.0.0.0/8, ::)
    - Carrier-grade NAT (100.64/10)
    - Documentation, benchmarking, and protocol assignment blocks
    - Cloud metadata endpoint (169.254.169.254)
    - IPv6 unique local (fc00::/7), IPv4-mapped, NAT64

    Args:
        ip: A string representation of an IPv4 or IPv6 address.

    Returns:
        ``True`` if the address should be blocked; ``False`` otherwise.

    Raises:
        ValueError: If *ip* is not a valid IP address string.
    """
    addr = _parse_ip(ip)
    return _is_blocked(addr)


def validate_ip_safety(ip: str) -> None:
    """Assert that *ip* is safe to connect to.

    Args:
        ip: A string representation of an IPv4 or IPv6 address.

    Raises:
        UnsafeTargetError: If the address belongs to a blocked range.
    """
    addr = _parse_ip(ip)
    if _is_blocked(addr):
        raise UnsafeTargetError(
            "The resolved IP address is not allowed.",
            detail={"ip": ip, "reason": _block_reason(addr)},
        )


async def resolve_and_validate(hostname: str) -> list[str]:
    """Resolve *hostname* via DNS and validate every returned IP.

    If hostname is already an IP address literal or localhost, validates it directly
    without performing a remote DNS query.
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if (
        clean_host in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback")
        or clean_host.endswith(".localhost")
    ):
        raise UnsafeTargetError(
            "The target hostname resolves to loopback/localhost and is not allowed.",
            detail={"hostname": hostname, "reason": "localhost"},
        )

    # Check IP literal directly
    try:
        ipaddress.ip_address(clean_host)
        validate_ip_safety(clean_host)
        return [clean_host]
    except ValueError:
        pass

    resolved_ips: list[str] = []

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = min(3.0, float(settings.http_timeout_seconds))

    # Try both A and AAAA; accumulate results.
    for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        try:
            answer = await resolver.resolve(hostname, rdtype)
            for rdata in answer:
                resolved_ips.append(rdata.address)
        except (
            dns.asyncresolver.NXDOMAIN,
            dns.asyncresolver.NoAnswer,
            dns.asyncresolver.NoNameservers,
        ):
            # This record type simply has no results — not fatal.
            continue
        except dns.exception.Timeout as exc:
            raise InvalidURLError(
                f"DNS resolution for '{hostname}' timed out.",
                detail=str(exc),
            ) from exc
        except dns.exception.DNSException as exc:
            raise InvalidURLError(
                f"DNS resolution for '{hostname}' failed.",
                detail=str(exc),
            ) from exc

    if not resolved_ips:
        raise InvalidURLError(
            f"DNS resolution for '{hostname}' returned no addresses.",
            detail={"hostname": hostname},
        )

    # Validate every resolved address.
    for ip_str in resolved_ips:
        validate_ip_safety(ip_str)

    return resolved_ips


def is_safe_port(
    port: int,
    allowed_ports: list[int] | None = None,
) -> bool:
    """Return ``True`` if *port* is in the allow-list.

    Args:
        port:          The TCP port to check.
        allowed_ports: Explicit allow-list.  Falls back to
                       ``settings.safe_scan_allowed_ports`` when *None*.

    Returns:
        ``True`` if the port is permitted; ``False`` otherwise.
    """
    if allowed_ports is None:
        allowed_ports = settings.safe_scan_allowed_ports
    return port in allowed_ports


# ── Internal helpers ─────────────────────────────────────────────────────

def _parse_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse *ip* into an :mod:`ipaddress` object.

    Strips surrounding brackets from IPv6 literals (``[::1]``) before
    parsing.

    Raises:
        ValueError: If the string is not a valid IP address.
    """
    ip = ip.strip()
    if ip.startswith("[") and ip.endswith("]"):
        ip = ip[1:-1]
    return ipaddress.ip_address(ip)


def _is_blocked(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return ``True`` if *addr* matches any blocked network."""
    # Explicit cloud-metadata check (defense-in-depth).
    if isinstance(addr, ipaddress.IPv4Address) and addr == _CLOUD_METADATA_IPV4:
        return True

    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _BLOCKED_IPV4_NETWORKS)

    # IPv6
    if any(addr in net for net in _BLOCKED_IPV6_NETWORKS):
        return True

    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) — extract the inner IPv4.
    if addr.ipv4_mapped is not None:
        return _is_blocked(addr.ipv4_mapped)

    return False


def _block_reason(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str:
    """Return a human-readable label for why *addr* is blocked.

    Used only for internal logging / error detail — never exposed to
    unauthenticated callers.
    """
    if isinstance(addr, ipaddress.IPv4Address) and addr == _CLOUD_METADATA_IPV4:
        return "cloud metadata endpoint"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private / RFC 1918"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if addr.is_unspecified:
        return "unspecified"
    return "blocked network"
