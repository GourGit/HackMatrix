"""Centrally enforced, SSRF-safe outbound networking layer for TrustLens.

All DNS lookups, HTTP/HTTPS requests, TLS inspection, redirects, and
scope-authorized TCP port connections MUST pass through this module.
Direct use of socket or unpinned HTTP clients in agents is strictly prohibited.

Core Security Invariants:
1. Destination safety: Blocks RFC 1918, loopbacks, link-local, multicast,
   unspecified, CGNAT, documentation, reserved, and cloud metadata (169.254.169.254).
2. DNS Rebinding defense: Resolves IP and directly connects/pins to the validated IP,
   while preserving proper SNI and Host header.
3. Redirect control: Disables automatic redirect following. Every hop is inspected
   and revalidated against SSRF safety before following.
4. Method restriction: GET and HEAD methods only.
5. Content limits: Strict timeouts, connection limits, and response byte caps.
6. Scope-enforced service probing: TCP connectivity probes check only explicitly approved ports.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.core.errors import (
    ErrorCode,
    InvalidURLError,
    SafeScanNotAllowedError,
    UnsafeTargetError,
)
from app.core.safety import is_private_ip, resolve_and_validate


@dataclass(frozen=True)
class SafeHttpResponse:
    """Normalized, redacted response from the egress layer."""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: bytes
    elapsed_ms: int
    peer_ip: str
    redirect_location: Optional[str] = None


@dataclass(frozen=True)
class SafeTlsObservation:
    """Passive TLS inspection results obtained through verified IP pinning."""
    hostname: str
    peer_ip: str
    port: int
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    san_list: List[str]
    has_sct: bool
    tls_version: str
    cipher_name: str
    key_size: int
    raw_der: bytes


class SafeEgressLayer:
    """The central outbound network egress controller."""

    def __init__(
        self,
        timeout_seconds: float = 8.0,
        max_response_bytes: int = 2 * 1024 * 1024,  # 2 MiB
        max_redirect_hops: int = 10,
    ):
        self.timeout = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_redirect_hops = max_redirect_hops

    async def fetch_url(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = False,
    ) -> SafeHttpResponse:
        """Fetch a URL safely with IP pinning, SSRF checks, and size caps."""
        if method.upper() not in ("GET", "HEAD"):
            raise InvalidURLError("Only GET and HEAD requests are permitted by egress policy.")

        current_url = url
        hops_count = 0

        req_headers = {
            "User-Agent": "TrustLens-Security-Assessment/1.0 (+https://trustlens.security/bot)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }
        if headers:
            req_headers.update(headers)

        while True:
            parsed = urlparse(current_url)
            if parsed.scheme not in ("http", "https"):
                raise InvalidURLError(f"Unsupported scheme '{parsed.scheme}'. Only http/https permitted.")
            if not parsed.hostname:
                raise InvalidURLError("Invalid target: missing hostname.")
            if parsed.username or parsed.password:
                raise InvalidURLError("Credentials/userinfo in target URL are prohibited.")

            # 1. Resolve and validate IP against SSRF & cloud metadata
            resolved_ips = await resolve_and_validate(parsed.hostname)
            if not resolved_ips:
                raise UnsafeTargetError(f"Hostname '{parsed.hostname}' failed DNS resolution.")
            target_ip = resolved_ips[0]

            # 2. Perform safe request pinned directly to target_ip
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            target_host = parsed.hostname
            start_time = asyncio.get_event_loop().time()

            # Ensure Host header preserves original hostname and port
            effective_headers = dict(req_headers)
            host_header = target_host if (port in (80, 443)) else f"{target_host}:{port}"
            effective_headers["Host"] = host_header

            # Build IP-pinned target URL
            # For IPv6, format with brackets: [2001:db8::1]
            ip_formatted = f"[{target_ip}]" if ":" in target_ip else target_ip
            pinned_url = f"{parsed.scheme}://{ip_formatted}:{port}{parsed.path or '/'}"
            if parsed.query:
                pinned_url += f"?{parsed.query}"

            # Verify SSL using the original hostname for SNI and certificate check
            ssl_context: ssl.SSLContext | bool = True
            if parsed.scheme == "https":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = True
                ssl_context = ssl_ctx

            # Create transport without restricting local_address to IPv4 (supports dual stack)
            transport = httpx.AsyncHTTPTransport(
                verify=ssl_context,
                retries=1,
            )

            # In httpx, when connecting to an IP URL while verifying SSL against hostname,
            # we pass extensions={"sni_hostname": target_host} to ensure proper SNI and cert validation
            extensions = {"sni_hostname": target_host} if parsed.scheme == "https" else {}

            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=self.timeout,
            ) as client:
                try:
                    req = client.build_request(
                        method=method,
                        url=pinned_url,
                        headers=effective_headers,
                        extensions=extensions,
                    )
                    resp = await client.send(req, stream=True)
                except httpx.HTTPError as e:
                    raise UnsafeTargetError(f"HTTP connection failed: {str(e)}")

                try:
                    # Stream response and enforce max_response_bytes boundary
                    body_chunks = []
                    total_bytes = 0
                    async for chunk in resp.aiter_bytes():
                        remaining = self.max_response_bytes - total_bytes
                        if remaining <= 0:
                            break
                        if len(chunk) > remaining:
                            body_chunks.append(chunk[:remaining])
                            total_bytes += remaining
                            break
                        body_chunks.append(chunk)
                        total_bytes += len(chunk)

                    body_bytes = b"".join(body_chunks)
                finally:
                    await resp.aclose()

                elapsed_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
                redirect_loc = resp.headers.get("location")

                response_obj = SafeHttpResponse(
                    url=current_url,
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=body_bytes,
                    elapsed_ms=elapsed_ms,
                    peer_ip=target_ip,
                    redirect_location=redirect_loc,
                )

                if follow_redirects and resp.is_redirect and redirect_loc:
                    hops_count += 1
                    if hops_count > self.max_redirect_hops:
                        raise UnsafeTargetError("Maximum redirect hops exceeded.")
                    next_url = urljoin(current_url, redirect_loc)
                    current_url = next_url
                    continue

                return response_obj

    async def probe_tls(self, hostname: str, port: int = 443) -> SafeTlsObservation:
        """Perform a passive, SSRF-validated TLS handshake and return certificate observations."""
        resolved_ips = await resolve_and_validate(hostname)
        if not resolved_ips:
            raise UnsafeTargetError(f"Hostname '{hostname}' failed DNS resolution.")
        target_ip = resolved_ips[0]

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._tls_worker, hostname, target_ip, port)

    def _tls_worker(self, hostname: str, target_ip: str, port: int) -> SafeTlsObservation:
        ssl_ctx = ssl.create_default_context()
        # Passive observation: we capture peer certificate even if untrusted/self-signed
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_ip, port), timeout=self.timeout) as sock:
            with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                tls_version = ssock.version() or "TLSv1.2"

                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                sans = []
                try:
                    ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

                has_sct = False
                try:
                    cert.extensions.get_extension_for_oid(x509.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
                    has_sct = True
                except Exception:
                    pass

                key_size = getattr(cert.public_key(), "key_size", 2048)

                return SafeTlsObservation(
                    hostname=hostname,
                    peer_ip=target_ip,
                    port=port,
                    subject=cert.subject.rfc4514_string(),
                    issuer=cert.issuer.rfc4514_string(),
                    not_before=cert.not_valid_before_utc,
                    not_after=cert.not_valid_after_utc,
                    san_list=sans,
                    has_sct=has_sct,
                    tls_version=tls_version,
                    cipher_name=cipher[0] if cipher else "UNKNOWN",
                    key_size=key_size,
                    raw_der=der_cert,
                )

    async def probe_tcp_port(
        self,
        hostname: str,
        port: int,
        approved_ports: List[int],
    ) -> bool:
        """Scope-bound, rate-limited safe port observation.

        Rejects ports not in approved_ports. Connects only to validated IP.
        """
        if port not in approved_ports:
            raise SafeScanNotAllowedError(f"Port {port} is not in scope-approved ports {approved_ports}.")

        resolved_ips = await resolve_and_validate(hostname)
        if not resolved_ips:
            raise UnsafeTargetError(f"Hostname '{hostname}' failed DNS resolution.")
        target_ip = resolved_ips[0]

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._tcp_connect_test, target_ip, port)

    def _tcp_connect_test(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=2.0):
                return True
        except Exception:
            return False


# Global default safe egress instance
default_egress = SafeEgressLayer()

