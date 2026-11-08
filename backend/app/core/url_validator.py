"""URL validation and normalization for SSRF-safe scanning.

Implements docs/authentication-and-security.md §4 controls 1–3:
 1. Permit only ``http`` and ``https`` schemes.
 2. Reject ``userinfo`` (``user:password@host``).
 3. Normalize the hostname via IDNA encoding.

The returned :class:`NormalizedURL` is the *only* URL representation that
downstream code should pass to HTTP clients — raw strings from user input
must never be forwarded directly.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import urllib.parse
from typing import Final

import idna

from app.core.errors import InvalidURLError

# ── Constants ─────────────────────────────────────────────────────────────

_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}
_MAX_URL_LENGTH: Final[int] = 8_192  # conservative upper bound


# ── Data structures ──────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True, slots=True)
class NormalizedURL:
    """Immutable, validated representation of a user-submitted URL.

    Attributes:
        scheme:         Lowercased scheme (``http`` or ``https``).
        host:           IDNA-encoded, lowercased hostname.
        port:           Explicit or default port for the scheme.
        path:           Percent-encoded path (at least ``/``).
        query:          Percent-encoded query string, or empty string.
        normalized_str: Fully reassembled canonical URL string.
    """

    scheme: str
    host: str
    port: int
    path: str
    query: str
    normalized_str: str

    def __str__(self) -> str:  # noqa: D105
        return self.normalized_str


# ── Public API ───────────────────────────────────────────────────────────

def normalize_url(raw_url: str) -> NormalizedURL:
    """Parse, validate, and normalize a user-supplied URL.

    Security controls applied (docs/authentication-and-security.md §4):
      * Only ``http`` / ``https`` schemes are accepted.
      * ``userinfo`` (``user:password@host``) is rejected.
      * The hostname is IDNA-encoded and lowercased.
      * Ports are validated (1–65535).
      * Fragment identifiers are stripped (never sent to the server).

    Args:
        raw_url: The raw URL string submitted by the user or extracted from
                 a redirect ``Location`` header.

    Returns:
        A :class:`NormalizedURL` ready for safe HTTP requests.

    Raises:
        InvalidURLError: If any validation check fails.
    """
    if not raw_url or not raw_url.strip():
        raise InvalidURLError("URL must not be empty.")

    raw_url = raw_url.strip()

    if len(raw_url) > _MAX_URL_LENGTH:
        raise InvalidURLError(
            f"URL exceeds maximum length ({_MAX_URL_LENGTH} bytes).",
            detail={"length": len(raw_url)},
        )

    # ── Parse ─────────────────────────────────────────────────────────
    try:
        parsed = urllib.parse.urlparse(raw_url)
    except ValueError as exc:
        raise InvalidURLError(
            "URL could not be parsed.",
            detail=str(exc),
        ) from exc

    # ── Scheme ────────────────────────────────────────────────────────
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise InvalidURLError(
            f"URL scheme '{scheme or '(empty)'}' is not allowed. "
            f"Only {', '.join(sorted(_ALLOWED_SCHEMES))} are permitted.",
            detail={"scheme": scheme},
        )

    # ── Userinfo ──────────────────────────────────────────────────────
    if parsed.username or parsed.password:
        raise InvalidURLError(
            "URLs containing user credentials (userinfo) are not allowed.",
        )

    # Catch edge-cases where urlparse may not split user:pass properly
    # but the netloc still contains a ``@``.
    if "@" in (parsed.netloc or ""):
        raise InvalidURLError(
            "URLs containing user credentials (userinfo) are not allowed.",
        )

    # ── Hostname ──────────────────────────────────────────────────────
    hostname = parsed.hostname
    if not hostname:
        raise InvalidURLError("URL must include a hostname.")

    hostname = _normalize_hostname(hostname)

    # ── Port ──────────────────────────────────────────────────────────
    port = parsed.port
    if port is not None:
        if not (1 <= port <= 65_535):
            raise InvalidURLError(
                f"Port {port} is outside the valid range 1–65535.",
                detail={"port": port},
            )
    else:
        port = _DEFAULT_PORTS[scheme]

    # ── Path / query ──────────────────────────────────────────────────
    path = parsed.path or "/"
    query = parsed.query or ""

    # ── Reassemble (fragments intentionally dropped) ──────────────────
    normalized_str = _reassemble(scheme, hostname, port, path, query)

    return NormalizedURL(
        scheme=scheme,
        host=hostname,
        port=port,
        path=path,
        query=query,
        normalized_str=normalized_str,
    )


# ── Internal helpers ─────────────────────────────────────────────────────

def _normalize_hostname(hostname: str) -> str:
    """IDNA-encode and lowercase *hostname*.

    Handles internationalized domain names (IDN) so that equivalent Unicode
    and ASCII representations resolve to the same canonical label.

    Raises:
        InvalidURLError: If the hostname is not a valid IDNA label.
    """
    # Handle IP address literals (IPv4 or bracketed/unbracketed IPv6)
    clean_ip = hostname.strip("[]")
    try:
        addr = ipaddress.ip_address(clean_ip)
        if isinstance(addr, ipaddress.IPv6Address):
            return f"[{addr.compressed.lower()}]"
        return addr.compressed.lower()
    except ValueError:
        pass

    try:
        # idna.encode returns bytes; decode back to str.
        encoded: str = idna.encode(hostname, uts46=True).decode("ascii")
    except (idna.core.IDNAError, UnicodeDecodeError, UnicodeError) as exc:
        raise InvalidURLError(
            f"Hostname '{hostname}' is not a valid internationalized domain name.",
            detail=str(exc),
        ) from exc

    return encoded.lower().rstrip(".")


def _reassemble(
    scheme: str,
    host: str,
    port: int,
    path: str,
    query: str,
) -> str:
    """Rebuild a canonical URL string from validated components."""
    default_port = _DEFAULT_PORTS.get(scheme)
    if port == default_port:
        netloc = host
    else:
        netloc = f"{host}:{port}"

    base = f"{scheme}://{netloc}{path}"
    if query:
        base = f"{base}?{query}"
    return base
