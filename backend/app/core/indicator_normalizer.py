"""Indicator normalization and validation functions.

Provides canonical normalization and validation for threat observables:
- URLs: canonical scheme, lowercased hostname, port normalization, query preserved, fragment stripped.
- Domains: lowercased, trailing dots stripped, RFC-compliant hostname syntax.
- IPs: valid IPv4 and IPv6 parsed, compressed canonical representation.
- Emails: lowercased, valid syntax (local-part@domain).
- Hashes: lowercased, delimiters stripped, validated length for MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128).
- Certificate fingerprints: lowercased, delimiters stripped, validated hex (32, 40, or 64 hex chars).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from app.schemas.common import IndicatorType

_HASH_LENGTHS = {32, 40, 64, 128}
_CERT_FINGERPRINT_LENGTHS = {32, 40, 64}
_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")
_HEX_REGEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def normalize_indicator_value(val: str, ind_type: IndicatorType | str) -> str:
    """Normalize and validate an indicator value according to its type.

    Args:
        val: Raw user-supplied indicator string.
        ind_type: IndicatorType enum or string representation.

    Returns:
        Canonical normalized representation of the indicator.

    Raises:
        ValueError: If the indicator value is malformed or invalid for its type.
    """
    if not val or not val.strip():
        raise ValueError("Indicator value cannot be empty.")

    s = val.strip()

    if isinstance(ind_type, str):
        try:
            ind_type = IndicatorType(ind_type)
        except ValueError:
            raise ValueError(f"Unknown indicator type: {ind_type}")

    if ind_type == IndicatorType.URL:
        if not s.lower().startswith(("http://", "https://")):
            raise ValueError("URL indicator must have an http:// or https:// scheme.")

        parsed = urlsplit(s)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Malformed URL indicator: missing scheme or host.")

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("Only http and https URL schemes are supported.")

        if "@" in (parsed.netloc or ""):
            raise ValueError("URL indicator must not contain user credentials.")

        if not parsed.hostname:
            raise ValueError("Malformed URL indicator: missing scheme or host.")

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"Invalid port in URL: {exc}") from exc

        if port is not None:
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port: {port}")
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                port = None

        host_str = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        authority = f"{host_str}:{port}" if port is not None else host_str

        path = parsed.path or "/"
        if not path.startswith("/"):
            path = "/" + path

        norm_url = f"{scheme}://{authority}{path}"
        if parsed.query:
            norm_url = f"{norm_url}?{parsed.query}"
        return norm_url

    elif ind_type == IndicatorType.DOMAIN:
        d = s.rstrip(".")
        if not d:
            raise ValueError("Domain cannot be empty.")
        if "://" in d or "/" in d or ":" in d or "@" in d or " " in d:
            raise ValueError("Invalid domain: cannot contain schemes, paths, ports, or spaces.")

        d_lower = d.lower()
        labels = d_lower.split(".")
        if len(labels) < 2:
            raise ValueError("Domain must have at least two labels (e.g., example.com).")

        for label in labels:
            if not label or len(label) > 63:
                raise ValueError("Domain labels must be between 1 and 63 characters.")
            if not _DOMAIN_LABEL_REGEX.match(label):
                raise ValueError(f"Invalid characters in domain label: {label}")

        return d_lower

    elif ind_type == IndicatorType.IP:
        try:
            ip = ipaddress.ip_address(s)
            return str(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {val}")

    elif ind_type == IndicatorType.EMAIL:
        e_lower = s.lower()
        if not _EMAIL_REGEX.match(e_lower):
            raise ValueError(f"Invalid email address: {val}")
        return e_lower

    elif ind_type == IndicatorType.HASH:
        cleaned = s.replace(":", "").replace("-", "").replace(" ", "").lower()
        if not _HEX_REGEX.match(cleaned):
            raise ValueError("Hash must contain only hexadecimal characters.")
        if len(cleaned) not in _HASH_LENGTHS:
            raise ValueError(
                f"Invalid hash length ({len(cleaned)}). Must be 32 (MD5), 40 (SHA-1), 64 (SHA-256), or 128 (SHA-512) characters."
            )
        return cleaned

    elif ind_type == IndicatorType.CERTIFICATE_FINGERPRINT:
        cleaned = s.replace(":", "").replace("-", "").replace(" ", "").lower()
        if not _HEX_REGEX.match(cleaned):
            raise ValueError("Certificate fingerprint must contain only hexadecimal characters.")
        if len(cleaned) not in _CERT_FINGERPRINT_LENGTHS:
            raise ValueError(
                f"Invalid certificate fingerprint length ({len(cleaned)}). Must be 32, 40, or 64 characters."
            )
        return cleaned

    else:
        raise ValueError(f"Unsupported indicator type: {ind_type}")

