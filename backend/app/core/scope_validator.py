"""Scope validation and target matching logic."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from app.core.errors import SafeScanNotAllowedError, UnauthorizedScopeError
from app.models.authorization import AuthorizationScope
from app.schemas.common import ScopeStatus


def match_target(target_url: str, allowed_targets: List[str]) -> bool:
    """Check if target_url or its hostname/domain is authorized by allowed_targets.

    Supports:
    - URL pattern matching: exact scheme, host, effective port, with path matched only at segment boundary.
    - Wildcard domain matching: "*.example.com" (covers subdomains and apex).
    - Exact hostname matching: "example.com" or "api.example.com".
    """
    parsed = urlparse(target_url)
    target_scheme = (parsed.scheme or "").lower()
    target_host = (parsed.hostname or "").lower()
    try:
        raw_target_port = parsed.port
    except ValueError:
        return False
    target_port = raw_target_port or (443 if target_scheme == "https" else 80 if target_scheme == "http" else None)
    target_path = parsed.path or "/"
    if not target_path.startswith("/"):
        target_path = "/" + target_path

    for pattern in allowed_targets:
        pat = pattern.strip().lower()
        if pat.startswith("http://") or pat.startswith("https://"):
            pat_parsed = urlparse(pat)
            pat_scheme = (pat_parsed.scheme or "").lower()
            pat_host = (pat_parsed.hostname or "").lower()
            try:
                raw_pat_port = pat_parsed.port
            except ValueError:
                continue
            pat_port = raw_pat_port or (443 if pat_scheme == "https" else 80 if pat_scheme == "http" else None)
            pat_path = pat_parsed.path or "/"
            if not pat_path.startswith("/"):
                pat_path = "/" + pat_path

            # Scheme, host, and port must match exactly
            if target_scheme != pat_scheme or target_host != pat_host or target_port != pat_port:
                continue

            # Path matching only at segment boundary:
            # e.g., pat_path "/login" matches "/login", "/login/", "/login/admin", but NOT "/login-admin"
            if pat_path == "/" or target_path == pat_path:
                return True
            pat_path_prefix = pat_path if pat_path.endswith("/") else pat_path + "/"
            if target_path.startswith(pat_path_prefix):
                return True

        elif pat.startswith("*."):
            domain_suffix = pat[2:]
            if target_host == domain_suffix or target_host.endswith("." + domain_suffix):
                return True
        else:
            if target_host == pat:
                return True

    return False


def validate_scope_authorization(
    scope: AuthorizationScope,
    normalized_url: str,
    safe_scan_requested: bool,
    requested_ports: Optional[List[int]],
) -> None:
    """Validate scope active state, validity window, target match, and ports."""
    now = datetime.now(timezone.utc)

    # 1. Status check
    if scope.status != ScopeStatus.ACTIVE.value:
        raise UnauthorizedScopeError(f"Scope is not active (current status: {scope.status}).")

    # 2. Validity window
    valid_from = scope.valid_from
    if valid_from and valid_from.tzinfo is None:
        valid_from = valid_from.replace(tzinfo=timezone.utc)

    valid_until = scope.valid_until
    if valid_until and valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=timezone.utc)

    if valid_from and now < valid_from:
        raise UnauthorizedScopeError("Scope validity window has not started yet.")
    if valid_until and now > valid_until:
        raise UnauthorizedScopeError("Scope validity has expired.")

    # 3. Target matching
    allowed_targets = scope.targets_json if isinstance(scope.targets_json, list) else []
    if not match_target(normalized_url, allowed_targets):
        raise UnauthorizedScopeError(
            f"Target URL '{normalized_url}' is not permitted under authorization scope {scope.id}."
        )

    # 4. Safe Scan Authorization
    if safe_scan_requested:
        if not scope.allowed_ports_json:
            raise SafeScanNotAllowedError(
                "Safe scan requested but scope does not authorize any open network port probes."
            )
        scope_ports = set(scope.allowed_ports_json)
        req_ports = set(requested_ports or [80, 443])
        if not req_ports.issubset(scope_ports):
            unauthorized = list(req_ports - scope_ports)
            raise SafeScanNotAllowedError(
                f"Requested ports {unauthorized} exceed scope-approved ports {list(scope_ports)}."
            )

