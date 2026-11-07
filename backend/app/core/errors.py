"""Structured error taxonomy and application exceptions.

Error codes match docs/debugging.md §2 and docs/api.md error envelope.
Every error carries a stable code, a safe user-facing message, and an
optional detail field for protected logs.
"""

from __future__ import annotations

from typing import Any


# ── Stable error codes (docs/debugging.md §2) ────────────────────────────

class ErrorCode:
    INVALID_URL = "INVALID_URL"
    URL_SCHEME_NOT_ALLOWED = "URL_SCHEME_NOT_ALLOWED"
    DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
    UNAUTHORIZED_SCOPE = "UNAUTHORIZED_SCOPE"
    UNSAFE_TARGET = "UNSAFE_TARGET"
    SAFE_SCAN_NOT_ALLOWED = "SAFE_SCAN_NOT_ALLOWED"
    DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED"
    REDIRECT_BLOCKED = "REDIRECT_BLOCKED"
    AGENT_TIMEOUT = "AGENT_TIMEOUT"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_AUTH_FAILED = "PROVIDER_AUTH_FAILED"
    INVALID_AGENT_RESULT = "INVALID_AGENT_RESULT"
    RISK_ASSESSMENT_INSUFFICIENT = "RISK_ASSESSMENT_INSUFFICIENT"
    AI_TIMEOUT = "AI_TIMEOUT"
    AI_INVALID_RESPONSE = "AI_INVALID_RESPONSE"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    SCAN_DEADLINE_EXCEEDED = "SCAN_DEADLINE_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    EVIDENCE_FORBIDDEN = "EVIDENCE_FORBIDDEN"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# ── Application exception hierarchy ──────────────────────────────────────

class TrustLensError(Exception):
    """Base exception for all TrustLens application errors."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        detail: Any = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        self.detail = detail  # for internal logs only — never expose to client
        super().__init__(message)

    def to_response(self, request_id: str | None = None) -> dict[str, Any]:
        """Return the API error envelope (docs/api.md)."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                **({"requestId": request_id} if request_id else {}),
            }
        }


class InvalidURLError(TrustLensError):
    def __init__(self, message: str = "The submitted URL is invalid.", detail: Any = None):
        super().__init__(ErrorCode.INVALID_URL, message, 400, detail)


class UnsafeTargetError(TrustLensError):
    def __init__(self, message: str = "The target address is not allowed.", detail: Any = None):
        super().__init__(ErrorCode.UNSAFE_TARGET, message, 403, detail)


class UnauthorizedScopeError(TrustLensError):
    def __init__(self, message: str = "Authorization scope is missing or invalid.", detail: Any = None):
        super().__init__(ErrorCode.UNAUTHORIZED_SCOPE, message, 403, detail)


class SafeScanNotAllowedError(TrustLensError):
    def __init__(self, message: str = "Safe scan is not authorized for this target.", detail: Any = None):
        super().__init__(ErrorCode.SAFE_SCAN_NOT_ALLOWED, message, 403, detail)


class RateLimitedError(TrustLensError):
    def __init__(self, message: str = "Rate limit exceeded. Please try again later."):
        super().__init__(ErrorCode.RATE_LIMITED, message, 429)


class EvidenceForbiddenError(TrustLensError):
    def __init__(self, message: str = "Access to this evidence is not authorized."):
        super().__init__(ErrorCode.EVIDENCE_FORBIDDEN, message, 403)


class NotFoundError(TrustLensError):
    def __init__(self, entity: str = "Resource", detail: Any = None):
        super().__init__(ErrorCode.NOT_FOUND, f"{entity} not found.", 404, detail)


class AgentTimeoutError(TrustLensError):
    def __init__(self, agent: str, detail: Any = None):
        super().__init__(
            ErrorCode.AGENT_TIMEOUT,
            f"Agent '{agent}' exceeded its time limit.",
            504,
            detail,
        )


class ProviderUnavailableError(TrustLensError):
    def __init__(self, provider: str, detail: Any = None):
        super().__init__(
            ErrorCode.PROVIDER_UNAVAILABLE,
            f"Provider '{provider}' is currently unavailable.",
            502,
            detail,
        )

