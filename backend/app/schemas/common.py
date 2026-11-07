"""Shared enumerations and lightweight value types used across schemas and models.

Canonical severity, status, and score-band definitions live here so that
both Pydantic schemas and SQLAlchemy models reference the same source.
"""

from __future__ import annotations

import enum


# ── Severity ──────────────────────────────────────────────────────────────

class Severity(str, enum.Enum):
    """Finding severity per docs/agents.md."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 40,
}


# ── Score bands (docs/prd.md) ────────────────────────────────────────────

class ScoreBand(str, enum.Enum):
    LOW = "low"               # 0–19
    GUARDED = "guarded"       # 20–49
    HIGH = "high"             # 50–74
    CRITICAL = "critical"     # 75–100


def score_to_band(score: int) -> ScoreBand:
    if score < 20:
        return ScoreBand.LOW
    if score < 50:
        return ScoreBand.GUARDED
    if score < 75:
        return ScoreBand.HIGH
    return ScoreBand.CRITICAL


# ── Assessment status ────────────────────────────────────────────────────

class AssessmentStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"       # some agents failed/unavailable
    FAILED = "failed"
    CANCELLED = "cancelled"


# ── Agent run status ─────────────────────────────────────────────────────

class AgentRunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"


# ── Finding review status ────────────────────────────────────────────────

class FindingStatus(str, enum.Enum):
    ACTIVE = "active"
    ACCEPTED = "accepted"
    DISPUTED = "disputed"
    FALSE_POSITIVE = "false_positive"


# ── Authorization scope status ───────────────────────────────────────────

class ScopeStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ── Evidence kinds ───────────────────────────────────────────────────────

class EvidenceKind(str, enum.Enum):
    HTTP_RESPONSE = "http_response"
    TLS_HANDSHAKE = "tls_handshake"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    RDAP_RECORD = "rdap_record"
    SCREENSHOT = "screenshot"
    HTML_CONTENT = "html_content"
    HEADER_SET = "header_set"
    COOKIE_SET = "cookie_set"
    PROVIDER_RESULT = "provider_result"
    BANNER = "banner"


# ── Indicator types ──────────────────────────────────────────────────────

class IndicatorType(str, enum.Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    HASH = "hash"
    CERTIFICATE_FINGERPRINT = "certificate_fingerprint"


# ── Sharing policy ───────────────────────────────────────────────────────

class SharingPolicy(str, enum.Enum):
    PRIVATE = "private"
    TENANT = "tenant"
    COMMUNITY = "community"


# ── Review status for indicators ─────────────────────────────────────────

class ReviewStatus(str, enum.Enum):
    PENDING_REVIEW = "pending_review"
    REVIEWED = "reviewed"
    REJECTED = "rejected"


# ── Check availability (API response) ────────────────────────────────────

class CheckAvailability(str, enum.Enum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_REQUESTED = "not_requested"
    UNAVAILABLE = "unavailable"


# ── Agent names ──────────────────────────────────────────────────────────

class AgentName(str, enum.Enum):
    URL_REDIRECT = "url-redirect"
    PHISHING_BRAND = "phishing-brand"
    CERTIFICATE_INTELLIGENCE = "certificate-intelligence"
    SAFE_SURFACE = "safe-surface"
    PRIVACY_SOFTWARE = "privacy-software"
    THREAT_INTELLIGENCE = "threat-intelligence"


# ── Provider status (integrations.md) ────────────────────────────────────

class ProviderStatus(str, enum.Enum):
    COMPLETED = "completed"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


# ── TLS / Certificate statuses ───────────────────────────────────────────

class CertificateFieldStatus(str, enum.Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class RevocationStatus(str, enum.Enum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"

