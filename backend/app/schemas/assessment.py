"""Pydantic v2 request / response schemas for the assessment endpoints.

Covers:
- POST /assessments  → CreateAssessmentRequest / CreateAssessmentResponse
- GET  /assessments/{assessmentId} → AssessmentDetailResponse
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.schemas.common import (
    AssessmentStatus,
    CheckAvailability,
    ScoreBand,
    Severity,
)


# ── helpers ──────────────────────────────────────────────────────────────


def _to_camel(name: str) -> str:
    """Convert a snake_case Python name to camelCase for JSON aliases."""
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


# ── request models ───────────────────────────────────────────────────────


class AuthorizationInput(BaseModel):
    """Caller's attestation that they are authorized to assess the target."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    attested: bool = Field(
        ...,
        description="Whether the caller attests authorization for the target.",
        examples=[True],
    )
    scope_id: uuid.UUID | None = Field(
        default=None,
        description="Scope identifier covering the target host. Optional in dev.",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    )


class SafeScanInput(BaseModel):
    """Optional safe-scan configuration.

    Accepted only when the referenced scope explicitly authorizes the
    target's hostname / IPs and the requested ports.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    enabled: bool = Field(
        False,
        description="Whether to run a safe surface scan.",
        examples=[False],
    )
    ports: list[int] = Field(
        default_factory=list,
        description="TCP ports authorized for scanning (empty ⇒ default set).",
        examples=[[443, 8443]],
    )


class OptionsInput(BaseModel):
    """Feature-flag options for a single assessment run."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    crypto_scam_analysis: bool = Field(
        False,
        description=(
            "Enable optional cryptocurrency-scam analysis. "
            "Not required for the core product or score."
        ),
        examples=[False],
    )


class CreateAssessmentRequest(BaseModel):
    """Body of ``POST /assessments``.

    Submits a URL for assessment along with authorization attestation and
    optional scan / feature-flag configuration.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    url: HttpUrl = Field(
        ...,
        description="The target URL to assess.",
        examples=["https://example.test/login"],
    )
    authorization: AuthorizationInput = Field(
        ...,
        description="Caller authorization attestation and scope reference.",
    )
    safe_scan: SafeScanInput = Field(
        default_factory=SafeScanInput,
        description="Safe-scan configuration (defaults to disabled).",
    )
    options: OptionsInput = Field(
        default_factory=OptionsInput,
        description="Optional feature-flag overrides.",
    )


# ── response models ─────────────────────────────────────────────────────


class CreateAssessmentResponse(BaseModel):
    """``202 Accepted`` response for ``POST /assessments``."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    assessment_id: uuid.UUID = Field(
        ...,
        description="Unique identifier for the queued assessment.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    )
    status: AssessmentStatus = Field(
        AssessmentStatus.QUEUED,
        description="Initial status — always 'queued' at creation time.",
        examples=["queued"],
    )
    scope_id: uuid.UUID = Field(
        ...,
        description="Scope identifier that was bound to this assessment.",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    )


class ScoreContribution(BaseModel):
    """One finding's contribution to the aggregate risk score."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    finding_id: uuid.UUID = Field(
        ...,
        description="Finding that contributed to the score.",
    )
    points: int = Field(
        ...,
        ge=0,
        description="Points this finding added to the aggregate score.",
        examples=[16],
    )


class RiskDetail(BaseModel):
    """Aggregate risk score with per-finding breakdown."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Composite risk score (0–100).",
        examples=[58],
    )
    band: ScoreBand = Field(
        ...,
        description="Human-readable risk band derived from the score.",
        examples=["high"],
    )
    version: str = Field(
        ...,
        description="Scoring-rule version string.",
        examples=["2026-1"],
    )
    contributions: list[ScoreContribution] = Field(
        default_factory=list,
        description="Per-finding point contributions.",
    )


class FindingSummary(BaseModel):
    """Lightweight finding embedded in the assessment detail response.

    The full finding envelope lives in :pymod:`app.schemas.finding`.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    finding_id: uuid.UUID = Field(..., description="Finding identifier.")
    agent: str = Field(
        ...,
        description="Agent that produced the finding.",
        examples=["certificate-intelligence"],
    )
    type: str = Field(
        ...,
        description="Dot-delimited finding type.",
        examples=["certificate.revocation_unknown"],
    )
    severity: Severity = Field(
        ...,
        description="Finding severity.",
        examples=["medium"],
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Agent-reported confidence (0–1).",
        examples=[0.7],
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Evidence artifacts linked to this finding.",
    )


class ChecksDetail(BaseModel):
    """Per-check availability status shown in the assessment response."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    ct: CheckAvailability = Field(
        ...,
        description="Certificate Transparency check result.",
        examples=["passed"],
    )
    revocation: CheckAvailability = Field(
        ...,
        description="Revocation check result.",
        examples=["unknown"],
    )
    safe_scan: CheckAvailability = Field(
        ...,
        description="Safe surface scan result.",
        examples=["not_requested"],
    )
    hostname_match: Optional[CheckAvailability] = Field(
        default=None,
        description="Certificate hostname / SAN matching result.",
        examples=["passed"],
    )
    validity_dates: Optional[CheckAvailability] = Field(
        default=None,
        description="Certificate validity dates result.",
        examples=["passed"],
    )
    ca_chain: Optional[CheckAvailability] = Field(
        default=None,
        description="Trusted CA chain validation result.",
        examples=["passed"],
    )
    tls_configuration: Optional[CheckAvailability] = Field(
        default=None,
        description="TLS protocol version and cipher suite evaluation.",
        examples=["passed"],
    )
    crypto_strength: Optional[CheckAvailability] = Field(
        default=None,
        description="Key size and signature algorithm strength.",
        examples=["passed"],
    )


class AgentRunSummary(BaseModel):
    """Execution status summary for an agent run."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    agent_name: str = Field(..., alias="agentName", description="Agent name identifier.")
    status: str = Field(..., description="Agent run status.")
    started_at: datetime | None = Field(None, alias="startedAt", description="Run start timestamp.")
    ended_at: datetime | None = Field(None, alias="endedAt", description="Run completion timestamp.")
    error_code: str | None = Field(None, alias="errorCode", description="Optional error classification.")


class AssessmentDetailResponse(BaseModel):
    """Full ``GET /assessments/{assessmentId}`` response.

    Includes status, risk score, inline finding summaries, and
    check-availability flags.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    assessment_id: uuid.UUID = Field(
        ...,
        description="Unique identifier for the assessment.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    )
    status: AssessmentStatus = Field(
        ...,
        description="Current assessment status.",
        examples=["completed"],
    )
    url: HttpUrl = Field(
        ...,
        description="Original target URL.",
        examples=["https://example.test/login"],
    )
    created_at: datetime = Field(
        ...,
        description="ISO-8601 UTC timestamp of assessment creation.",
    )
    completed_at: datetime | None = Field(
        None,
        description="ISO-8601 UTC timestamp of assessment completion.",
    )
    risk: RiskDetail | None = Field(
        None,
        description="Aggregate risk breakdown (present when scored).",
    )
    findings: list[FindingSummary] = Field(
        default_factory=list,
        description="Inline finding summaries.",
    )
    checks: ChecksDetail | None = Field(
        None,
        description="Per-check availability flags.",
    )
    agent_runs: list[AgentRunSummary] = Field(
        default_factory=list,
        alias="agentRuns",
        description="Execution status per deterministic agent.",
    )
