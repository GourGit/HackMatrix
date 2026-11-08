"""Pydantic v2 schemas for the finding domain.

Covers:
- Common finding envelope emitted by every agent (docs/agents.md)
- GET  findings (embedded or standalone)
- POST /findings/{findingId}/review
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.common import (
    AgentName,
    FindingStatus,
    ReviewDecision,
    Severity,
)


# ── helpers ──────────────────────────────────────────────────────────────


def _to_camel(name: str) -> str:
    """Convert a snake_case Python name to camelCase for JSON aliases."""
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


# ── core envelope ────────────────────────────────────────────────────────


class FindingEnvelope(BaseModel):
    """Common finding envelope returned by every TrustLens agent.

    Fields defined in docs/agents.md § "Common finding envelope":
    findingId, assessmentId, agent, type, severity, scoreImpact,
    confidence, status, title, description, affectedAsset, evidenceIds,
    observedAt, ruleVersion.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    finding_id: uuid.UUID = Field(
        ...,
        description="Globally unique finding identifier.",
        examples=["b3a1c2d4-e5f6-7890-abcd-ef1234567890"],
    )
    assessment_id: uuid.UUID = Field(
        ...,
        description="Assessment this finding belongs to.",
    )
    agent: AgentName = Field(
        ...,
        description="Agent that produced the finding.",
        examples=["certificate-intelligence"],
    )
    type: str = Field(
        ...,
        description="Dot-delimited finding type code.",
        examples=["certificate.revocation_unknown"],
    )
    severity: Severity = Field(
        ...,
        description="Finding severity (informational–critical).",
        examples=["medium"],
    )
    score_impact: int = Field(
        ...,
        ge=0,
        description="Points this finding contributes to the risk score.",
        examples=[16],
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Agent-reported confidence (0–1).",
        examples=[0.7],
    )
    status: FindingStatus = Field(
        FindingStatus.ACTIVE,
        description="Review status of this finding.",
        examples=["active"],
    )
    title: str = Field(
        ...,
        max_length=256,
        description="Short human-readable title.",
        examples=["Revocation status unknown for leaf certificate"],
    )
    description: str = Field(
        ...,
        description="Detailed explanation with actionable guidance.",
    )
    affected_asset: str = Field(
        ...,
        description="URL, hostname, IP, or other asset identifier.",
        examples=["example.test"],
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Evidence artifacts supporting this finding.",
    )
    observed_at: datetime = Field(
        ...,
        description="ISO-8601 UTC time at which the finding was observed.",
    )
    rule_version: str = Field(
        ...,
        description="Version of the detection rule that produced this finding.",
        examples=["cert-intel-v3.1"],
    )


# ── API response wrappers ───────────────────────────────────────────────


class FindingResponse(FindingEnvelope):
    """Standalone finding representation returned by the API.

    Identical to the envelope today; kept as a separate class so API-only
    fields (e.g., HATEOAS links) can be added later without mutating the
    agent contract.
    """


# ── review ───────────────────────────────────────────────────────────────


class FindingReviewRequest(BaseModel):
    """Body of ``POST /findings/{findingId}/review``.

    Analysts may mark a finding as accepted, disputed, or false_positive.
    A rationale is required for audit purposes.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    decision: ReviewDecision | None = Field(
        None,
        description="Constrained review decision: accepted, disputed, or false_positive.",
        examples=["accepted"],
    )
    status: ReviewDecision | None = Field(
        None,
        description="Alias for decision: accepted, disputed, or false_positive.",
        examples=["accepted"],
    )
    rationale: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Analyst explanation for the review decision.",
        examples=["Confirmed via independent OCSP responder check."],
    )

    @field_validator("rationale")
    @classmethod
    def validate_rationale_not_blank(cls, v: str) -> str:
        trimmed = (v or "").strip()
        if not trimmed:
            raise ValueError("Rationale cannot be blank or whitespace-only.")
        return trimmed

    @model_validator(mode="after")
    def validate_decision_or_status(self) -> FindingReviewRequest:
        if self.decision is None and self.status is None:
            raise ValueError("Either 'decision' or 'status' must be provided.")
        if self.decision is not None and self.status is not None and self.decision != self.status:
            raise ValueError("When both 'decision' and 'status' are provided, they must match.")
        if self.decision is None:
            self.decision = self.status
        elif self.status is None:
            self.status = self.decision
        return self


class FindingReviewResponse(BaseModel):
    """Response after successfully recording a finding review."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    finding_id: uuid.UUID = Field(
        ...,
        alias="findingId",
        description="Finding that was reviewed.",
    )
    status: str = Field(
        ...,
        description="Updated review status.",
        examples=["accepted"],
    )
    decision: str | None = Field(
        None,
        description="Review decision.",
        examples=["accepted"],
    )
    reviewed_at: datetime = Field(
        ...,
        alias="reviewedAt",
        description="ISO-8601 UTC timestamp of the review.",
    )
    reviewer_id: uuid.UUID = Field(
        ...,
        alias="reviewerId",
        description="UUID of the analyst who performed the review.",
    )
    reviewed_by: str | None = Field(
        None,
        alias="reviewedBy",
        description="Identifier of the analyst who performed the review.",
    )
    rationale: str = Field(
        ...,
        description="Analyst explanation for the review decision.",
    )
