"""Pydantic v2 schemas for the indicator / threat-intelligence endpoints.

Covers:
- POST /indicators  → CreateIndicatorRequest, CreateIndicatorResponse
- GET  /indicators  → IndicatorResponse, IndicatorListResponse, IndicatorQueryParams
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.indicator_normalizer import normalize_indicator_value
from app.schemas.common import (
    IndicatorType,
    ReviewStatus,
    SharingPolicy,
)


# ── helpers ──────────────────────────────────────────────────────────────


def _to_camel(name: str) -> str:
    """Convert a snake_case Python name to camelCase for JSON aliases."""
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


# ── request models ───────────────────────────────────────────────────────


class CreateIndicatorRequest(BaseModel):
    """Body of ``POST /indicators``.

    Submits a new threat indicator with supporting evidence references.
    The indicator begins in ``pending_review`` status.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    value: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The indicator value (URL, domain, IP, hash, etc.).",
        examples=["evil.example.com"],
    )
    type: IndicatorType = Field(
        ...,
        description="Indicator type classification.",
        examples=["domain"],
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        max_length=50,
        description="Evidence artifacts supporting this indicator.",
    )
    source_evidence_id: uuid.UUID | None = Field(
        default=None,
        description="Primary evidence artifact supporting this indicator.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Submitter-asserted confidence (0–1).",
        examples=[0.85],
    )
    sharing_policy: SharingPolicy = Field(
        default=SharingPolicy.PRIVATE,
        description="Visibility scope for this indicator.",
        examples=["tenant"],
    )
    source: str | None = Field(
        default=None,
        max_length=512,
        description="Provenance label or feed name.",
        examples=["manual-analyst-submission"],
    )

    @model_validator(mode="after")
    def validate_and_normalize(self) -> CreateIndicatorRequest:
        """Validate and normalize indicator value according to its declared type."""
        self.value = normalize_indicator_value(self.value, self.type)
        return self


# ── response models ─────────────────────────────────────────────────────


class CreateIndicatorResponse(BaseModel):
    """Response returned upon indicator creation or deduplication."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    indicator_id: uuid.UUID = Field(
        ...,
        alias="indicatorId",
        description="Unique identifier of the created or existing indicator.",
    )
    status: str = Field(
        ReviewStatus.PENDING_REVIEW.value,
        description="Current review status.",
    )
    is_duplicate: bool | None = Field(
        default=None,
        alias="isDuplicate",
        description="Whether this submission matched an existing indicator.",
    )


class IndicatorResponse(BaseModel):
    """Representation of an indicator returned by the API.

    Includes provenance labels and canonicalized values.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    indicator_id: uuid.UUID = Field(
        ...,
        alias="indicatorId",
        description="Unique indicator identifier.",
    )
    value: str = Field(
        ...,
        description="The normalized indicator value.",
    )
    type: IndicatorType = Field(
        ...,
        description="Indicator type classification.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0 to 1.0).",
    )
    sharing_policy: SharingPolicy = Field(
        ...,
        alias="sharingPolicy",
        description="Current visibility scope.",
    )
    review_status: ReviewStatus = Field(
        ...,
        alias="reviewStatus",
        description="Current review status.",
    )
    source_evidence_id: uuid.UUID | None = Field(
        None,
        alias="sourceEvidenceId",
        description="Supporting evidence artifact UUID.",
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        alias="evidenceIds",
        description="All linked evidence IDs.",
    )
    created_at: datetime = Field(
        ...,
        alias="createdAt",
        description="ISO-8601 UTC creation timestamp.",
    )
    tenant_id: uuid.UUID = Field(
        ...,
        alias="tenantId",
        description="Owning tenant identifier.",
    )
    source: str | None = Field(
        None,
        description="Provenance label.",
    )


class IndicatorListResponse(BaseModel):
    """Paginated list of indicators."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    items: list[IndicatorResponse]
    total: int
    page: int
    page_size: int = Field(..., alias="pageSize")


# ── query params ─────────────────────────────────────────────────────────


class IndicatorQueryParams(BaseModel):
    """Query parameters for ``GET /indicators?value=&type=``."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    value: str | None = Field(
        None,
        min_length=1,
        max_length=2048,
        description="Filter by indicator value (exact match after normalization).",
    )
    type: IndicatorType | None = Field(
        None,
        description="Filter by indicator type.",
    )
    sharing_policy: SharingPolicy | None = Field(
        None,
        alias="sharingPolicy",
        description="Filter by sharing policy.",
    )
    page: int = Field(
        1,
        ge=1,
        description="Page number.",
    )
    page_size: int = Field(
        20,
        ge=1,
        le=100,
        alias="pageSize",
        description="Items per page.",
    )
    limit: int | None = Field(
        None,
        ge=1,
        le=500,
        description="Limit items (alternative pagination).",
    )
    offset: int | None = Field(
        None,
        ge=0,
        description="Offset items (alternative pagination).",
    )
