"""Pydantic v2 schemas for the indicator / threat-intelligence endpoints.

Covers:
- POST /indicators  → CreateIndicatorRequest
- GET  /indicators  → IndicatorResponse (list items), IndicatorQueryParams
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

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
        ...,
        min_length=1,
        description="Evidence artifacts supporting this indicator.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Submitter-asserted confidence (0–1).",
        examples=[0.85],
    )
    sharing_policy: SharingPolicy = Field(
        SharingPolicy.PRIVATE,
        description="Visibility scope for this indicator.",
        examples=["tenant"],
    )
    source: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Provenance label or feed name.",
        examples=["manual-analyst-submission"],
    )


# ── response models ─────────────────────────────────────────────────────


class IndicatorResponse(BaseModel):
    """Representation of an indicator returned by the API.

    Includes provenance labels so consumers can trace data lineage.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    indicator_id: uuid.UUID = Field(
        ...,
        description="Unique indicator identifier.",
        examples=["d4e5f6a7-b8c9-0123-4567-890abcdef012"],
    )
    value: str = Field(
        ...,
        description="The indicator value.",
        examples=["evil.example.com"],
    )
    type: IndicatorType = Field(
        ...,
        description="Indicator type classification.",
        examples=["domain"],
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Linked evidence artifacts.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence at time of submission.",
        examples=[0.85],
    )
    sharing_policy: SharingPolicy = Field(
        ...,
        description="Current visibility scope.",
        examples=["tenant"],
    )
    source: str = Field(
        ...,
        description="Provenance label.",
        examples=["manual-analyst-submission"],
    )
    review_status: ReviewStatus = Field(
        ...,
        description="Current review status.",
        examples=["pending_review"],
    )
    created_at: datetime = Field(
        ...,
        description="ISO-8601 UTC creation timestamp.",
    )
    reviewed_at: datetime | None = Field(
        None,
        description="ISO-8601 UTC timestamp of last review (if any).",
    )
    tenant_id: uuid.UUID = Field(
        ...,
        description="Owning tenant identifier.",
    )


# ── query params ─────────────────────────────────────────────────────────


class IndicatorQueryParams(BaseModel):
    """Query parameters for ``GET /indicators?value=&type=``.

    Used with FastAPI's ``Depends()`` for query-string validation.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    value: str | None = Field(
        None,
        min_length=1,
        max_length=2048,
        description="Filter by indicator value (exact or prefix match).",
        examples=["evil.example.com"],
    )
    type: IndicatorType | None = Field(
        None,
        description="Filter by indicator type.",
        examples=["domain"],
    )
    sharing_policy: SharingPolicy | None = Field(
        None,
        description="Filter by sharing policy.",
    )
    limit: int = Field(
        50,
        ge=1,
        le=500,
        description="Maximum number of results to return.",
    )
    offset: int = Field(
        0,
        ge=0,
        description="Pagination offset.",
    )
