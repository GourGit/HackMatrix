"""Indicator model.

Threat indicators extracted from evidence — URLs, domains, IPs, email
addresses, hashes, and certificate fingerprints that may be shared with
the community feed or kept private per tenant policy.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TenantMixin, UUIDMixin
from app.schemas.common import IndicatorType, ReviewStatus, SharingPolicy


class Indicator(Base, UUIDMixin, TenantMixin):
    """A normalised threat indicator derived from assessment evidence.

    ``value_normalized`` stores a canonicalised representation (lower-cased
    domain, defanged URL, etc.) suitable for deduplication and matching.
    The ``sharing_policy`` and ``review_status`` gate whether the indicator
    feeds into the community threat-intelligence stream.
    """

    __tablename__ = "indicators"

    # ── Classification ───────────────────────────────────────────────────
    type: Mapped[IndicatorType] = mapped_column(
        String(40),
        nullable=False,
    )
    value_normalized: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        comment="Canonicalised indicator value for matching.",
    )

    # ── Confidence ───────────────────────────────────────────────────────
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Confidence that this indicator is malicious (0.0–1.0).",
    )

    # ── Policy & review ──────────────────────────────────────────────────
    sharing_policy: Mapped[SharingPolicy] = mapped_column(
        String(20),
        nullable=False,
        default=SharingPolicy.PRIVATE,
    )
    review_status: Mapped[ReviewStatus] = mapped_column(
        String(20),
        nullable=False,
        default=ReviewStatus.PENDING_REVIEW,
    )

    # ── Provenance ───────────────────────────────────────────────────────
    source_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Timestamps ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # ── Relationships ────────────────────────────────────────────────────
    source_evidence: Mapped["Evidence | None"] = relationship(
        "Evidence",
        back_populates="sourced_indicators",
    )

    __table_args__ = (
        Index("ix_indicators_type_value", "type", "value_normalized"),
        Index("ix_indicators_tenant_type", "tenant_id", "type"),
    )

    def __repr__(self) -> str:
        return (
            f"<Indicator id={self.id!s} type={self.type} "
            f"policy={self.sharing_policy} review={self.review_status}>"
        )
