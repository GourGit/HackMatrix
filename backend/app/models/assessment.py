"""Assessment model.

An assessment represents a single security evaluation of a submitted URL,
running through the agent pipeline and producing a composite trust score.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TenantMixin, TimestampMixin, UUIDMixin
from app.schemas.common import AssessmentStatus, ScoreBand


class Assessment(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """A security assessment of a submitted URL.

    Assessments progress through ``QUEUED → RUNNING → COMPLETED`` (or
    ``PARTIAL`` / ``FAILED``).  The final ``score`` and ``score_band``
    are computed once all agent runs have finished.
    """

    __tablename__ = "assessments"

    # ── Scope link ───────────────────────────────────────────────────────
    scope_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorization_scopes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── URL tracking ─────────────────────────────────────────────────────
    submitted_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Original URL as entered by the user.",
    )
    normalized_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Canonicalised URL used by agents.",
    )

    # ── Status & scoring ─────────────────────────────────────────────────
    status: Mapped[AssessmentStatus] = mapped_column(
        String(20),
        nullable=False,
        default=AssessmentStatus.QUEUED,
    )
    score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Composite trust-risk score 0-100.",
    )
    score_band: Mapped[ScoreBand | None] = mapped_column(
        String(20),
        nullable=True,
    )
    score_version: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        comment="Scoring algorithm version that produced the score.",
    )
    checks_json: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Durable check availability states (ct, revocation, safe_scan, etc.).",
    )

    # ── Timestamps ───────────────────────────────────────────────────────
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────────────
    scope: Mapped["AuthorizationScope"] = relationship(
        "AuthorizationScope",
        back_populates="assessments",
    )
    agent_runs: Mapped[list["AgentRun"]] = relationship(
        "AgentRun",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    evidence_items: Mapped[list["Evidence"]] = relationship(
        "Evidence",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    redirect_hops: Mapped[list["RedirectHop"]] = relationship(
        "RedirectHop",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    certificate_observations: Mapped[list["CertificateObservation"]] = relationship(
        "CertificateObservation",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    service_observations: Mapped[list["ServiceObservation"]] = relationship(
        "ServiceObservation",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    cookie_observations: Mapped[list["CookieObservation"]] = relationship(
        "CookieObservation",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_assessments_status", "status"),
        Index("ix_assessments_tenant_status", "tenant_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<Assessment id={self.id!s} url={self.normalized_url!r} "
            f"status={self.status} score={self.score}>"
        )
