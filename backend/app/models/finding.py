"""Finding model and finding ↔ evidence junction table.

A finding is a discrete security issue discovered by an agent run.
Each finding may reference multiple pieces of evidence via the
``finding_evidence`` association table.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin
from app.schemas.common import FindingStatus, Severity

# ── Junction table (many-to-many: findings ↔ evidence) ──────────────────

finding_evidence = Table(
    "finding_evidence",
    Base.metadata,
    Column(
        "finding_id",
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "evidence_id",
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Finding(Base, UUIDMixin):
    """A discrete security finding produced by an agent run.

    Findings carry a ``severity``, a machine-readable ``type``, a
    ``confidence`` score, and a ``score_impact`` that feeds into the
    composite assessment score.
    """

    __tablename__ = "findings"

    # ── Provenance ───────────────────────────────────────────────────────
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agent_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Classification ───────────────────────────────────────────────────
    type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Machine-readable finding type, e.g. 'missing-hsts'.",
    )
    severity: Mapped[Severity] = mapped_column(
        String(20),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Agent confidence 0.0–1.0.",
    )
    score_impact: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Weighted contribution to the composite score.",
    )

    # ── Review ───────────────────────────────────────────────────────────
    status: Mapped[FindingStatus] = mapped_column(
        String(20),
        nullable=False,
        default=FindingStatus.ACTIVE,
    )
    decision: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        comment="Review verdict (accepted, disputed, false_positive).",
    )
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="User or principal UUID who performed the review.",
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when the review was recorded.",
    )
    rationale: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Analyst explanation for the review decision.",
    )

    # ── Detail ───────────────────────────────────────────────────────────
    asset: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Affected asset (URL, header, cookie name hash, etc.).",
    )
    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable description of the finding.",
    )
    rule_version: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────────────
    assessment: Mapped["Assessment"] = relationship(
        "Assessment",
        back_populates="findings",
    )
    agent_run: Mapped["AgentRun"] = relationship(
        "AgentRun",
        back_populates="findings",
    )
    evidence_items: Mapped[list["Evidence"]] = relationship(
        "Evidence",
        secondary=finding_evidence,
        back_populates="findings",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_findings_type_severity", "type", "severity"),
        Index("ix_findings_assessment_type", "assessment_id", "type"),
    )

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id!s} type={self.type!r} "
            f"severity={self.severity} status={self.status}>"
        )
