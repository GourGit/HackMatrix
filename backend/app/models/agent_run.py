"""Agent run model.

Tracks the lifecycle of a single agent execution within an assessment.
Each assessment spawns one run per configured agent.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin
from app.schemas.common import AgentName, AgentRunStatus


class AgentRun(Base, UUIDMixin):
    """Execution record for a single agent within an assessment.

    The ``status`` tracks progress through
    ``QUEUED → RUNNING → COMPLETED | FAILED | TIMEOUT``.
    ``rule_version`` pins the detection-rule set used by this run.
    """

    __tablename__ = "agent_runs"

    # ── Parent assessment ────────────────────────────────────────────────
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Agent identification ─────────────────────────────────────────────
    agent_name: Mapped[AgentName] = mapped_column(
        String(50),
        nullable=False,
    )

    # ── Status & versioning ──────────────────────────────────────────────
    status: Mapped[AgentRunStatus] = mapped_column(
        String(20),
        nullable=False,
        default=AgentRunStatus.QUEUED,
    )
    rule_version: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        comment="Semantic version of the rule set this run used.",
    )

    # ── Timing ───────────────────────────────────────────────────────────
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Error handling ───────────────────────────────────────────────────
    error_code: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        comment="Machine-readable error code when status is FAILED.",
    )

    # ── Relationships ────────────────────────────────────────────────────
    assessment: Mapped["Assessment"] = relationship(
        "Assessment",
        back_populates="agent_runs",
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="agent_run",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    evidence_items: Mapped[list["Evidence"]] = relationship(
        "Evidence",
        back_populates="agent_run",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_agent_runs_assessment_status", "assessment_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<AgentRun id={self.id!s} agent={self.agent_name} "
            f"status={self.status}>"
        )
