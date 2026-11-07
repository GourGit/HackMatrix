"""Redirect hop model.

Records each HTTP redirect encountered while following a submitted URL,
preserving the full redirect chain with positional ordering.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, SmallInteger, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class RedirectHop(Base, UUIDMixin):
    """A single step in an HTTP redirect chain.

    ``position`` establishes the order within the chain (0-based).
    Each hop links back to the ``Evidence`` artefact that captured it.
    """

    __tablename__ = "redirect_hops"

    # ── Parent assessment ────────────────────────────────────────────────
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Chain ordering ───────────────────────────────────────────────────
    position: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="0-based position within the redirect chain.",
    )

    # ── URLs ─────────────────────────────────────────────────────────────
    from_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    to_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ── HTTP status code ─────────────────────────────────────────────────
    status_code: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        comment="HTTP status code triggering this redirect (301, 302, …).",
    )

    # ── Evidence link ────────────────────────────────────────────────────
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────────────
    assessment: Mapped["Assessment"] = relationship(
        "Assessment",
        back_populates="redirect_hops",
    )
    evidence: Mapped["Evidence | None"] = relationship(
        "Evidence",
        back_populates="redirect_hops",
    )

    __table_args__ = (
        Index(
            "ix_redirect_hops_assessment_position",
            "assessment_id",
            "position",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<RedirectHop id={self.id!s} pos={self.position} "
            f"{self.status_code} → {self.to_url!r}>"
        )
