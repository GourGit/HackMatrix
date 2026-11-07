"""Cookie observation model.

Stores metadata about cookies observed during an assessment.  Raw cookie
values are never persisted — only the hashed name, security attributes,
and domain/path are recorded.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class CookieObservation(Base, UUIDMixin):
    """Metadata for a single cookie observed in a Set-Cookie header.

    ``name_hash`` is a one-way hash of the cookie name so the original
    name is not stored.  Security attributes (``secure``, ``http_only``,
    ``same_site``) drive the privacy-software agent's scoring.
    """

    __tablename__ = "cookie_observations"

    # ── Parent assessment ────────────────────────────────────────────────
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Cookie identity (hashed) ─────────────────────────────────────────
    name_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="SHA-256 of the cookie name — raw name never stored.",
    )

    # ── Scope ────────────────────────────────────────────────────────────
    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    path: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Security attributes ──────────────────────────────────────────────
    secure: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    http_only: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    same_site: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
        comment="'Strict', 'Lax', 'None', or null if absent.",
    )
    max_age: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Max-Age in seconds, null if session cookie.",
    )
    third_party_context: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if the cookie was set in a third-party context.",
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
        back_populates="cookie_observations",
    )
    evidence: Mapped["Evidence | None"] = relationship(
        "Evidence",
        back_populates="cookie_observations",
    )

    __table_args__ = (
        Index(
            "ix_cookie_obs_assessment_domain",
            "assessment_id",
            "domain",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<CookieObservation id={self.id!s} domain={self.domain!r} "
            f"secure={self.secure} httpOnly={self.http_only}>"
        )
