"""Service observation model.

Records open ports, protocols, and banner/version information discovered
during an assessment's surface-scan agent run.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class ServiceObservation(Base, UUIDMixin):
    """An observed network service on a target host.

    The ``authorization_scope_id`` link proves the port/protocol was
    within the assessment's authorised boundary.
    """

    __tablename__ = "service_observations"

    # ── Parent assessment ────────────────────────────────────────────────
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Service details ──────────────────────────────────────────────────
    host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    protocol: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Transport protocol: tcp, udp, etc.",
    )
    banner: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Raw service banner (redacted where necessary).",
    )
    version_hint: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Parsed version string if available.",
    )

    # ── Authorization scope link ─────────────────────────────────────────
    authorization_scope_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorization_scopes.id", ondelete="SET NULL"),
        nullable=True,
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
        back_populates="service_observations",
    )
    authorization_scope: Mapped["AuthorizationScope | None"] = relationship(
        "AuthorizationScope",
        back_populates="service_observations",
    )
    evidence: Mapped["Evidence | None"] = relationship(
        "Evidence",
        back_populates="service_observations",
    )

    __table_args__ = (
        Index(
            "ix_service_obs_assessment_host_port",
            "assessment_id",
            "host",
            "port",
        ),
        Index(
            "ix_service_obs_scope",
            "authorization_scope_id",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<ServiceObservation id={self.id!s} "
            f"{self.host}:{self.port}/{self.protocol}>"
        )
