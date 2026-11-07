"""Authorization scope model.

Defines the boundary within which an assessment is permitted to run —
subjects, target URLs/domains, allowed ports, and validity window.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TenantMixin, TimestampMixin, UUIDMixin
from app.schemas.common import ScopeStatus


class AuthorizationScope(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """Row-level authorisation boundary for security assessments.

    Each scope records *who* is authorised (``subject_id``), *what* targets
    may be assessed, the allowed port range, and a validity window.
    Assessments reference a scope to prove they were explicitly authorised.
    """

    __tablename__ = "authorization_scopes"

    # ── Subject & targets ────────────────────────────────────────────────
    subject_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="User or service principal authorised to assess targets.",
    )
    targets_json: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="Array of allowed target URLs / domains / CIDRs.",
    )
    allowed_ports_json: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Optional allowlist of TCP/UDP ports (null = all ports).",
    )

    # ── Validity window ──────────────────────────────────────────────────
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    valid_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # ── Attestation & status ─────────────────────────────────────────────
    attestation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable attestation or reference to legal authorisation.",
    )
    status: Mapped[ScopeStatus] = mapped_column(
        String(20),
        nullable=False,
        default=ScopeStatus.ACTIVE,
    )

    # ── Relationships ────────────────────────────────────────────────────
    assessments: Mapped[list["Assessment"]] = relationship(
        "Assessment",
        back_populates="scope",
        lazy="selectin",
    )
    service_observations: Mapped[list["ServiceObservation"]] = relationship(
        "ServiceObservation",
        back_populates="authorization_scope",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_authorization_scopes_status", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuthorizationScope id={self.id!s} "
            f"subject={self.subject_id!s} status={self.status}>"
        )
