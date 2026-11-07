"""Audit event model.

Append-only log of security-relevant actions within the platform.
Audit events are never updated or deleted — they form an immutable
record for compliance and forensic review.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, UUIDMixin


class AuditEvent(Base, UUIDMixin, TenantMixin):
    """Immutable audit-trail entry.

    Each event records *who* performed *what* action on *which* entity,
    with optional ``metadata_json`` for action-specific context.

    .. warning::
       This table is **append-only**.  Application code must never issue
       UPDATE or DELETE against ``audit_events``.
    """

    __tablename__ = "audit_events"

    # ── Actor ────────────────────────────────────────────────────────────
    actor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="User or service principal that triggered the event.",
    )

    # ── Action ───────────────────────────────────────────────────────────
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Machine-readable action, e.g. 'assessment.created'.",
    )

    # ── Entity reference ─────────────────────────────────────────────────
    entity_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Polymorphic entity type, e.g. 'assessment', 'indicator'.",
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    # ── Metadata ─────────────────────────────────────────────────────────
    metadata_json: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Action-specific context (diff, old/new values, etc.).",
    )

    # ── Timestamp ────────────────────────────────────────────────────────
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_audit_events_entity", "entity_type", "entity_id"),
        Index("ix_audit_events_tenant_action", "tenant_id", "action"),
        Index("ix_audit_events_occurred_at", "occurred_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id!s} action={self.action!r} "
            f"entity={self.entity_type}:{self.entity_id!s}>"
        )
