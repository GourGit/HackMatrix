"""Evidence model.

Evidence items are immutable artefacts collected by agents — HTTP responses,
TLS handshakes, certificates, screenshots, etc.  Raw content is stored
externally (object storage); the DB holds only metadata and a content hash.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin
from app.schemas.common import EvidenceKind


class Evidence(Base, UUIDMixin):
    """Collected evidence artefact.

    Never stores raw sensitive data (response bodies, credentials, cookie
    values).  ``content_hash`` enables deduplication; ``storage_ref``
    points to the redacted blob in object storage.
    """

    __tablename__ = "evidence"

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
    kind: Mapped[EvidenceKind] = mapped_column(
        String(30),
        nullable=False,
    )

    # ── Storage ──────────────────────────────────────────────────────────
    source_uri: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Original URI this evidence was collected from.",
    )
    content_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="SHA-256 hex digest of the redacted content.",
    )
    storage_ref: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Object-storage key or path for the redacted blob.",
    )

    # ── Timing & versioning ──────────────────────────────────────────────
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    collector_version: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )
    redaction_version: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )
    retention_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC deadline after which this evidence may be purged.",
    )

    # ── Relationships ────────────────────────────────────────────────────
    assessment: Mapped["Assessment"] = relationship(
        "Assessment",
        back_populates="evidence_items",
    )
    agent_run: Mapped["AgentRun"] = relationship(
        "AgentRun",
        back_populates="evidence_items",
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        secondary="finding_evidence",
        back_populates="evidence_items",
        lazy="selectin",
    )

    # One-to-one back-refs from observation tables (nullable FK there)
    redirect_hops: Mapped[list["RedirectHop"]] = relationship(
        "RedirectHop",
        back_populates="evidence",
        lazy="selectin",
    )
    certificate_observations: Mapped[list["CertificateObservation"]] = relationship(
        "CertificateObservation",
        back_populates="evidence",
        lazy="selectin",
    )
    service_observations: Mapped[list["ServiceObservation"]] = relationship(
        "ServiceObservation",
        back_populates="evidence",
        lazy="selectin",
    )
    cookie_observations: Mapped[list["CookieObservation"]] = relationship(
        "CookieObservation",
        back_populates="evidence",
        lazy="selectin",
    )
    sourced_indicators: Mapped[list["Indicator"]] = relationship(
        "Indicator",
        back_populates="source_evidence",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_evidence_content_hash", "content_hash"),
        Index("ix_evidence_assessment_kind", "assessment_id", "kind"),
    )

    def __repr__(self) -> str:
        return (
            f"<Evidence id={self.id!s} kind={self.kind} "
            f"hash={self.content_hash[:12]}…>"
        )
