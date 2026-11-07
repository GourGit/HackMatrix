"""Certificate observation model.

Stores TLS certificate intelligence gathered during an assessment —
fingerprints, chain data, CA validation, hostname matching, CT log
presence, revocation status, and cryptographic parameters.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin
from app.schemas.common import CertificateFieldStatus, RevocationStatus


class CertificateObservation(Base, UUIDMixin):
    """TLS certificate observation for a given host.

    Cryptographic details (key size, signature algorithm, etc.) and the
    full chain are stored as JSONB to accommodate future extension
    without schema migration.
    """

    __tablename__ = "certificate_observations"

    # ── Parent assessment ────────────────────────────────────────────────
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Host & fingerprint ───────────────────────────────────────────────
    host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    leaf_fingerprint: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="SHA-256 fingerprint of the leaf certificate.",
    )

    # ── Chain ────────────────────────────────────────────────────────────
    chain_json: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Ordered array of certificate subjects in the chain.",
    )

    # ── Validation statuses ──────────────────────────────────────────────
    ca_status: Mapped[CertificateFieldStatus] = mapped_column(
        String(20),
        nullable=False,
    )
    hostname_status: Mapped[CertificateFieldStatus] = mapped_column(
        String(20),
        nullable=False,
    )
    ct_status: Mapped[CertificateFieldStatus] = mapped_column(
        String(20),
        nullable=False,
        comment="Certificate Transparency log presence.",
    )
    revocation_status: Mapped[RevocationStatus] = mapped_column(
        String(20),
        nullable=False,
    )

    # ── Cryptographic parameters ─────────────────────────────────────────
    crypto_json: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Key size, signature algorithm, etc.",
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
        back_populates="certificate_observations",
    )
    evidence: Mapped["Evidence | None"] = relationship(
        "Evidence",
        back_populates="certificate_observations",
    )

    __table_args__ = (
        Index(
            "ix_cert_obs_assessment_host",
            "assessment_id",
            "host",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<CertificateObservation id={self.id!s} host={self.host!r} "
            f"ca={self.ca_status} revocation={self.revocation_status}>"
        )
