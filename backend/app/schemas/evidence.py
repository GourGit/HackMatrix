"""Pydantic v2 schemas for the evidence endpoint.

Covers ``GET /evidence/{evidenceId}``, which returns redacted metadata
and a time-limited artifact download link.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.schemas.common import EvidenceKind


# ── helpers ──────────────────────────────────────────────────────────────


def _to_camel(name: str) -> str:
    """Convert a snake_case Python name to camelCase for JSON aliases."""
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


# ── models ───────────────────────────────────────────────────────────────


class EvidenceMetadata(BaseModel):
    """Redacted metadata attached to an evidence artifact.

    Sensitive details (raw payloads, internal IPs) are stripped before
    this reaches the caller.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    kind: EvidenceKind = Field(
        ...,
        description="Category of evidence (tls_handshake, certificate, …).",
        examples=["tls_handshake"],
    )
    mime_type: str = Field(
        ...,
        description="MIME type of the stored artifact.",
        examples=["application/json"],
    )
    size_bytes: int | None = Field(
        None,
        ge=0,
        description="Size of the artifact in bytes (if known).",
        examples=[4096],
    )
    sha256: str | None = Field(
        None,
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest of the artifact for integrity verification.",
    )
    collected_at: datetime = Field(
        ...,
        description="ISO-8601 UTC timestamp when the evidence was collected.",
    )
    agent: str = Field(
        ...,
        description="Agent that collected this evidence.",
        examples=["certificate-intelligence"],
    )
    labels: dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary key-value labels (e.g., hostname, port).",
    )


class EvidenceResponse(BaseModel):
    """``GET /evidence/{evidenceId}`` response.

    Returns redacted metadata plus a time-limited pre-signed URL that
    the caller can use to download the actual artifact.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    evidence_id: uuid.UUID = Field(
        ...,
        description="Unique evidence identifier.",
        examples=["c1d2e3f4-a5b6-7890-cdef-1234567890ab"],
    )
    assessment_id: uuid.UUID = Field(
        ...,
        description="Assessment this evidence belongs to.",
    )
    finding_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Findings that reference this evidence.",
    )
    metadata: EvidenceMetadata = Field(
        ...,
        description="Redacted metadata about the evidence artifact.",
    )
    artifact_url: HttpUrl = Field(
        ...,
        description="Time-limited pre-signed download URL for the artifact.",
        examples=["https://storage.example.com/evidence/abc?token=xyz"],
    )
    expires_at: datetime = Field(
        ...,
        description="ISO-8601 UTC expiry for the artifact URL.",
    )
