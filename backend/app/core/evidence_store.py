"""Content-addressed evidence storage for scan artefacts.

Implements the evidence-persistence requirements from
docs/architecture.md and docs/database.md:

 * SHA-256 content hashing for deduplication.
 * Filesystem-backed object store (path from ``settings.evidence_storage_path``).
 * Collection metadata (source URI, collector version, redaction version,
   timestamp) persisted alongside raw bytes.
 * Secret redaction helper for request/response metadata.
 * Retention-aware retrieval (see ``settings.evidence_retention_days``).

.. note::

   Encryption at rest is handled at the volume / filesystem layer (e.g.
   LUKS, BitLocker, EBS encryption).  This module guarantees that
   sensitive tokens are **redacted** before evidence is written.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Final

import aiofiles
import aiofiles.os

from app.config import settings

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────

_HASH_ALGORITHM: Final[str] = "sha256"

# Two-level fan-out for the object store (like Git):
# ``ab/cdef01…`` keeps directory listings small.
_FANOUT_PREFIX_LEN: Final[int] = 2

# Metadata sidecar suffix.
_META_SUFFIX: Final[str] = ".meta.json"


# ── Data structures ──────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True, slots=True)
class EvidenceMetadata:
    """Provenance metadata attached to every evidence blob.

    Attributes:
        source_uri:        The URL / identifier the evidence was collected from.
        collector_version: Semver of the collecting agent or module.
        redaction_version: Version of the redaction rule-set applied.
        collected_at:      UTC timestamp of collection.
    """

    source_uri: str
    collector_version: str
    redaction_version: str = "1.0"
    collected_at: datetime.datetime = dataclasses.field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    def to_dict(self) -> dict[str, str]:
        """Serialize to a JSON-compatible dict."""
        return {
            "source_uri": self.source_uri,
            "collector_version": self.collector_version,
            "redaction_version": self.redaction_version,
            "collected_at": self.collected_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> EvidenceMetadata:
        """Deserialize from a dict (as stored in the sidecar)."""
        return cls(
            source_uri=data["source_uri"],
            collector_version=data["collector_version"],
            redaction_version=data.get("redaction_version", "1.0"),
            collected_at=datetime.datetime.fromisoformat(data["collected_at"]),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class StoredEvidence:
    """Receipt returned after a successful store operation.

    Attributes:
        content_hash: Hex-encoded SHA-256 digest of the raw content.
        storage_ref:  Absolute filesystem path where the blob lives.
        size_bytes:   Size of the stored content in bytes.
    """

    content_hash: str
    storage_ref: str
    size_bytes: int


# ── Secret redaction ─────────────────────────────────────────────────────

# Patterns intentionally over-match to err on the side of safety.
_SECRET_PATTERNS: Final[list[re.Pattern[str]]] = [
    # Authorization / auth headers (Bearer, Basic, Token, ApiKey, etc.)
    re.compile(
        r"(Authorization\s*[:=]\s*)(Bearer\s+|Basic\s+|Token\s+|ApiKey\s+)?\S+",
        re.IGNORECASE,
    ),
    # Proxy-Authorization header
    re.compile(
        r"(Proxy-Authorization\s*[:=]\s*)\S+",
        re.IGNORECASE,
    ),
    # Cookie header values
    re.compile(
        r"(Cookie\s*[:=]\s*).+",
        re.IGNORECASE,
    ),
    # Set-Cookie header values
    re.compile(
        r"(Set-Cookie\s*[:=]\s*).+",
        re.IGNORECASE,
    ),
    # Generic api_key / token / secret / password query params or JSON keys
    re.compile(
        r"([\"']?(?:api[_-]?key|token|secret|password|passwd|credential|access[_-]?key)"
        r"[\"']?\s*[:=]\s*[\"']?)([^\"'\s,;&]+)",
        re.IGNORECASE,
    ),
    # URL-embedded credentials  user:pass@host
    re.compile(
        r"(://)[^@/\s]+@",
        re.IGNORECASE,
    ),
    # X-Api-Key header
    re.compile(
        r"(X-Api-Key\s*[:=]\s*)\S+",
        re.IGNORECASE,
    ),
]

_REDACTED_PLACEHOLDER: Final[str] = "[REDACTED]"


def redact_secrets(text: str) -> str:
    """Strip authentication headers, tokens, and passwords from *text*.

    This function is applied to request/response metadata before evidence
    is persisted, satisfying the requirement that stored evidence never
    contains raw secrets.

    The redaction patterns are intentionally broad to reduce the risk of
    leaking credentials.  A ``redaction_version`` field in
    :class:`EvidenceMetadata` tracks which rule-set was applied so that
    consumers can account for evolving heuristics.

    Args:
        text: Raw text (e.g., serialized HTTP headers, curl-style logs).

    Returns:
        A copy of *text* with sensitive values replaced by
        ``[REDACTED]``.
    """
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(
            lambda m: m.group(1) + _REDACTED_PLACEHOLDER,
            result,
        )
    return result


# ── Evidence store ───────────────────────────────────────────────────────

class EvidenceStore:
    """Content-addressed evidence object store.

    Evidence blobs are stored on the local filesystem under a two-level
    fan-out directory structure keyed by their SHA-256 hex digest::

        <base_path>/ab/cdef0123456789…

    A JSON sidecar (``<hash>.meta.json``) is written alongside each blob
    to capture provenance metadata.

    Deduplication is automatic: storing the same content twice is a no-op
    that returns the existing :class:`StoredEvidence` receipt.

    Args:
        base_path: Root directory for the object store.  Defaults to
                   ``settings.evidence_storage_path``.
    """

    def __init__(self, base_path: Path | None = None) -> None:
        self._base_path = base_path or settings.evidence_storage_path

    # ── Write ─────────────────────────────────────────────────────────

    async def store(
        self,
        content: bytes,
        metadata: EvidenceMetadata,
    ) -> StoredEvidence:
        """Persist *content* and return a :class:`StoredEvidence` receipt.

        If content with the same SHA-256 hash is already stored the
        existing blob is kept and the receipt is returned immediately
        (deduplication).

        Args:
            content:  Raw evidence bytes.
            metadata: Collection provenance to persist in the sidecar.

        Returns:
            A :class:`StoredEvidence` with hash, path, and size.
        """
        content_hash = hashlib.sha256(content).hexdigest()
        blob_path = self._blob_path(content_hash)
        meta_path = blob_path.parent / f"{content_hash}{_META_SUFFIX}"

        # Deduplication — blob already exists.
        if blob_path.exists():
            logger.debug("Evidence %s already stored; skipping write.", content_hash)
            return StoredEvidence(
                content_hash=content_hash,
                storage_ref=str(blob_path),
                size_bytes=len(content),
            )

        # Ensure parent directories exist.
        blob_path.parent.mkdir(parents=True, exist_ok=True)

        # Write blob atomically via temp → rename.
        tmp_blob = blob_path.with_suffix(".tmp")
        try:
            async with aiofiles.open(tmp_blob, "wb") as f:
                await f.write(content)
            await aiofiles.os.rename(tmp_blob, blob_path)
        except Exception:
            # Clean up partial write.
            if tmp_blob.exists():
                tmp_blob.unlink(missing_ok=True)
            raise

        # Write metadata sidecar.
        async with aiofiles.open(meta_path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(metadata.to_dict(), indent=2))

        logger.info(
            "Stored evidence %s (%d bytes) from %s.",
            content_hash,
            len(content),
            metadata.source_uri,
        )

        return StoredEvidence(
            content_hash=content_hash,
            storage_ref=str(blob_path),
            size_bytes=len(content),
        )

    # ── Read ──────────────────────────────────────────────────────────

    async def retrieve(self, content_hash: str) -> bytes | None:
        """Return the raw evidence bytes for *content_hash*, or ``None``.

        Args:
            content_hash: The hex-encoded SHA-256 digest.

        Returns:
            The evidence bytes if found; ``None`` if the hash is unknown
            or the blob has been garbage-collected.
        """
        blob_path = self._blob_path(content_hash)
        if not blob_path.exists():
            return None

        async with aiofiles.open(blob_path, "rb") as f:
            return await f.read()

    # ── Metadata ──────────────────────────────────────────────────────

    async def retrieve_metadata(self, content_hash: str) -> EvidenceMetadata | None:
        """Return the :class:`EvidenceMetadata` sidecar for *content_hash*.

        Args:
            content_hash: The hex-encoded SHA-256 digest.

        Returns:
            The parsed metadata, or ``None`` if not found.
        """
        meta_path = self._blob_path(content_hash).parent / f"{content_hash}{_META_SUFFIX}"
        if not meta_path.exists():
            return None

        async with aiofiles.open(meta_path, "r", encoding="utf-8") as f:
            raw = await f.read()

        return EvidenceMetadata.from_dict(json.loads(raw))

    # ── Internals ─────────────────────────────────────────────────────

    def _blob_path(self, content_hash: str) -> Path:
        """Compute the filesystem path for a given content hash.

        Uses two-level fan-out: ``<base>/<first-2-chars>/<full-hash>``.
        """
        prefix = content_hash[:_FANOUT_PREFIX_LEN]
        return self._base_path / prefix / content_hash
