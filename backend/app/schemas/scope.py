"""Authorization scope schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import ScopeStatus


def _to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


class CreateScopeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, alias_generator=_to_camel)

    targets: List[str] = Field(..., description="Allowed URL patterns, hostnames, or domains", min_length=1)
    allowed_ports: Optional[List[int]] = Field(default=None, description="Optional allowed port list")
    valid_from: Optional[datetime] = Field(default=None, description="Scope start time (defaults to now)")
    valid_until: Optional[datetime] = Field(default=None, description="Scope expiration time (defaults to 30 days)")
    attestation: str = Field(..., description="Legal/organizational attestation statement", min_length=5)


class ScopeResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    id: uuid.UUID
    tenant_id: uuid.UUID
    subject_id: uuid.UUID
    targets: List[str] = Field(
        validation_alias="targets_json",
        serialization_alias="targets",
    )
    allowed_ports: Optional[List[int]] = Field(
        default=None,
        validation_alias="allowed_ports_json",
        serialization_alias="allowedPorts",
    )
    valid_from: datetime
    valid_until: datetime
    attestation: Optional[str] = None
    status: ScopeStatus
    created_at: datetime

