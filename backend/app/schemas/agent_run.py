"""Pydantic v2 schema for agent-run tracking.

Each assessment spawns one run per agent.  This schema exposes the
run's status, timing, and (when applicable) error detail.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import AgentName, AgentRunStatus


# ── helpers ──────────────────────────────────────────────────────────────


def _to_camel(name: str) -> str:
    """Convert a snake_case Python name to camelCase for JSON aliases."""
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


# ── response model ───────────────────────────────────────────────────────


class AgentRunResponse(BaseModel):
    """Representation of a single agent run within an assessment.

    Tracks which agent was invoked, its lifecycle status, timing, the
    number of findings it produced, and any error information.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        alias_generator=_to_camel,
    )

    run_id: uuid.UUID = Field(
        ...,
        description="Unique agent-run identifier.",
        examples=["e1f2a3b4-c5d6-7890-ef01-234567890abc"],
    )
    assessment_id: uuid.UUID = Field(
        ...,
        description="Assessment this run belongs to.",
    )
    agent: AgentName = Field(
        ...,
        description="Name of the agent that was executed.",
        examples=["certificate-intelligence"],
    )
    status: AgentRunStatus = Field(
        ...,
        description="Current run status.",
        examples=["completed"],
    )
    started_at: datetime | None = Field(
        None,
        description="ISO-8601 UTC timestamp when the agent began execution.",
    )
    completed_at: datetime | None = Field(
        None,
        description="ISO-8601 UTC timestamp when the agent finished.",
    )
    duration_ms: int | None = Field(
        None,
        ge=0,
        description="Wall-clock duration in milliseconds.",
        examples=[1234],
    )
    finding_count: int = Field(
        0,
        ge=0,
        description="Number of findings the agent produced.",
        examples=[3],
    )
    error_code: str | None = Field(
        None,
        max_length=128,
        description="Machine-readable error code (set on failure / timeout).",
        examples=["OCSP_RESPONDER_TIMEOUT"],
    )
    error_message: str | None = Field(
        None,
        max_length=2000,
        description="Human-readable error description.",
    )
