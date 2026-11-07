"""Base class and common data structures for all TrustLens agents.

Every agent is bounded, auditable, and emits normalized findings conforming
to the envelope defined in docs/agents.md.
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional

from app.schemas.common import AgentName, AgentRunStatus, Severity
from app.schemas.finding import FindingEnvelope


@dataclass
class AgentExecutionContext:
    """Immutable context passed to an agent for an assessment run."""

    assessment_id: uuid.UUID
    run_id: uuid.UUID
    target_url: str
    normalized_url: str
    scope_id: Optional[uuid.UUID] = None
    safe_scan_enabled: bool = False
    safe_scan_ports: List[int] = field(default_factory=list)
    crypto_scam_analysis: bool = False
    collector_version: str = "1.0.0"
    rule_version: str = "2026-1"


@dataclass
class AgentExecutionResult:
    """Standard result returned by an agent run."""

    agent_name: AgentName
    status: AgentRunStatus
    findings: List[FindingEnvelope] = field(default_factory=list)
    raw_evidence: List[dict[str, Any]] = field(default_factory=list)
    check_availability: dict[str, str] = field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None


class BaseAgent(abc.ABC):
    """Abstract base class for all deterministic TrustLens analyzers."""

    agent_name: AgentName
    rule_version: str = "2026-1"

    @abc.abstractmethod
    async def run(self, context: AgentExecutionContext) -> AgentExecutionResult:
        """Execute the agent analysis within its strictly defined boundaries."""
        pass

    def create_finding(
        self,
        context: AgentExecutionContext,
        finding_type: str,
        severity: Severity,
        confidence: float,
        title: str,
        description: str,
        affected_asset: str,
        evidence_ids: List[uuid.UUID],
        score_impact: int = 0,
        status: str = "active",
    ) -> FindingEnvelope:
        """Helper to create a normalized finding envelope."""
        return FindingEnvelope(
            finding_id=uuid.uuid4(),
            assessment_id=context.assessment_id,
            agent=self.agent_name.value,
            type=finding_type,
            severity=severity,
            score_impact=score_impact,
            confidence=max(0.0, min(1.0, confidence)),
            status=status,
            title=title,
            description=description,
            affected_asset=affected_asset,
            evidence_ids=evidence_ids,
            observed_at=datetime.now(timezone.utc),
            rule_version=self.rule_version,
        )

