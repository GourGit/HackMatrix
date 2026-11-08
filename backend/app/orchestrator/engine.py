"""Asyncio Orchestrator for TrustLens assessments.

Coordinates the six deterministic agents, handles timeouts, persists
execution records, stores raw evidence with SHA-256 content hashing and secret
redaction, associates findings with evidence via junction records, executes the
risk engine, and records accurate check statuses.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import AgentExecutionContext, AgentExecutionResult
from app.agents.certificate_intel import CertificateIntelAgent
from app.agents.phishing_brand import PhishingBrandAgent
from app.agents.privacy_software import PrivacySoftwareAgent
from app.agents.safe_surface import SafeSurfaceAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.agents.url_redirect import UrlRedirectAgent
from app.config import settings
from app.core.evidence_store import EvidenceMetadata, EvidenceStore, redact_secrets
from app.core.scoring import FindingScore, RiskScoreCalculator
from app.models.agent_run import AgentRun
from app.models.assessment import Assessment
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.schemas.common import (
    AgentName,
    AgentRunStatus,
    AssessmentStatus,
    EvidenceKind,
    score_to_band,
)


class AssessmentOrchestrator:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.agents = [
            UrlRedirectAgent(),
            PhishingBrandAgent(),
            CertificateIntelAgent(),
            SafeSurfaceAgent(),
            PrivacySoftwareAgent(),
            ThreatIntelAgent(),
        ]
        self.scorer = RiskScoreCalculator()
        self.evidence_store = EvidenceStore()

    async def execute_assessment(
        self,
        assessment_id: uuid.UUID,
        safe_scan_enabled: bool = False,
        safe_scan_ports: list[int] | None = None,
        crypto_scam_analysis: bool = False,
    ) -> Assessment:
        """Runs all 6 agents concurrently and persists evidence, findings, and risk metrics."""
        stmt = select(Assessment).where(Assessment.id == assessment_id)
        res = await self.db.execute(stmt)
        assessment = res.scalar_one_or_none()
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found.")

        assessment.status = AssessmentStatus.RUNNING.value
        await self.db.commit()

        effective_safe_scan_ports = list(safe_scan_ports) if safe_scan_ports is not None else []

        tasks = []
        run_records: Dict[AgentName, AgentRun] = {}
        agents_by_name = {a.agent_name: a for a in self.agents}

        try:
            for agent in self.agents:
                run_id = uuid.uuid4()
                agent_run = AgentRun(
                    id=run_id,
                    assessment_id=assessment.id,
                    agent_name=agent.agent_name.value,
                    status=AgentRunStatus.RUNNING.value,
                    rule_version=agent.rule_version,
                    started_at=datetime.now(timezone.utc),
                )
                self.db.add(agent_run)
                run_records[agent.agent_name] = agent_run

                ctx = AgentExecutionContext(
                    assessment_id=assessment.id,
                    run_id=run_id,
                    target_url=assessment.submitted_url,
                    normalized_url=assessment.normalized_url,
                    scope_id=assessment.scope_id,
                    safe_scan_enabled=safe_scan_enabled,
                    safe_scan_ports=effective_safe_scan_ports,
                    crypto_scam_analysis=crypto_scam_analysis,
                )
                tasks.append(self._run_with_timeout(agent, ctx))

            await self.db.commit()

            # Run agents with isolation & timeout
            results: List[AgentExecutionResult] = await asyncio.gather(*tasks, return_exceptions=False)

            all_finding_scores: List[FindingScore] = []
            has_partial_failures = False
            now_utc = datetime.now(timezone.utc)
            retention_deadline = now_utc + timedelta(days=settings.evidence_retention_days)

            for res in results:
                run_rec = run_records[res.agent_name]
                run_rec.status = res.status.value
                run_rec.ended_at = res.ended_at or datetime.now(timezone.utc)
                run_rec.error_code = res.error_code

                current_agent = agents_by_name.get(res.agent_name)
                rule_version = current_agent.rule_version if current_agent else "2026-1"

                if res.status != AgentRunStatus.COMPLETED:
                    has_partial_failures = True

                # 1. Persist Raw Evidence Items
                evidence_map: Dict[uuid.UUID, Evidence] = {}
                for item in res.raw_evidence:
                    ev_id = item.get("evidence_id", uuid.uuid4())
                    kind_val = item.get("kind", EvidenceKind.PROVIDER_RESULT)
                    kind_str = kind_val.value if hasattr(kind_val, "value") else str(kind_val)

                    # Redact sensitive parameters and serialize
                    payload_json = json.dumps(item, default=str)
                    redacted_json = redact_secrets(payload_json)
                    content_bytes = redacted_json.encode("utf-8")

                    meta = EvidenceMetadata(
                        source_uri=assessment.submitted_url,
                        collector_version=rule_version,
                    )
                    try:
                        stored = await self.evidence_store.store(content_bytes, meta)

                        ev_model = Evidence(
                            id=ev_id,
                            assessment_id=assessment.id,
                            agent_run_id=run_rec.id,
                            kind=kind_str,
                            source_uri=assessment.submitted_url,
                            content_hash=stored.content_hash,
                            storage_ref=stored.storage_ref,
                            collected_at=now_utc,
                            collector_version=rule_version,
                            redaction_version="1.0",
                            retention_until=retention_deadline,
                        )
                        self.db.add(ev_model)
                        evidence_map[ev_id] = ev_model
                    except Exception:
                        has_partial_failures = True
                        if run_rec.status == AgentRunStatus.COMPLETED.value:
                            run_rec.status = AgentRunStatus.PARTIAL.value
                        if not run_rec.error_code:
                            run_rec.error_code = "EVIDENCE_STORAGE_FAILED"

                # 2. Persist Findings and associate with Evidence
                for f in res.findings:
                    finding_db = Finding(
                        id=f.finding_id,
                        assessment_id=assessment.id,
                        agent_run_id=run_rec.id,
                        type=f.type,
                        severity=f.severity.value,
                        confidence=f.confidence,
                        score_impact=f.score_impact,
                        status=f.status,
                        asset=f.affected_asset,
                        summary=f.title,
                        rule_version=f.rule_version,
                        observed_at=f.observed_at,
                    )

                    # Link associated evidence
                    for ev_id in f.evidence_ids:
                        if ev_id in evidence_map:
                            finding_db.evidence_items.append(evidence_map[ev_id])

                    self.db.add(finding_db)

                    all_finding_scores.append(
                        FindingScore(
                            finding_id=str(f.finding_id),
                            severity=f.severity,
                            confidence=f.confidence,
                        )
                    )

            # 3. Deterministic Risk Engine Scoring
            risk_result = self.scorer.calculate(all_finding_scores)

            # 4. Finalize Assessment
            assessment.score = risk_result.score
            assessment.score_band = risk_result.band.value
            assessment.score_version = risk_result.version
            assessment.status = (
                AssessmentStatus.PARTIAL.value if has_partial_failures else AssessmentStatus.COMPLETED.value
            )
            assessment.completed_at = datetime.now(timezone.utc)

            await self.db.commit()
            await self.db.refresh(assessment)
            return assessment

        except Exception:
            await self.db.rollback()
            now_failed = datetime.now(timezone.utc)
            await self.db.execute(
                update(Assessment)
                .where(Assessment.id == assessment_id)
                .values(
                    status=AssessmentStatus.FAILED.value,
                    completed_at=now_failed,
                )
            )
            await self.db.execute(
                update(AgentRun)
                .where(
                    AgentRun.assessment_id == assessment_id,
                    AgentRun.status == AgentRunStatus.RUNNING.value,
                )
                .values(
                    status=AgentRunStatus.FAILED.value,
                    ended_at=now_failed,
                    error_code="ORCHESTRATOR_ERROR",
                )
            )
            await self.db.commit()
            raise

    async def _run_with_timeout(self, agent, ctx: AgentExecutionContext) -> AgentExecutionResult:
        try:
            return await asyncio.wait_for(agent.run(ctx), timeout=15.0)
        except asyncio.TimeoutError:
            return AgentExecutionResult(
                agent_name=agent.agent_name,
                status=AgentRunStatus.TIMEOUT,
                error_code="AGENT_TIMEOUT",
                error_message="Agent exceeded deadline",
                ended_at=datetime.now(timezone.utc),
            )
        except Exception as e:
            return AgentExecutionResult(
                agent_name=agent.agent_name,
                status=AgentRunStatus.FAILED,
                error_code="INTERNAL_ERROR",
                error_message=str(e),
                ended_at=datetime.now(timezone.utc),
            )
