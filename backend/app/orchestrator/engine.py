"""Asyncio Orchestrator for TrustLens assessments.

Coordinates the six deterministic agents, handles timeouts, retries,
records agent runs in PostgreSQL, collects raw evidence, and invokes
the risk calculation engine and OpenRouter AI summary.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import AgentExecutionContext, AgentExecutionResult
from app.agents.certificate_intel import CertificateIntelAgent
from app.agents.phishing_brand import PhishingBrandAgent
from app.agents.privacy_software import PrivacySoftwareAgent
from app.agents.safe_surface import SafeSurfaceAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.agents.url_redirect import UrlRedirectAgent
from app.core.scoring import FindingScore, RiskScoreCalculator
from app.models.agent_run import AgentRun
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.schemas.common import AgentName, AgentRunStatus, AssessmentStatus, CheckAvailability, score_to_band


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

    async def execute_assessment(self, assessment_id: uuid.UUID) -> Assessment:
        """Runs all 6 agents concurrently and updates the database records."""
        # 1. Fetch Assessment
        stmt = select(Assessment).where(Assessment.id == assessment_id)
        res = await self.db.execute(stmt)
        assessment = res.scalar_one_or_none()
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found.")

        assessment.status = AssessmentStatus.RUNNING.value
        await self.db.commit()

        # 2. Build Execution Contexts & Agent Run Records
        tasks = []
        run_records = {}

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
                safe_scan_enabled=False,  # default safe
                crypto_scam_analysis=False,
            )
            tasks.append(self._run_with_timeout(agent, ctx))

        await self.db.commit()

        # 3. Concurrently run all agents
        results: List[AgentExecutionResult] = await asyncio.gather(*tasks, return_exceptions=False)

        # 4. Process Findings and Update Agent Runs
        all_finding_scores: List[FindingScore] = []
        checks = {
            "ct": "unknown",
            "revocation": "unknown",
            "safeScan": "not_requested",
        }

        has_partial_failures = False

        for res in results:
            run_rec = run_records[res.agent_name]
            run_rec.status = res.status.value
            run_rec.ended_at = res.ended_at or datetime.now(timezone.utc)
            run_rec.error_code = res.error_code

            if res.status != AgentRunStatus.COMPLETED:
                has_partial_failures = True

            # Merge checks
            for k, v in res.check_availability.items():
                checks[k] = v

            # Insert findings into DB
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
                self.db.add(finding_db)

                all_finding_scores.append(
                    FindingScore(
                        finding_id=f.finding_id,
                        severity=f.severity,
                        confidence=f.confidence,
                    )
                )

        # 5. Deterministic Risk Engine Scoring
        risk_result = self.scorer.calculate(all_finding_scores)

        # 6. Finalize Assessment
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

