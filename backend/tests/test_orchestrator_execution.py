"""Tests for assessment execution and option dispatching."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from app.agents.base import AgentExecutionContext, AgentExecutionResult
from app.config import settings
from app.models.assessment import Assessment
from app.models.authorization import AuthorizationScope
from app.orchestrator.engine import AssessmentOrchestrator
from app.schemas.common import AgentName, AgentRunStatus, AssessmentStatus, ScopeStatus


@pytest.mark.asyncio
async def test_normal_assessment_not_immediately_failed(db_session):
    """Test that a normal assessment is processed and not marked failed immediately."""
    tenant_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    assessment_id = uuid.uuid4()

    scope = AuthorizationScope(
        id=scope_id,
        tenant_id=tenant_id,
        subject_id=uuid.uuid4(),
        targets_json=["https://example.com"],
        valid_from=datetime.now(timezone.utc),
        valid_until=datetime.now(timezone.utc),
        status=ScopeStatus.ACTIVE.value,
    )
    db_session.add(scope)

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=scope_id,
        submitted_url="https://example.com",
        normalized_url="https://example.com",
        status=AssessmentStatus.QUEUED.value,
    )
    db_session.add(assessment)
    await db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    # Mock all agents to complete cleanly
    for agent in orchestrator.agents:
        mock_result = AgentExecutionResult(
            agent_name=agent.agent_name,
            status=AgentRunStatus.COMPLETED,
            findings=[],
            ended_at=datetime.now(timezone.utc),
        )
        agent.run = AsyncMock(return_value=mock_result)

    result_assessment = await orchestrator.execute_assessment(
        assessment_id=assessment_id,
        safe_scan_enabled=False,
        safe_scan_ports=None,
        crypto_scam_analysis=False,
    )

    assert result_assessment.status in (AssessmentStatus.COMPLETED.value, AssessmentStatus.PARTIAL.value)
    assert result_assessment.status != AssessmentStatus.FAILED.value


@pytest.mark.asyncio
async def test_safe_scan_options_reach_safe_surface_agent(db_session):
    """Test that safe_scan_enabled and safe_scan_ports are passed to Safe Surface Agent."""
    tenant_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    assessment_id = uuid.uuid4()

    scope = AuthorizationScope(
        id=scope_id,
        tenant_id=tenant_id,
        subject_id=uuid.uuid4(),
        targets_json=["https://example.com"],
        allowed_ports_json=[80, 443, 8080],
        valid_from=datetime.now(timezone.utc),
        valid_until=datetime.now(timezone.utc),
        status=ScopeStatus.ACTIVE.value,
    )
    db_session.add(scope)

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=scope_id,
        submitted_url="https://example.com",
        normalized_url="https://example.com",
        status=AssessmentStatus.QUEUED.value,
    )
    db_session.add(assessment)
    await db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    captured_contexts: dict[str, AgentExecutionContext] = {}

    for agent in orchestrator.agents:
        def make_side_effect(ag):
            async def _run(ctx: AgentExecutionContext):
                captured_contexts[ag.agent_name.value] = ctx
                return AgentExecutionResult(
                    agent_name=ag.agent_name,
                    status=AgentRunStatus.COMPLETED,
                    findings=[],
                    ended_at=datetime.now(timezone.utc),
                )
            return _run
        agent.run = AsyncMock(side_effect=make_side_effect(agent))

    await orchestrator.execute_assessment(
        assessment_id=assessment_id,
        safe_scan_enabled=True,
        safe_scan_ports=[8080],
        crypto_scam_analysis=False,
    )

    assert AgentName.SAFE_SURFACE.value in captured_contexts
    surface_ctx = captured_contexts[AgentName.SAFE_SURFACE.value]
    assert surface_ctx.safe_scan_enabled is True
    assert surface_ctx.safe_scan_ports == [8080]


@pytest.mark.asyncio
async def test_crypto_scam_option_reaches_phishing_agent(db_session):
    """Test that crypto_scam_analysis option reaches the Phishing Agent."""
    tenant_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    assessment_id = uuid.uuid4()

    scope = AuthorizationScope(
        id=scope_id,
        tenant_id=tenant_id,
        subject_id=uuid.uuid4(),
        targets_json=["https://example.com"],
        valid_from=datetime.now(timezone.utc),
        valid_until=datetime.now(timezone.utc),
        status=ScopeStatus.ACTIVE.value,
    )
    db_session.add(scope)

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=scope_id,
        submitted_url="https://example.com",
        normalized_url="https://example.com",
        status=AssessmentStatus.QUEUED.value,
    )
    db_session.add(assessment)
    await db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    captured_contexts: dict[str, AgentExecutionContext] = {}

    for agent in orchestrator.agents:
        def make_side_effect(ag):
            async def _run(ctx: AgentExecutionContext):
                captured_contexts[ag.agent_name.value] = ctx
                return AgentExecutionResult(
                    agent_name=ag.agent_name,
                    status=AgentRunStatus.COMPLETED,
                    findings=[],
                    ended_at=datetime.now(timezone.utc),
                )
            return _run
        agent.run = AsyncMock(side_effect=make_side_effect(agent))

    # Test with crypto_scam_analysis = True
    await orchestrator.execute_assessment(
        assessment_id=assessment_id,
        safe_scan_enabled=False,
        safe_scan_ports=None,
        crypto_scam_analysis=True,
    )

    assert AgentName.PHISHING_BRAND.value in captured_contexts
    phishing_ctx = captured_contexts[AgentName.PHISHING_BRAND.value]
    assert phishing_ctx.crypto_scam_analysis is True
    # Verify default safe-scan ports are empty list
    assert phishing_ctx.safe_scan_ports == []

