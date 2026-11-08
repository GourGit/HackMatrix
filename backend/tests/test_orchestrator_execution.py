"""Tests for assessment execution and option dispatching."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
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


@pytest.mark.asyncio
async def test_evidence_collector_version_matches_specific_agent(db_session, monkeypatch):
    """Test that Evidence collector_version uses each specific agent's rule_version."""
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

    # Set distinct rule versions on agents
    for idx, agent in enumerate(orchestrator.agents):
        agent.rule_version = f"custom-rule-v{idx}"

    stored_metas = []
    original_store = orchestrator.evidence_store.store

    async def mock_store(content, metadata):
        stored_metas.append(metadata)
        return await original_store(content, metadata)

    monkeypatch.setattr(orchestrator.evidence_store, "store", mock_store)

    # Have the first agent emit raw evidence
    first_agent = orchestrator.agents[0]
    expected_version = first_agent.rule_version

    async def first_agent_run(ctx):
        return AgentExecutionResult(
            agent_name=first_agent.agent_name,
            status=AgentRunStatus.COMPLETED,
            raw_evidence=[{"kind": "url_observation", "data": "test"}],
            ended_at=datetime.now(timezone.utc),
        )

    first_agent.run = AsyncMock(side_effect=first_agent_run)

    for agent in orchestrator.agents[1:]:
        async def empty_run(ctx, ag=agent):
            return AgentExecutionResult(
                agent_name=ag.agent_name,
                status=AgentRunStatus.COMPLETED,
                ended_at=datetime.now(timezone.utc),
            )
        agent.run = AsyncMock(side_effect=empty_run)

    result_assessment = await orchestrator.execute_assessment(assessment_id)

    assert result_assessment.status == AssessmentStatus.COMPLETED.value
    assert len(stored_metas) == 1
    # EvidenceMetadata collector_version must match the first agent, NOT the last agent
    assert stored_metas[0].collector_version == expected_version

    # Check Evidence model in DB
    from app.models.evidence import Evidence
    ev_stmt = select(Evidence).where(Evidence.assessment_id == assessment_id)
    ev_res = await db_session.execute(ev_stmt)
    ev_record = ev_res.scalar_one()
    assert ev_record.collector_version == expected_version


@pytest.mark.asyncio
async def test_evidence_store_failure_marks_partial_and_finalizes_runs(db_session, monkeypatch):
    """Test that failure in evidence_store.store transitions assessment to PARTIAL and finalizes runs."""
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

    # Mock evidence store to fail with exception
    async def mock_failing_store(content, metadata):
        raise IOError("Storage backend unreachable")

    monkeypatch.setattr(orchestrator.evidence_store, "store", mock_failing_store)

    first_agent = orchestrator.agents[0]

    async def first_agent_run(ctx):
        return AgentExecutionResult(
            agent_name=first_agent.agent_name,
            status=AgentRunStatus.COMPLETED,
            raw_evidence=[{"kind": "url_observation", "data": "test"}],
            ended_at=datetime.now(timezone.utc),
        )

    first_agent.run = AsyncMock(side_effect=first_agent_run)

    for agent in orchestrator.agents[1:]:
        async def empty_run(ctx, ag=agent):
            return AgentExecutionResult(
                agent_name=ag.agent_name,
                status=AgentRunStatus.COMPLETED,
                ended_at=datetime.now(timezone.utc),
            )
        agent.run = AsyncMock(side_effect=empty_run)

    result_assessment = await orchestrator.execute_assessment(assessment_id)

    # Must NOT remain RUNNING; must be marked PARTIAL
    assert result_assessment.status == AssessmentStatus.PARTIAL.value
    assert result_assessment.completed_at is not None

    # Check agent run records: the failing one must be PARTIAL with error code
    from app.models.agent_run import AgentRun
    runs_stmt = select(AgentRun).where(AgentRun.assessment_id == assessment_id)
    runs_res = await db_session.execute(runs_stmt)
    runs = runs_res.scalars().all()
    assert len(runs) == len(orchestrator.agents)
    failing_run = next(r for r in runs if r.agent_name == first_agent.agent_name.value)
    assert failing_run.status == AgentRunStatus.PARTIAL.value
    assert failing_run.error_code == "EVIDENCE_STORAGE_FAILED"


@pytest.mark.asyncio
async def test_evidence_store_preserves_failed_run_status_and_code(db_session, monkeypatch):
    """Test that evidence storage failure preserves existing FAILED status and error code."""
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

    # Mock evidence store to fail with exception
    async def mock_failing_store(content, metadata):
        raise IOError("Storage backend error")

    monkeypatch.setattr(orchestrator.evidence_store, "store", mock_failing_store)

    first_agent = orchestrator.agents[0]

    # First agent already failed with an existing error code
    async def first_agent_run(ctx):
        return AgentExecutionResult(
            agent_name=first_agent.agent_name,
            status=AgentRunStatus.FAILED,
            error_code="DNS_LOOKUP_TIMEOUT",
            raw_evidence=[{"kind": "url_observation", "data": "test"}],
            ended_at=datetime.now(timezone.utc),
        )

    first_agent.run = AsyncMock(side_effect=first_agent_run)

    for agent in orchestrator.agents[1:]:
        async def empty_run(ctx, ag=agent):
            return AgentExecutionResult(
                agent_name=ag.agent_name,
                status=AgentRunStatus.COMPLETED,
                ended_at=datetime.now(timezone.utc),
            )
        agent.run = AsyncMock(side_effect=empty_run)

    result_assessment = await orchestrator.execute_assessment(assessment_id)

    assert result_assessment.status == AssessmentStatus.PARTIAL.value

    # Check that first_agent's FAILED status and DNS_LOOKUP_TIMEOUT were preserved
    from app.models.agent_run import AgentRun
    runs_stmt = select(AgentRun).where(AgentRun.assessment_id == assessment_id)
    runs_res = await db_session.execute(runs_stmt)
    runs = runs_res.scalars().all()
    failing_run = next(r for r in runs if r.agent_name == first_agent.agent_name.value)
    assert failing_run.status == AgentRunStatus.FAILED.value
    assert failing_run.error_code == "DNS_LOOKUP_TIMEOUT"


@pytest.mark.asyncio
async def test_orchestrator_unhandled_exception_rolls_back_and_marks_failed(db_session, monkeypatch):
    """Test that unexpected orchestrator error rolls back session and updates DB with failure state."""
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

    # Make risk calculator blow up unexpectedly
    def mock_broken_calc(scores):
        raise RuntimeError("Fatal risk calculation error")

    monkeypatch.setattr(orchestrator.scorer, "calculate", mock_broken_calc)

    with pytest.raises(RuntimeError, match="Fatal risk calculation error"):
        await orchestrator.execute_assessment(assessment_id)

    # Verify that in database, the assessment is FAILED and not RUNNING
    from app.models.assessment import Assessment as AssModel
    ass_stmt = select(AssModel).where(AssModel.id == assessment_id)
    ass_res = await db_session.execute(ass_stmt)
    failed_assessment = ass_res.scalar_one()
    assert failed_assessment.status == AssessmentStatus.FAILED.value
    assert failed_assessment.completed_at is not None

    # Verify agent runs are marked FAILED with ORCHESTRATOR_ERROR
    from app.models.agent_run import AgentRun
    runs_stmt = select(AgentRun).where(AgentRun.assessment_id == assessment_id)
    runs_res = await db_session.execute(runs_stmt)
    runs = runs_res.scalars().all()
    assert len(runs) == len(orchestrator.agents)
    for r in runs:
        assert r.status == AgentRunStatus.FAILED.value
        assert r.error_code == "ORCHESTRATOR_ERROR"



