"""Unit tests for deterministic scoring formula."""

import uuid
from app.core.scoring import FindingScore, RiskScoreCalculator
from app.schemas.common import ScoreBand, Severity


def test_scoring_weights_and_cap():
    calc = RiskScoreCalculator()

    # Empty findings -> 0
    res = calc.calculate([])
    assert res.score == 0
    assert res.band == ScoreBand.LOW

    # Single critical finding: 40 * 1.0 * 1.0 = 40 (Guarded)
    res = calc.calculate([
        FindingScore(finding_id=uuid.uuid4(), severity=Severity.CRITICAL, confidence=1.0)
    ])
    assert res.score == 40
    assert res.band == ScoreBand.GUARDED

    # Three critical findings: 40 * 3 = 120 -> capped at 100 (Critical)
    res = calc.calculate([
        FindingScore(finding_id=uuid.uuid4(), severity=Severity.CRITICAL, confidence=1.0),
        FindingScore(finding_id=uuid.uuid4(), severity=Severity.CRITICAL, confidence=1.0),
        FindingScore(finding_id=uuid.uuid4(), severity=Severity.CRITICAL, confidence=1.0),
    ])
    assert res.score == 100
    assert res.band == ScoreBand.CRITICAL

