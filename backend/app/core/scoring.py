"""Risk-score calculation engine.

Implements the composite scoring formula from docs/prd.md:

    score = min(100, Σ severity_weight × confidence × freshness × corroboration)

Score bands:
    0–19   → low
    20–49  → guarded
    50–74  → high
    75–100 → critical

Design invariants:
  * Unknown / unavailable checks produce **no** positive score impact.
  * Corroboration may increase confidence, but never pushes a single
    finding's severity weight beyond its maximum.
  * Individual contributions are exposed alongside the aggregate so the
    UI and API can render per-finding breakdowns.
  * A ``version`` field tracks the scoring algorithm revision.
"""

from __future__ import annotations

import dataclasses
import datetime
from typing import Final

from app.schemas.common import (
    SEVERITY_WEIGHTS,
    ScoreBand,
    Severity,
    score_to_band,
)

# ── Constants ─────────────────────────────────────────────────────────────

_SCORE_VERSION: Final[str] = "2026-1"

# Freshness parameters.
_FRESHNESS_DECAY_DAYS: Final[int] = 30
_FRESHNESS_FLOOR: Final[float] = 0.5

# Corroboration range.
_CORROBORATION_DEFAULT: Final[float] = 1.0
_CORROBORATION_MAX: Final[float] = 1.5


# ── Data structures ──────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True, slots=True)
class FindingScore:
    """Input to the scoring engine representing one finding.

    Attributes:
        finding_id:     Unique identifier for this finding.
        severity:       Severity enum (informational … critical).
        confidence:     Confidence in [0.0, 1.0].
        freshness:      Days since the observation was made.
                        Use 0.0 for brand-new findings.
        corroboration:  Corroboration multiplier in [1.0, 1.5].
                        Defaults to 1.0 (no corroboration).
    """

    finding_id: str
    severity: Severity
    confidence: float
    freshness: float = 0.0  # days since observation
    corroboration: float = _CORROBORATION_DEFAULT


@dataclasses.dataclass(frozen=True, slots=True)
class FindingContribution:
    """Per-finding breakdown of its contribution to the total score.

    Attributes:
        finding_id: Identifier matching the input :class:`FindingScore`.
        points:     Effective points contributed (before final clamping).
    """

    finding_id: str
    points: float


@dataclasses.dataclass(frozen=True, slots=True)
class RiskResult:
    """Aggregate risk-score result.

    Attributes:
        score:          The integer risk score in [0, 100].
        band:           Severity band derived from *score*.
        contributions:  Per-finding point contributions.
        version:        Algorithm version (e.g. ``"2026-1"``).
    """

    score: int
    band: ScoreBand
    contributions: list[FindingContribution]
    version: str


# ── Calculator ───────────────────────────────────────────────────────────

class RiskScoreCalculator:
    """Stateless risk-score calculator.

    Usage::

        calc = RiskScoreCalculator()
        result = calc.calculate(findings)
        print(result.score, result.band)

    The calculator is intentionally stateless so that it can be shared
    across requests without thread-safety concerns.
    """

    @staticmethod
    def calculate(findings: list[FindingScore]) -> RiskResult:
        """Compute the composite risk score for a list of findings.

        Formula per finding:

            contribution = severity_weight × confidence × freshness × corroboration

        Aggregate:

            score = min(100, round(Σ contributions))

        Freshness decays linearly over 30 days with a floor of 0.5::

            freshness_factor = max(0.5, 1.0 − days_since_observation / 30)

        Args:
            findings: Validated finding scores.  Empty lists yield
                      score 0 / band ``low``.

        Returns:
            A :class:`RiskResult` with score, band, contributions, and
            algorithm version.
        """
        contributions: list[FindingContribution] = []
        raw_total: float = 0.0

        for f in findings:
            # Severity weight lookup — informational has weight 0 and thus
            # produces no positive score impact.
            weight = SEVERITY_WEIGHTS.get(f.severity, 0)

            # Clamp inputs to their valid ranges.
            confidence = max(0.0, min(1.0, f.confidence))
            corroboration = max(
                _CORROBORATION_DEFAULT,
                min(_CORROBORATION_MAX, f.corroboration),
            )

            freshness_factor = _compute_freshness(f.freshness)

            points = weight * confidence * freshness_factor * corroboration
            contributions.append(
                FindingContribution(finding_id=f.finding_id, points=points)
            )
            raw_total += points

        clamped_score = min(100, max(0, round(raw_total)))

        return RiskResult(
            score=clamped_score,
            band=score_to_band(clamped_score),
            contributions=contributions,
            version=_SCORE_VERSION,
        )


# ── Helpers ──────────────────────────────────────────────────────────────

def _compute_freshness(days_since_observation: float) -> float:
    """Return the freshness decay factor.

    Linearly decays from 1.0 (brand-new) to 0.5 (≥ 30 days old).

    Args:
        days_since_observation: Non-negative number of days since the
            observation was recorded.

    Returns:
        A float in [0.5, 1.0].
    """
    return max(
        _FRESHNESS_FLOOR,
        1.0 - days_since_observation / _FRESHNESS_DECAY_DAYS,
    )
