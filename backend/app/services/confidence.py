"""
Confidence Engine — calculates evidence-based confidence scores.

Key distinction:
- SOURCE CONFIDENCE: how reliable is a single source (e.g., crt.sh = 0.92)
- CROSS-SOURCE AGREEMENT: how many independent sources agree
- FINAL CONFIDENCE: composite of both + freshness

This engine NEVER claims absolute accuracy — all values are estimates based on
passive OSINT analysis. The terminology uses "Confidence" and "Source Agreement"
rather than "Accuracy" because OSINT cannot guarantee factual accuracy.

Scoring model (configurable):
  base = average of source confidences
  source_bonus = source_count × SOURCE_BONUS_PER_AGREEMENT (capped at MAX_AGREEMENT_BONUS)
  freshness_bonus = FRESHNESS_BONUS if data is recent (< FRESHNESS_THRESHOLD_DAYS)
  final = min(base + source_bonus + freshness_bonus, MAX_CONFIDENCE)

Human-readable thresholds:
  1 source  → ~60%
  2 sources → ~72%
  3 sources → ~83%
  4+ sources → ~92%+
"""

from datetime import datetime, timezone
from typing import List, Optional


# ── Configurable scoring parameters ─────────────────────────────────────────
# Change these to tune the scoring model without touching business logic.
SOURCE_BONUS_PER_AGREEMENT: float = 0.08    # Added per additional agreeing source
MAX_AGREEMENT_BONUS: float = 0.30           # Maximum bonus from source agreement
FRESHNESS_THRESHOLD_DAYS: int = 30          # Days after which data is considered "stale"
FRESHNESS_BONUS: float = 0.05              # Bonus for recent data
MAX_CONFIDENCE: float = 0.97               # Never claim 100% (OSINT is never certain)
MIN_CONFIDENCE: float = 0.30               # Floor value
# ─────────────────────────────────────────────────────────────────────────────


def calculate_confidence(
    source_confidences: List[float],
    source_count: int,
    first_seen: Optional[str] = None,
) -> float:
    """
    Calculate the final confidence score for a merged finding.

    Args:
        source_confidences: List of per-source confidence values (0.0–1.0)
        source_count:       Number of unique sources that found this entity
        first_seen:         ISO timestamp of earliest observation (for freshness)

    Returns:
        float: Confidence score in range [MIN_CONFIDENCE, MAX_CONFIDENCE]
    """
    if not source_confidences:
        return MIN_CONFIDENCE

    # Base: average confidence across sources
    base = sum(source_confidences) / len(source_confidences)

    # Source agreement bonus
    agreement_bonus = min(
        (source_count - 1) * SOURCE_BONUS_PER_AGREEMENT,
        MAX_AGREEMENT_BONUS,
    )

    # Freshness bonus
    freshness_bonus = 0.0
    if first_seen:
        try:
            seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - seen_dt).days
            if age_days <= FRESHNESS_THRESHOLD_DAYS:
                freshness_bonus = FRESHNESS_BONUS
        except Exception:
            pass

    final = base + agreement_bonus + freshness_bonus
    return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, final)), 4)


def calculate_confidence_pct(
    source_confidences: List[float],
    source_count: int,
    first_seen: Optional[str] = None,
) -> int:
    """Return confidence as an integer percentage (0–97)."""
    return round(calculate_confidence(source_confidences, source_count, first_seen) * 100)


def get_confidence_label(confidence_pct: int) -> str:
    """Return a human-readable confidence label."""
    if confidence_pct >= 90:
        return "Very High"
    elif confidence_pct >= 75:
        return "High"
    elif confidence_pct >= 60:
        return "Moderate"
    elif confidence_pct >= 40:
        return "Low"
    else:
        return "Very Low"


def get_agreement_label(source_count: int, total_queried: int) -> str:
    """Return human-readable source agreement string, e.g. '3/4'."""
    return f"{source_count}/{total_queried}"


def confidence_breakdown(
    source_confidences: List[float],
    source_count: int,
    total_queried: int,
    first_seen: Optional[str] = None,
) -> dict:
    """
    Return a full transparency breakdown of the confidence calculation.
    Use this for the UI evidence panel and academic explanations.
    """
    base = round(sum(source_confidences) / len(source_confidences) * 100) if source_confidences else 0
    agreement_bonus_pct = round(
        min((source_count - 1) * SOURCE_BONUS_PER_AGREEMENT, MAX_AGREEMENT_BONUS) * 100
    )
    freshness_bonus_pct = 0
    if first_seen:
        try:
            seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - seen_dt).days
            if age_days <= FRESHNESS_THRESHOLD_DAYS:
                freshness_bonus_pct = round(FRESHNESS_BONUS * 100)
        except Exception:
            pass

    final_pct = calculate_confidence_pct(source_confidences, source_count, first_seen)

    return {
        "final_confidence_pct": final_pct,
        "confidence_label": get_confidence_label(final_pct),
        "source_agreement": get_agreement_label(source_count, total_queried),
        "source_count": source_count,
        "total_queried": total_queried,
        "breakdown": {
            "base_confidence_pct": base,
            "source_agreement_bonus_pct": agreement_bonus_pct,
            "freshness_bonus_pct": freshness_bonus_pct,
        },
        "note": (
            "Confidence is an estimate based on passive OSINT analysis. "
            "It reflects source agreement, not factual accuracy. "
            "Active verification requires authorized VAPT."
        ),
    }
