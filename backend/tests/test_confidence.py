"""Tests for the confidence scoring engine."""
import unittest
from app.services.confidence import (
    calculate_confidence, calculate_confidence_pct, get_confidence_label,
    get_agreement_label, confidence_breakdown,
)


class TestCalculateConfidence(unittest.TestCase):
    def test_single_source_low_confidence(self):
        score = calculate_confidence([0.60], 1)
        assert 0.50 <= score <= 0.70

    def test_two_sources_bonus(self):
        one_src = calculate_confidence([0.85], 1)
        two_src = calculate_confidence([0.85, 0.82], 2)
        assert two_src > one_src

    def test_three_sources_higher_than_two(self):
        two_src = calculate_confidence([0.85, 0.82], 2)
        three_src = calculate_confidence([0.85, 0.82, 0.88], 3)
        assert three_src > two_src

    def test_max_confidence_cap(self):
        score = calculate_confidence([0.95, 0.95, 0.95, 0.95, 0.95], 5)
        assert score <= 0.97

    def test_min_confidence_floor(self):
        score = calculate_confidence([0.10], 1)
        assert score >= 0.30

    def test_freshness_bonus_recent(self):
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        score_fresh = calculate_confidence([0.85], 1, first_seen=recent)
        score_stale = calculate_confidence([0.85], 1, first_seen=None)
        assert score_fresh > score_stale

    def test_freshness_no_bonus_old(self):
        old = "2020-01-01T00:00:00+00:00"
        score = calculate_confidence([0.85], 1, first_seen=old)
        score_no_date = calculate_confidence([0.85], 1)
        # Old data should be same or slightly less (no freshness bonus)
        assert abs(score - score_no_date) < 0.01


class TestConfidencePct(unittest.TestCase):
    def test_returns_int(self):
        result = calculate_confidence_pct([0.85], 1)
        assert isinstance(result, int)

    def test_range(self):
        result = calculate_confidence_pct([0.85, 0.90], 2)
        assert 0 <= result <= 97


class TestConfidenceLabel(unittest.TestCase):
    def test_very_high(self):
        assert get_confidence_label(92) == "Very High"

    def test_high(self):
        assert get_confidence_label(80) == "High"

    def test_moderate(self):
        assert get_confidence_label(65) == "Moderate"

    def test_low(self):
        assert get_confidence_label(45) == "Low"

    def test_very_low(self):
        assert get_confidence_label(25) == "Very Low"


class TestConfidenceBreakdown(unittest.TestCase):
    def test_structure(self):
        result = confidence_breakdown([0.85, 0.90], 2, 4)
        assert "final_confidence_pct" in result
        assert "source_agreement" in result
        assert "breakdown" in result
        assert "note" in result
        assert result["source_count"] == 2
        assert result["total_queried"] == 4

    def test_agreement_string(self):
        result = confidence_breakdown([0.85, 0.90, 0.88], 3, 4)
        assert result["source_agreement"] == "3/4"

    def test_note_present(self):
        result = confidence_breakdown([0.85], 1, 1)
        assert "passive osint" in result["note"].lower()


if __name__ == "__main__":
    unittest.main()
