"""
Unit tests for the AIAnalysisResponse Pydantic model.
Covers risk-score normalization (English + legacy Turkish) and markdown rendering.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.ai_models import AIAnalysisResponse


def _make(risk: str) -> AIAnalysisResponse:
    return AIAnalysisResponse(
        risk_score=risk,
        user_entity="ATTACKER",
        summary="Failed logon attempt",
        advice="Investigate the source host.",
    )


class TestRiskScoreNormalization:
    """validate_risk_score must always return canonical English values."""

    @pytest.mark.parametrize("value,expected", [
        ("High", "High"),
        ("high", "High"),
        ("Yüksek", "High"),
        ("yüksek", "High"),
        ("Medium", "Medium"),
        ("orta", "Medium"),
        ("Low", "Low"),
        ("düşük", "Low"),
    ])
    def test_known_values_map_to_english(self, value, expected):
        assert _make(value).risk_score == expected

    @pytest.mark.parametrize("value", ["", "unknown", "banana", "n/a"])
    def test_unknown_values_default_to_medium(self, value):
        assert _make(value).risk_score == "Medium"

    def test_substring_fallback(self):
        # Values that are not exact matches but contain a known keyword
        assert _make("very high risk").risk_score == "High"
        assert _make("looks low to me").risk_score == "Low"


class TestToMarkdown:
    """to_markdown should produce the dashboard-friendly layout."""

    def test_contains_all_sections(self):
        md = _make("High").to_markdown()
        assert "🕵️‍♂️ Analysis" in md
        assert "User/Entity: ATTACKER" in md
        assert "Summary: Failed logon attempt" in md
        assert "Risk Level: High" in md
        assert "💡 Recommendation" in md
        assert "Investigate the source host." in md

    def test_event_id_explanation_optional(self):
        without = _make("Low").to_markdown()
        assert "Event ID Explained" not in without

        with_expl = AIAnalysisResponse(
            risk_score="Low",
            user_entity="SYSTEM",
            summary="s",
            advice="a",
            event_id_explanation="Event 4624 means a successful logon.",
        ).to_markdown()
        assert "Event ID Explained" in with_expl
        assert "successful logon" in with_expl


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
