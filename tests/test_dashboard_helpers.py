"""
Unit tests for dashboard.py's pure helpers. Regression focus: the severity
mapping used to check "high" before "critical", which made the High tier
unreachable — every high-risk event rendered as Critical.
"""

import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import dashboard


class TestMapSeverity:
    @pytest.mark.parametrize(
        "risk,expected",
        [
            ("High", "High"),
            ("high risk", "High"),
            ("Yüksek", "High"),
            ("Critical", "Critical"),
            ("kritik", "Critical"),
            ("Medium", "Medium"),
            ("Orta", "Medium"),
            ("Low", "Low"),
            ("Düşük", "Low"),
            ("", "Unspecified"),
            (None, "Unspecified"),
            ("weird", "Unspecified"),
        ],
    )
    def test_mapping(self, risk, expected):
        assert dashboard.map_severity(risk) == expected

    def test_high_tier_is_reachable(self):
        # Regression: "high" must NOT collapse into Critical
        assert dashboard.map_severity("High") != "Critical"


class TestTranslateRiskLevel:
    @pytest.mark.parametrize(
        "risk,expected",
        [
            ("Yüksek", "High"),
            ("orta", "Medium"),
            ("düşük", "Low"),
            ("High", "High"),
            ("critical", "Critical"),
            (None, "Unspecified"),
        ],
    )
    def test_translation(self, risk, expected):
        assert dashboard.translate_risk_level(risk) == expected


class TestFilterData:
    @pytest.fixture
    def df(self):
        return pd.DataFrame(
            {
                "Time": ["2026-07-01 10:00:00", "2026-07-02 11:00:00", "2026-07-03 12:00:00"],
                "Event ID": ["4625", "4720", "4625"],
                "Risk Level": ["High", "Medium", "Low"],
                "Message": ["failed logon", "user created", "logon ok"],
                "AI Analysis": ["brute force", "new account", "normal"],
                "MITRE Technique": ["T1110", "T1136", None],
            }
        )

    def test_risk_filter(self, df):
        out = dashboard.filter_data(df, ["High"], "")
        assert list(out["Risk Level"]) == ["High"]

    def test_event_id_filter(self, df):
        out = dashboard.filter_data(df, [], "4625")
        assert len(out) == 2

    def test_text_search_covers_mitre(self, df):
        out = dashboard.filter_data(df, [], "", text_search="t1110")
        assert len(out) == 1
        assert out.iloc[0]["Event ID"] == "4625"

    def test_no_filters_returns_all(self, df):
        assert len(dashboard.filter_data(df, [], "")) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
