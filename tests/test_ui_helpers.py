"""Tests for ui.helpers — the pure helpers behind the dashboard.

test_dashboard_helpers.py covers the `dashboard` shim's re-exports; this file
targets ui.helpers directly and adds the icon/CSS-class helpers.
"""

import pandas as pd

from ui.helpers import get_risk_color_class, get_risk_icon


class TestGetRiskIcon:
    def test_english_levels(self):
        assert get_risk_icon("High") == "🔴"
        assert get_risk_icon("Medium") == "🟠"
        assert get_risk_icon("Low") == "🟢"

    def test_legacy_turkish_levels(self):
        assert get_risk_icon("Yüksek") == "🔴"
        assert get_risk_icon("Orta") == "🟠"
        assert get_risk_icon("Düşük") == "🟢"

    def test_nan_and_unknown(self):
        assert get_risk_icon(pd.NA) == "❓"
        assert get_risk_icon("weird") == "⚪"


class TestGetRiskColorClass:
    def test_english_levels(self):
        assert get_risk_color_class("High") == "risk-high"
        assert get_risk_color_class("Medium") == "risk-medium"
        assert get_risk_color_class("Low") == "risk-low"

    def test_legacy_turkish_levels(self):
        assert get_risk_color_class("Yüksek") == "risk-high"
        assert get_risk_color_class("Orta") == "risk-medium"
        assert get_risk_color_class("Düşük") == "risk-low"

    def test_nan_and_unknown(self):
        assert get_risk_color_class(pd.NA) == ""
        assert get_risk_color_class("weird") == ""
