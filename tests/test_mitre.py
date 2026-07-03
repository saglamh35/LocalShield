"""
Unit tests for the offline MITRE ATT&CK lookup used by the dashboard heatmap.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import mitre


class TestTechniqueInfo:
    def test_known_technique(self):
        info = mitre.technique_info("T1110")
        assert info["name"] == "Brute Force"
        assert info["tactic"] == "Credential Access"

    def test_known_subtechnique(self):
        info = mitre.technique_info("T1059.001")
        assert info["name"] == "PowerShell"
        assert info["tactic"] == "Execution"

    def test_unknown_subtechnique_falls_back_to_parent(self):
        info = mitre.technique_info("T1110.999")
        assert info["tactic"] == "Credential Access"  # inherited from T1110
        assert info["id"] == "T1110.999"

    def test_fully_unknown_is_graceful(self):
        info = mitre.technique_info("T9999")
        assert info["tactic"] == "Unknown"
        assert info["name"] == "T9999"

    def test_none_and_empty(self):
        assert mitre.technique_info(None)["tactic"] == "Unknown"
        assert mitre.technique_info("")["tactic"] == "Unknown"

    def test_case_insensitive(self):
        assert mitre.technique_info("t1047")["name"] == "Windows Management Instrumentation"


class TestSummarize:
    def test_counts_and_sorted(self):
        rows = mitre.summarize(["T1110", "T1110", "T1059.001"])
        assert rows[0]["id"] == "T1110"
        assert rows[0]["count"] == 2
        assert rows[1]["id"] == "T1059.001"

    def test_ignores_blank_and_nan(self):
        rows = mitre.summarize(["T1110", None, "", "nan", "N/A"])
        assert len(rows) == 1
        assert rows[0]["id"] == "T1110"

    def test_empty_input(self):
        assert mitre.summarize([]) == []

    def test_enriches_tactic(self):
        rows = mitre.summarize(["T1543.003"])
        assert rows[0]["tactic"] == "Persistence"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
