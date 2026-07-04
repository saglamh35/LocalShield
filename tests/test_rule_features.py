"""
Tests for detection-engine expressiveness added in Track 2:
OR event-id matching, negative (not_*) conditions, and load-time schema
validation that skips malformed rules instead of crashing.
"""

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine, DetectionRule
from modules.rule_schema import validate_rule


class TestOrEventId:
    def test_event_id_list_matches_any(self):
        rule = DetectionRule(
            {
                "id": "or1",
                "name": "OR rule",
                "severity": "high",
                "conditions": {"provider": "Security", "event_id": ["4625", "4771"]},
            },
            "or.yaml",
        )
        now = datetime.now()
        assert rule.matches("4625", now, "x", "Security")
        assert rule.matches("4771", now, "x", "Security")
        assert not rule.matches("4624", now, "x", "Security")

    def test_single_event_id_still_works(self):
        rule = DetectionRule(
            {"id": "s1", "name": "single", "severity": "low", "conditions": {"event_id": "4624"}},
            "s.yaml",
        )
        assert rule.matches("4624", datetime.now(), "x", "Security")
        assert not rule.matches("4625", datetime.now(), "x", "Security")


class TestNegation:
    def test_not_message_regex_excludes(self):
        rule = DetectionRule(
            {
                "id": "n1",
                "name": "neg",
                "severity": "medium",
                "conditions": {"event_id": "4624", "message_regex": "logon", "not_message_regex": "ANONYMOUS"},
            },
            "n.yaml",
        )
        now = datetime.now()
        assert rule.matches("4624", now, "interactive logon by alice", "Security")
        assert not rule.matches("4624", now, "ANONYMOUS logon", "Security")

    def test_not_command_line_regex_excludes(self):
        rule = DetectionRule(
            {
                "id": "n2",
                "name": "neg2",
                "severity": "high",
                "conditions": {
                    "provider": "Sysmon",
                    "event_id": "1",
                    "command_line_regex": "powershell",
                    "not_command_line_regex": "-ExecutionPolicy Bypass -File update",
                },
            },
            "n2.yaml",
        )
        now = datetime.now()
        assert rule.matches("1", now, "", "Sysmon", {"CommandLine": "powershell -enc AAAA"})
        assert not rule.matches(
            "1", now, "", "Sysmon", {"CommandLine": "powershell -ExecutionPolicy Bypass -File update.ps1"}
        )


class TestSchemaValidation:
    def test_valid_rule_passes(self):
        validate_rule({"id": "v", "name": "ok", "severity": "high", "conditions": {"event_id": "4625"}})  # no raise

    def test_bad_severity_raises(self):
        with pytest.raises(Exception):
            validate_rule({"name": "bad", "severity": "urgent"})

    def test_unknown_condition_key_raises(self):
        with pytest.raises(Exception):
            validate_rule({"name": "bad", "conditions": {"event_id": "1", "bogus_key": 1}})

    def test_engine_skips_invalid_rule_keeps_valid(self, tmp_path):
        (tmp_path / "good.yaml").write_text(
            "id: good1\nname: Good\nseverity: high\nconditions:\n  event_id: '4625'\n",
            encoding="utf-8",
        )
        # invalid: unknown severity
        (tmp_path / "bad.yaml").write_text(
            "id: bad1\nname: Bad\nseverity: apocalyptic\nconditions:\n  event_id: '1'\n",
            encoding="utf-8",
        )
        engine = DetectionEngine(rules_dir=str(tmp_path))
        ids = {r.id for r in engine.rules}
        assert "good1" in ids
        assert "bad1" not in ids  # skipped, engine did not crash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
