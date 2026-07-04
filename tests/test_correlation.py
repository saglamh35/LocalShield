"""
Tests for cross-event correlation: a successful logon (4624) after repeated
failures (4625) from the same source IP fires the 'successful brute force' rule.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine


@pytest.fixture
def engine():
    return DetectionEngine(rules_dir=str(Path(__file__).parent.parent / "rules"))


def _fail(ip):
    return f"An account failed to log on.\n\tSource Network Address:\t{ip}\n"


def _success(ip):
    return f"An account was successfully logged on.\n\tSource Network Address:\t{ip}\n"


class TestSuccessfulBruteForce:
    def test_success_after_failures_fires(self, engine):
        base = datetime.now()
        ip = "203.0.113.50"
        # 5 failed logons from the attacker IP
        for i in range(5):
            engine.check_event("4625", base + timedelta(seconds=i), _fail(ip), "Security")
        # then a successful logon from the same IP -> correlation fires
        result = engine.check_event("4624", base + timedelta(seconds=6), _success(ip), "Security")
        assert result is not None
        assert result["rule_id"] == "brute_force_success_001"
        assert result["severity"] == "critical"

    def test_lone_success_does_not_fire(self, engine):
        result = engine.check_event("4624", datetime.now(), _success("198.51.100.9"), "Security")
        # No correlation rule should fire (may be None or a non-correlation match)
        if result is not None:
            assert result["rule_id"] != "brute_force_success_001"

    def test_success_from_different_ip_does_not_fire(self, engine):
        base = datetime.now()
        for i in range(5):
            engine.check_event("4625", base + timedelta(seconds=i), _fail("10.0.0.1"), "Security")
        # success from a DIFFERENT IP with no failures of its own
        result = engine.check_event("4624", base + timedelta(seconds=6), _success("10.0.0.99"), "Security")
        if result is not None:
            assert result["rule_id"] != "brute_force_success_001"

    def test_failures_outside_window_do_not_correlate(self, engine):
        base = datetime.now()
        ip = "203.0.113.77"
        for i in range(5):
            engine.check_event("4625", base + timedelta(seconds=i), _fail(ip), "Security")
        # success far outside the 300s correlation window
        result = engine.check_event("4624", base + timedelta(seconds=600), _success(ip), "Security")
        if result is not None:
            assert result["rule_id"] != "brute_force_success_001"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
