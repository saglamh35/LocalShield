"""
Tests for the audit-tampering, scheduled-task, and RDP brute-force rules.
Loads the real rules/ directory so the shipped YAML is exercised end-to-end.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine

RULES_DIR = str(Path(__file__).parent.parent / "rules")


@pytest.fixture
def engine():
    # Function-scoped: threshold rules keep per-source history, so every test
    # gets a clean engine.
    return DetectionEngine(rules_dir=RULES_DIR)


def _rule(engine, rule_id):
    for r in engine.rules:
        if r.id == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not loaded")


def _rdp_fail(ip):
    return (
        "An account failed to log on.\n"
        "Logon Type:\t\t\t10\n"
        "Account For Which Logon Failed:\n"
        "\tAccount Name:\t\tadmin\n"
        "Network Information:\n"
        f"\tSource Network Address:\t{ip}\n"
    )


def _network_fail(ip):
    return f"An account failed to log on.\nLogon Type:\t\t\t3\nNetwork Information:\n\tSource Network Address:\t{ip}\n"


class TestRulesLoaded:
    def test_new_rules_present(self, engine):
        ids = {r.id for r in engine.rules}
        for rid in [
            "audit_log_cleared_001",
            "scheduled_task_created_001",
            "audit_policy_change_001",
            "rdp_brute_force_001",
        ]:
            assert rid in ids, f"missing rule: {rid}"


class TestAuditTamperingRules:
    def test_audit_log_cleared_fires(self, engine):
        r = _rule(engine, "audit_log_cleared_001")
        assert r.matches("1102", datetime.now(), "The audit log was cleared.", "Security")
        assert r.severity == "critical"
        assert "T1070.001" in r.mitre

    def test_audit_log_cleared_wrong_event_or_provider(self, engine):
        r = _rule(engine, "audit_log_cleared_001")
        assert not r.matches("1100", datetime.now(), "The event logging service has shut down.", "Security")
        assert not r.matches("1102", datetime.now(), "x", "Sysmon")

    def test_audit_policy_change_fires(self, engine):
        r = _rule(engine, "audit_policy_change_001")
        assert r.matches("4719", datetime.now(), "System audit policy was changed.", "Security")
        assert "T1562.002" in r.mitre

    def test_scheduled_task_created_fires(self, engine):
        r = _rule(engine, "scheduled_task_created_001")
        assert r.matches("4698", datetime.now(), "A scheduled task was created.", "Security")
        assert "T1053.005" in r.mitre
        # Task deletion (4699) must not trigger the creation rule
        assert not r.matches("4699", datetime.now(), "A scheduled task was deleted.", "Security")


class TestRdpBruteForce:
    def test_five_type10_failures_fire(self, engine):
        base = datetime.now()
        ip = "203.0.113.99"
        fired = None
        for i in range(5):
            results = engine.check_event_all("4625", base + timedelta(seconds=i * 5), _rdp_fail(ip), "Security")
            rdp = [r for r in results if r.get("rule_id") == "rdp_brute_force_001"]
            if i < 4:
                assert not rdp, f"RDP rule must not fire on attempt #{i + 1}"
            else:
                assert rdp, "RDP rule must fire on the 5th type-10 failure"
                fired = rdp[0]

        assert fired is not None
        assert fired["risk_level"] == "High"
        assert "T1110" in fired["mitre_techniques"]
        assert "T1021.001" in fired["mitre_techniques"]

    def test_type3_failures_do_not_fire_rdp_rule(self, engine):
        base = datetime.now()
        ip = "203.0.113.98"
        for i in range(6):
            results = engine.check_event_all("4625", base + timedelta(seconds=i * 5), _network_fail(ip), "Security")
            assert not [r for r in results if r.get("rule_id") == "rdp_brute_force_001"], (
                "Logon Type 3 failures must not trip the RDP rule"
            )

    def test_counting_is_per_source_ip(self, engine):
        base = datetime.now()
        # 4 failures from one IP + 4 from another: neither source reaches 5
        for i in range(4):
            engine.check_event_all("4625", base + timedelta(seconds=i * 5), _rdp_fail("198.51.100.1"), "Security")
        for i in range(4):
            results = engine.check_event_all(
                "4625", base + timedelta(seconds=25 + i * 5), _rdp_fail("198.51.100.2"), "Security"
            )
            assert not [r for r in results if r.get("rule_id") == "rdp_brute_force_001"], (
                "Counts from different source IPs must not be merged"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
