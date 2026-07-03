"""
Regression tests for the security/logic fixes found during the audit:

1. Brute-force threshold counts PER SOURCE IP (group_by: source_ip), so five
   unrelated single failures from five hosts no longer produce a false alert.
2. Blocking candidates come only from structured source-address fields, so an
   IP embedded in an attacker-controlled string (username, workstation name)
   cannot weaponize the auto-response against arbitrary third parties.
3. The log watcher deduplicates events by Windows RecordNumber, so the 5-second
   overlap window cannot process the same event twice.
"""
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine
from modules.response_engine import FirewallManager


@pytest.fixture
def engine():
    rules_dir = Path(__file__).parent.parent / "rules"
    return DetectionEngine(rules_dir=str(rules_dir))


class TestPerSourceBruteForce:
    def _msg(self, ip, user="victim"):
        return (f"An account failed to log on.\n"
                f"\tAccount Name:\t{user}\n"
                f"\tSource Network Address:\t{ip}\n")

    def test_five_failures_from_five_hosts_do_not_trigger(self, engine):
        base = datetime.now()
        result = None
        for i in range(5):
            result = engine.check_event(
                "4625", base + timedelta(seconds=i), self._msg(f"10.0.0.{i}"), "Security"
            )
        assert result is None, "unrelated single failures must not add up to one alert"

    def test_five_failures_from_same_host_trigger(self, engine):
        base = datetime.now()
        result = None
        for i in range(5):
            result = engine.check_event(
                "4625", base + timedelta(seconds=i), self._msg("203.0.113.66"), "Security"
            )
        assert result is not None
        assert result["rule_id"] == "brute_force_001"

    def test_message_without_ip_falls_back_to_global_counter(self, engine):
        # Events with no extractable source IP still count (grouped by event_id)
        base = datetime.now()
        result = None
        for i in range(5):
            result = engine.check_event(
                "4625", base + timedelta(seconds=i), "Account Name: X", "Security"
            )
        assert result is not None


class TestSourceIPExtraction:
    def test_structured_fields_extracted(self):
        fw = FirewallManager(allowlist=[])
        text = ("An account failed to log on.\n"
                "\tSource Network Address:\t203.0.113.5\n"
                "pam_unix: authentication failure; rhost=198.51.100.7\n"
                "Failed password for root from 192.0.2.9 port 22\n")
        ips = fw.extract_source_ips_from_text(text)
        assert ips == ["203.0.113.5", "198.51.100.7", "192.0.2.9"]

    def test_ip_inside_attacker_controlled_string_is_ignored(self):
        # The old blanket scan would have picked 8.8.8.8 out of the username
        # and blocked it. The source-field extraction must not.
        fw = FirewallManager(allowlist=[])
        text = ("An account failed to log on.\n"
                "\tAccount Name:\t8.8.8.8\n"
                "\tWorkstation Name:\tEVIL-1.2.3.4\n")
        assert fw.extract_source_ips_from_text(text) == []

    def test_deduplicates_and_validates(self):
        fw = FirewallManager(allowlist=[])
        text = ("Source Network Address: 203.0.113.5\n"
                "Source Network Address: 203.0.113.5\n"
                "Source Network Address: 999.999.1.1\n")
        assert fw.extract_source_ips_from_text(text) == ["203.0.113.5"]


@pytest.fixture(scope="module")
def watcher_cls():
    # log_watcher imports pywin32 at module load; stub it so the pure
    # dedup logic is testable on any platform.
    for name in ("win32evtlog", "win32evtlogutil", "win32con"):
        sys.modules.setdefault(name, types.ModuleType(name))
    import log_watcher
    return log_watcher.LogWatcher


class TestRecordNumberDedup:
    def _fake_event(self, record, ts):
        return SimpleNamespace(RecordNumber=record, TimeGenerated=ts)

    def _bare_watcher(self, watcher_cls):
        w = watcher_cls.__new__(watcher_cls)  # skip __init__ (needs Windows/DB)
        w._last_record = {}
        return w

    def test_same_event_not_selected_twice(self, watcher_cls):
        w = self._bare_watcher(watcher_cls)
        now = datetime.now()
        threshold = now - timedelta(seconds=60)
        events = [self._fake_event(100 + i, now) for i in range(3)]

        first = w._select_new_events("Security", events, threshold)
        assert len(first) == 3

        # Second read returns the same events (5s overlap) -> all skipped
        second = w._select_new_events("Security", events, threshold)
        assert second == []

    def test_new_records_still_selected(self, watcher_cls):
        w = self._bare_watcher(watcher_cls)
        now = datetime.now()
        threshold = now - timedelta(seconds=60)
        w._select_new_events("Security", [self._fake_event(10, now)], threshold)

        newer = [self._fake_event(11, now), self._fake_event(12, now)]
        assert len(w._select_new_events("Security", newer, threshold)) == 2

    def test_channels_tracked_independently(self, watcher_cls):
        w = self._bare_watcher(watcher_cls)
        now = datetime.now()
        threshold = now - timedelta(seconds=60)
        w._select_new_events("Security", [self._fake_event(50, now)], threshold)
        # Same record number on a different channel is still new
        assert len(w._select_new_events("Sysmon", [self._fake_event(50, now)], threshold)) == 1

    def test_old_events_filtered_by_time(self, watcher_cls):
        w = self._bare_watcher(watcher_cls)
        now = datetime.now()
        threshold = now - timedelta(seconds=60)
        old = self._fake_event(999, now - timedelta(hours=1))
        assert w._select_new_events("Security", [old], threshold) == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
