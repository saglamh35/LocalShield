"""
Regression tests for the event-ingestion fixes:

1. A burst larger than one ReadEventLog batch (~1000 events) is fully
   drained instead of silently dropping everything but the newest batch —
   previously _last_record advanced past the unread events, losing them
   exactly when detection matters most (e.g. a brute-force flood).
2. The drain loop stops as soon as it reaches records that were already
   processed, and is bounded so a flooding channel cannot pin the watcher.
3. A RecordNumber reset (Windows log cleared, Event 1102) re-baselines the
   per-channel high-water mark instead of blinding the watcher until the
   counter climbs back past the old maximum.
4. The startup time filter no longer applies in steady state, so an event
   delivered late (queued > 5s) is still processed — its RecordNumber
   proves it was never seen.
"""

import sys
import types
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# log_watcher imports pywin32 at module load; stub it so the pure reading
# logic is testable on any platform.
for name in ("win32evtlog", "win32evtlogutil", "win32con"):
    sys.modules.setdefault(name, types.ModuleType(name))

import log_watcher


def _fake_event(record, ts=None):
    return SimpleNamespace(RecordNumber=record, TimeGenerated=ts or datetime.now())


def _bare_watcher():
    w = log_watcher.LogWatcher.__new__(log_watcher.LogWatcher)  # skip __init__ (needs Windows/DB)
    w._last_record = {}
    return w


@pytest.fixture
def evtlog_stub(monkeypatch):
    """Give the stubbed win32evtlog module the flags the drain loop reads."""
    stub = sys.modules["win32evtlog"]
    monkeypatch.setattr(stub, "EVENTLOG_BACKWARDS_READ", 8, raising=False)
    monkeypatch.setattr(stub, "EVENTLOG_SEQUENTIAL_READ", 1, raising=False)
    return stub


class TestChannelDrain:
    def _batches(self, monkeypatch, stub, batches):
        """Serve pre-built batches from ReadEventLog and count the calls."""
        calls = {"count": 0}

        def fake_read(handle, flags, offset, size):
            idx = calls["count"]
            calls["count"] += 1
            return batches[idx] if idx < len(batches) else []

        monkeypatch.setattr(stub, "ReadEventLog", fake_read, raising=False)
        return calls

    def test_burst_larger_than_one_batch_is_fully_drained(self, monkeypatch, evtlog_stub):
        # 3000 events arrived since the last cycle; ReadEventLog returns them
        # newest-first in batches of 1000.
        batches = [
            [_fake_event(r) for r in range(3000, 2000, -1)],
            [_fake_event(r) for r in range(2000, 1000, -1)],
            [_fake_event(r) for r in range(1000, 0, -1)],
            [],
        ]
        w = _bare_watcher()
        w._last_record = {"Security": 500}
        self._batches(monkeypatch, evtlog_stub, batches)

        events = w._read_channel_events("Security", object())
        threshold = datetime.now() - timedelta(seconds=60)
        selected = w._select_new_events("Security", events, threshold)

        assert len(selected) == 2500, "every event between the high-water mark and newest must survive"
        assert {e.RecordNumber for e in selected} == set(range(501, 3001))
        assert w._last_record["Security"] == 3000

    def test_drain_stops_at_high_water_mark(self, monkeypatch, evtlog_stub):
        batches = [
            [_fake_event(r) for r in range(2000, 1000, -1)],
            [_fake_event(r) for r in range(1000, 0, -1)],  # dips below last_record
            [_fake_event(r) for r in range(3000, 2500, -1)],  # must never be requested
        ]
        w = _bare_watcher()
        w._last_record = {"Security": 900}
        calls = self._batches(monkeypatch, evtlog_stub, batches)

        w._read_channel_events("Security", object())
        assert calls["count"] == 2, "reading past already-processed records must stop the drain"

    def test_drain_is_bounded(self, monkeypatch, evtlog_stub):
        # A channel that floods forever: same fresh batch on every call.
        endless = [[_fake_event(r) for r in range(10_000, 9_000, -1)]] * 50
        w = _bare_watcher()
        w._last_record = {"Security": 0}
        calls = self._batches(monkeypatch, evtlog_stub, endless)

        w._read_channel_events("Security", object())
        assert calls["count"] == log_watcher._MAX_READ_BATCHES


class TestRecordNumberReset:
    def test_log_clear_rebaselines(self):
        # The Security log was cleared: numbering restarted at 1 while our
        # high-water mark is still 5000. Post-clear activity must be seen.
        w = _bare_watcher()
        w._last_record = {"Security": 5000}
        now = datetime.now()
        threshold = now - timedelta(seconds=60)
        events = [_fake_event(r, now) for r in (1, 2, 3)]

        selected = w._select_new_events("Security", events, threshold)

        assert len(selected) == 3, "events after a log clear must not be deduplicated away"
        assert w._last_record["Security"] == 3

    def test_late_delivered_event_survives_time_threshold(self):
        # Steady state (last_record already set): an event delivered late has
        # an old TimeGenerated but a brand-new RecordNumber. It must not be
        # dropped by the startup time filter.
        w = _bare_watcher()
        now = datetime.now()
        threshold = now - timedelta(seconds=60)
        w._select_new_events("Security", [_fake_event(10, now)], threshold)

        late = _fake_event(11, now - timedelta(hours=2))
        assert w._select_new_events("Security", [late], threshold) == [late]

    def test_baseline_read_still_skips_history(self):
        # First read after startup: the historical backlog must be skipped.
        w = _bare_watcher()
        now = datetime.now()
        threshold = now - timedelta(seconds=60)
        events = [_fake_event(1, now - timedelta(hours=1)), _fake_event(2, now)]

        selected = w._select_new_events("Security", events, threshold)
        assert [e.RecordNumber for e in selected] == [2]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
