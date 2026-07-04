"""
Tests for the offline-first Notifier: severity gating, the always-on alert-log
backend, and the opt-in webhook backend (mocked, and proven offline-safe).
"""
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.notifier import Notifier


class TestSeverityGate:
    def test_threshold_high(self):
        n = Notifier(min_severity="High", alert_log_file="/dev/null")
        assert not n.should_notify("Low")
        assert not n.should_notify("Medium")
        assert n.should_notify("High")
        assert n.should_notify("Critical")

    def test_threshold_medium(self):
        n = Notifier(min_severity="Medium", alert_log_file="/dev/null")
        assert not n.should_notify("Low")
        assert n.should_notify("Medium")


class TestAlertLog:
    def test_writes_line(self, tmp_path):
        log = tmp_path / "alerts.log"
        n = Notifier(min_severity="High", alert_log_file=str(log), webhook_url="")
        n.notify("High", "Brute force", detail="T1110", event_id="4625", source_ip="1.2.3.4")
        content = log.read_text(encoding="utf-8")
        assert "HIGH" in content
        assert "Brute force" in content
        assert "1.2.3.4" in content
        assert "4625" in content

    def test_below_threshold_writes_nothing(self, tmp_path):
        log = tmp_path / "alerts.log"
        n = Notifier(min_severity="High", alert_log_file=str(log), webhook_url="")
        n.notify("Low", "Routine logon")
        assert not log.exists() or log.read_text(encoding="utf-8") == ""


class TestWebhook:
    def test_webhook_called_when_configured(self, tmp_path, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["data"] = req.data
            captured["timeout"] = timeout
            class R:
                def __enter__(self): return self
                def __exit__(self, *a): return False
            return R()

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        n = Notifier(min_severity="High", alert_log_file=str(tmp_path / "a.log"),
                     webhook_url="http://localhost:9999/hook")
        n.notify("Critical", "Successful brute force", event_id="4624", source_ip="9.9.9.9")
        assert captured["url"] == "http://localhost:9999/hook"
        assert captured["timeout"] == 3
        assert b"Successful brute force" in captured["data"]

    def test_webhook_failure_is_swallowed(self, tmp_path, monkeypatch):
        # A missing network must never break processing.
        def boom(req, timeout=None):
            raise OSError("network is unreachable")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        n = Notifier(min_severity="High", alert_log_file=str(tmp_path / "a.log"),
                     webhook_url="http://unreachable/hook")
        # Must not raise:
        n.notify("High", "still works offline", event_id="4625")
        # Alert-log still written despite webhook failure
        assert (tmp_path / "a.log").read_text(encoding="utf-8").strip() != ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
