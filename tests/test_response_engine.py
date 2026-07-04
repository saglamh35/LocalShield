"""
Unit tests for the FirewallManager (response engine).
subprocess.run is patched so no real netsh/firewall commands are executed.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import response_engine
from modules.response_engine import FirewallManager


class FakeResult:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""


@pytest.fixture
def fw():
    # Empty allowlist so the block/unblock tests can use a public IP freely;
    # the allowlist behaviour is covered by its own test.
    return FirewallManager(allowlist=[])


class TestValidation:
    @pytest.mark.parametrize(
        "ip,valid",
        [
            ("1.2.3.4", True),
            ("192.168.0.1", True),
            ("255.255.255.255", True),
            ("999.1.1.1", False),
            ("1.2.3", False),
            ("abc", False),
            ("", False),
        ],
    )
    def test_is_valid_ipv4(self, fw, ip, valid):
        assert fw.is_valid_ipv4(ip) is valid

    @pytest.mark.parametrize(
        "ip,private",
        [
            ("10.0.0.1", True),
            ("172.16.5.5", True),
            ("192.168.1.100", True),
            ("127.0.0.1", True),
            ("169.254.1.1", True),
            ("8.8.8.8", False),
            ("1.2.3.4", False),
        ],
    )
    def test_is_private_ip(self, fw, ip, private):
        assert fw.is_private_ip(ip) is private

    def test_extract_ips_from_text(self, fw):
        text = "Source 8.8.8.8 hit 1.2.3.4 but 999.999.999.999 is invalid"
        ips = fw.extract_ips_from_text(text)
        assert "8.8.8.8" in ips
        assert "1.2.3.4" in ips
        assert "999.999.999.999" not in ips


class TestBlocking:
    def test_block_public_ip_success(self, fw, monkeypatch):
        calls = {}

        def fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            return FakeResult(returncode=0)

        monkeypatch.setattr(response_engine.subprocess, "run", fake_run)
        assert fw.block_ip("8.8.8.8") is True
        assert "8.8.8.8" in fw.blocked_ips
        # The firewall rule must target the right IP
        assert "remoteip=8.8.8.8" in calls["cmd"]

    def test_allowlisted_ip_is_refused(self, monkeypatch):
        # A critical IP on the allowlist must never be blocked
        fw = FirewallManager(allowlist=["8.8.8.8"])

        def fail(*a, **k):
            raise AssertionError("subprocess must not run for an allowlisted IP")

        monkeypatch.setattr(response_engine.subprocess, "run", fail)
        assert fw.block_ip("8.8.8.8") is False
        assert "8.8.8.8" not in fw.blocked_ips

    def test_block_private_ip_is_refused(self, fw, monkeypatch):
        def fail(*a, **k):
            raise AssertionError("subprocess must not run for a private IP")

        monkeypatch.setattr(response_engine.subprocess, "run", fail)
        assert fw.block_ip("192.168.1.50") is False
        assert "192.168.1.50" not in fw.blocked_ips

    def test_block_invalid_ip_is_refused(self, fw, monkeypatch):
        def fail(*a, **k):
            raise AssertionError("subprocess must not run for an invalid IP")

        monkeypatch.setattr(response_engine.subprocess, "run", fail)
        assert fw.block_ip("not-an-ip") is False

    def test_already_blocked_short_circuits(self, fw, monkeypatch):
        fw.blocked_ips.add("8.8.8.8")

        def fail(*a, **k):
            raise AssertionError("subprocess must not run when already blocked")

        monkeypatch.setattr(response_engine.subprocess, "run", fail)
        assert fw.block_ip("8.8.8.8") is True

    def test_existing_rule_is_treated_as_success(self, fw, monkeypatch):
        monkeypatch.setattr(
            response_engine.subprocess,
            "run",
            lambda *a, **k: FakeResult(returncode=1, stderr="Rule already exists."),
        )
        assert fw.block_ip("8.8.8.8") is True
        assert "8.8.8.8" in fw.blocked_ips

    def test_block_failure_returns_false(self, fw, monkeypatch):
        monkeypatch.setattr(
            response_engine.subprocess,
            "run",
            lambda *a, **k: FakeResult(returncode=1, stderr="Access denied."),
        )
        assert fw.block_ip("8.8.8.8") is False
        assert "8.8.8.8" not in fw.blocked_ips

    def test_timeout_returns_false(self, fw, monkeypatch):
        def raise_timeout(*a, **k):
            raise subprocess.TimeoutExpired(cmd="netsh", timeout=10)

        monkeypatch.setattr(response_engine.subprocess, "run", raise_timeout)
        assert fw.block_ip("8.8.8.8") is False

    def test_unblock_success(self, fw, monkeypatch):
        fw.blocked_ips.add("8.8.8.8")
        monkeypatch.setattr(
            response_engine.subprocess,
            "run",
            lambda *a, **k: FakeResult(returncode=0),
        )
        assert fw.unblock_ip("8.8.8.8") is True
        assert "8.8.8.8" not in fw.blocked_ips


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
