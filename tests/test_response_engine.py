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


class TestIPv6:
    @pytest.mark.parametrize(
        "ip,valid",
        [
            ("2607:f8b0::1", True),
            ("2001:db8::5", True),
            ("::1", True),
            ("1.2.3.4", True),
            ("2607:f8b0::zzzz", False),
            ("not-an-ip", False),
        ],
    )
    def test_is_valid_ip_both_families(self, fw, ip, valid):
        assert fw.is_valid_ip(ip) is valid

    @pytest.mark.parametrize(
        "ip,private",
        [
            ("::1", True),  # loopback
            ("fe80::1", True),  # link-local
            ("fd12:3456::1", True),  # unique-local (ULA)
            ("2607:f8b0::1", False),  # public
        ],
    )
    def test_is_private_ipv6(self, fw, ip, private):
        assert fw.is_private_ip(ip) is private

    def test_extract_ips_finds_ipv6(self, fw):
        text = "Connections from 2607:f8b0::1 and 1.2.3.4 at 10:30:00 today"
        ips = fw.extract_ips_from_text(text)
        assert "2607:f8b0::1" in ips
        assert "1.2.3.4" in ips
        assert "10:30:00" not in ips  # timestamps are not addresses

    def test_extract_source_ipv6_windows_field(self, fw):
        text = "An account failed to log on.\n\tSource Network Address:\t2001:db8::5\n"
        assert fw.extract_source_ips_from_text(text) == ["2001:db8::5"]

    def test_extract_source_ipv6_ssh(self, fw):
        text = "Failed password for root from 2001:db8::7 port 22 ssh2"
        assert fw.extract_source_ips_from_text(text) == ["2001:db8::7"]

    def test_ipv6_in_attacker_controlled_field_is_ignored(self, fw):
        # LS-01 regression, IPv6 flavour: an address planted in a name field
        # must never become a blocking candidate.
        text = "An account failed to log on.\n\tAccount Name:\t2607:f8b0::99\n\tWorkstation Name:\tEVIL\n"
        assert fw.extract_source_ips_from_text(text) == []

    def test_source_extraction_normalizes_spelling(self, fw):
        text = "Source Network Address: 2001:0db8:0000:0000:0000:0000:0000:0005"
        assert fw.extract_source_ips_from_text(text) == ["2001:db8::5"]

    def test_block_ipv6_builds_safe_rule_name(self, fw, monkeypatch):
        calls = {}

        def fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            return FakeResult(returncode=0)

        monkeypatch.setattr(response_engine.subprocess, "run", fake_run)
        assert fw.block_ip("2607:f8b0::1") is True
        assert "remoteip=2607:f8b0::1" in calls["cmd"]
        # Rule names must not contain ':' (not name-safe)
        name_arg = next(part for part in calls["cmd"] if part.startswith("name="))
        assert ":" not in name_arg.removeprefix("name=")

    def test_allowlist_matches_any_ipv6_spelling(self, monkeypatch):
        # The allowlist entry and the log spelling differ but are the same address
        fw2 = FirewallManager(allowlist=["2001:4860:4860:0:0:0:0:8888"])

        def fail(*a, **k):
            raise AssertionError("subprocess must not run for an allowlisted IP")

        monkeypatch.setattr(response_engine.subprocess, "run", fail)
        assert fw2.block_ip("2001:4860:4860::8888") is False

    def test_private_ipv6_is_refused(self, fw, monkeypatch):
        def fail(*a, **k):
            raise AssertionError("subprocess must not run for a private IP")

        monkeypatch.setattr(response_engine.subprocess, "run", fail)
        assert fw.block_ip("fe80::1") is False
        assert fw.block_ip("fd00::1") is False


class TestDryRun:
    def test_dry_run_blocks_without_firewall_command(self, monkeypatch):
        fw = FirewallManager(allowlist=[], dry_run=True)

        def fail(*a, **k):
            raise AssertionError("subprocess must not run in dry-run mode")

        monkeypatch.setattr(response_engine.subprocess, "run", fail)
        assert fw.block_ip("93.184.216.34") is True
        assert "93.184.216.34" in fw.blocked_ips

    def test_dry_run_safety_checks_still_apply(self, monkeypatch):
        fw = FirewallManager(allowlist=["8.8.8.8"], dry_run=True)
        monkeypatch.setattr(
            response_engine.subprocess,
            "run",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no subprocess in dry-run")),
        )
        assert fw.block_ip("8.8.8.8") is False  # allowlisted
        assert fw.block_ip("192.168.1.5") is False  # private
        assert fw.block_ip("garbage") is False  # invalid

    def test_dry_run_unblock(self, monkeypatch):
        fw = FirewallManager(allowlist=[], dry_run=True)
        monkeypatch.setattr(
            response_engine.subprocess,
            "run",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no subprocess in dry-run")),
        )
        assert fw.block_ip("93.184.216.34") is True
        assert fw.unblock_ip("93.184.216.34") is True
        assert "93.184.216.34" not in fw.blocked_ips

    def test_default_is_real_mode(self):
        assert FirewallManager(allowlist=[]).dry_run is False


class TestThreadSafety:
    def test_concurrent_block_ip_invokes_netsh_once(self, monkeypatch):
        # block_ip runs in the watcher's thread pool; the check-and-reserve
        # must guarantee a single netsh invocation per IP.
        import threading

        calls = []
        call_lock = threading.Lock()

        def fake_run(cmd, **kwargs):
            with call_lock:
                calls.append(cmd)
            return FakeResult(returncode=0)

        monkeypatch.setattr(response_engine.subprocess, "run", fake_run)
        fw = FirewallManager(allowlist=[], dry_run=False)

        results = []
        threads = [threading.Thread(target=lambda: results.append(fw.block_ip("93.184.216.34"))) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(calls) == 1, "concurrent blocks of the same IP must run netsh exactly once"
        assert all(results)
        assert fw.blocked_ips == {"93.184.216.34"}

    def test_failed_block_rolls_back_reservation(self, monkeypatch):
        monkeypatch.setattr(
            response_engine.subprocess,
            "run",
            lambda *a, **k: FakeResult(returncode=1, stderr="unexpected error"),
        )
        fw = FirewallManager(allowlist=[], dry_run=False)

        assert fw.block_ip("93.184.216.34") is False
        assert "93.184.216.34" not in fw.blocked_ips, "a failed block must not stay reserved"
        # A retry after the failure must attempt netsh again (not short-circuit)
        monkeypatch.setattr(response_engine.subprocess, "run", lambda *a, **k: FakeResult(returncode=0))
        assert fw.block_ip("93.184.216.34") is True
        assert "93.184.216.34" in fw.blocked_ips


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
