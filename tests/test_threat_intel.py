"""
Unit tests for the ThreatIntel module.
Uses a temporary CSV feed so the tests do not depend on data/threat_intel.csv.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.threat_intel import ThreatIntel

CSV_CONTENT = """ip,category,confidence
1.2.3.4,Botnet,100
5.6.7.8,BruteForce,90
8.8.8.8,Benign,0
9.9.9.9,Unknown,0
"""


@pytest.fixture
def feed(tmp_path):
    """Write a temporary threat-intel CSV and return a loaded ThreatIntel."""
    csv_file = tmp_path / "threat_intel.csv"
    csv_file.write_text(CSV_CONTENT, encoding="utf-8")
    return ThreatIntel(csv_path=str(csv_file))


class TestThreatIntel:
    def test_only_malicious_ips_loaded(self, feed):
        # Benign (8.8.8.8) and confidence-0 (9.9.9.9) rows are skipped
        assert feed.get_threat_count() == 2

    def test_malicious_ip_match(self, feed):
        result = feed.check_ip("1.2.3.4")
        assert result is not None
        assert result["category"] == "Botnet"
        assert result["confidence"] == 100
        assert result["ip"] == "1.2.3.4"

    def test_benign_ip_returns_none(self, feed):
        assert feed.check_ip("8.8.8.8") is None

    def test_unknown_ip_returns_none(self, feed):
        assert feed.check_ip("203.0.113.5") is None

    def test_whitespace_is_stripped(self, feed):
        assert feed.check_ip("  5.6.7.8  ") is not None

    def test_empty_input_returns_none(self, feed):
        assert feed.check_ip("") is None
        assert feed.check_ip("   ") is None

    def test_missing_file_disables_checks(self, tmp_path):
        ti = ThreatIntel(csv_path=str(tmp_path / "does_not_exist.csv"))
        assert ti.get_threat_count() == 0
        assert ti.check_ip("1.2.3.4") is None

    def test_malformed_row_does_not_abort_feed(self, tmp_path):
        """A row with a non-numeric confidence is skipped; the rest still load."""
        csv_file = tmp_path / "threat_intel.csv"
        csv_file.write_text(
            "ip,category,confidence\n"
            "1.2.3.4,Botnet,100\n"
            "5.6.7.8,BruteForce,not_a_number\n"
            "9.9.9.10,Scanner,\n"
            "10.20.30.40,Malware,80\n",
            encoding="utf-8",
        )
        ti = ThreatIntel(csv_path=str(csv_file))
        # Bad row (5.6.7.8) is skipped, empty confidence (9.9.9.10) counts as 0
        # and is filtered as benign; the rows around them still load.
        assert ti.check_ip("1.2.3.4") is not None
        assert ti.check_ip("10.20.30.40") is not None
        assert ti.check_ip("5.6.7.8") is None
        assert ti.get_threat_count() == 2

    def test_reload(self, feed, tmp_path):
        # Overwrite the feed with a single new malicious IP and reload
        (tmp_path / "threat_intel.csv").write_text("ip,category,confidence\n10.20.30.40,Malware,80\n", encoding="utf-8")
        feed.reload()
        assert feed.get_threat_count() == 1
        assert feed.check_ip("10.20.30.40") is not None
        assert feed.check_ip("1.2.3.4") is None


CIDR_CONTENT = """ip,category,confidence
1.2.3.4,Botnet,100
185.220.0.0/16,TorExit,85
10.10.0.0/24,Internal-Bad,70
bad-cidr/33,Broken,50
"""


@pytest.fixture
def cidr_feed(tmp_path):
    csv_file = tmp_path / "threat_intel.csv"
    csv_file.write_text(CIDR_CONTENT, encoding="utf-8")
    return ThreatIntel(csv_path=str(csv_file))


class TestCIDRRanges:
    def test_counts_ips_and_ranges(self, cidr_feed):
        # 1 exact IP + 2 valid ranges (the /33 is invalid and skipped)
        assert cidr_feed.get_threat_count() == 3

    def test_ip_inside_range_matches(self, cidr_feed):
        result = cidr_feed.check_ip("185.220.101.42")
        assert result is not None
        assert result["category"] == "TorExit"
        assert result["matched_range"] == "185.220.0.0/16"

    def test_ip_outside_range_no_match(self, cidr_feed):
        assert cidr_feed.check_ip("185.221.0.1") is None

    def test_exact_ip_still_matches_alongside_ranges(self, cidr_feed):
        assert cidr_feed.check_ip("1.2.3.4") is not None

    def test_second_range_boundaries(self, cidr_feed):
        assert cidr_feed.check_ip("10.10.0.255") is not None  # inside /24
        assert cidr_feed.check_ip("10.10.1.0") is None  # just outside /24

    def test_garbage_input_is_safe(self, cidr_feed):
        assert cidr_feed.check_ip("not-an-ip") is None


IPV6_CONTENT = """ip,category,confidence
2001:0db8:0000:0000:0000:0000:0000:0001,Botnet,95
2607:f8b0::/32,BadRange,80
1.2.3.4,Botnet,100
"""


@pytest.fixture
def ipv6_feed(tmp_path):
    csv_file = tmp_path / "threat_intel.csv"
    csv_file.write_text(IPV6_CONTENT, encoding="utf-8")
    return ThreatIntel(csv_path=str(csv_file))


class TestIPv6Feed:
    def test_all_entries_loaded(self, ipv6_feed):
        assert ipv6_feed.get_threat_count() == 3

    def test_exact_ipv6_matches_any_spelling(self, ipv6_feed):
        # The feed stores the long form; the query uses the compressed form
        result = ipv6_feed.check_ip("2001:db8::1")
        assert result is not None
        assert result["category"] == "Botnet"

    def test_ipv6_cidr_range_matches(self, ipv6_feed):
        result = ipv6_feed.check_ip("2607:f8b0:1234::9")
        assert result is not None
        assert result["matched_range"] == "2607:f8b0::/32"

    def test_ipv6_outside_range_no_match(self, ipv6_feed):
        assert ipv6_feed.check_ip("2607:f8b1::1") is None

    def test_ipv4_still_works_alongside_ipv6(self, ipv6_feed):
        assert ipv6_feed.check_ip("1.2.3.4") is not None
        assert ipv6_feed.check_ip("5.6.7.8") is None


class TestFeedUpdater:
    """update_feed is opt-in (CLI only) — these tests never touch the network."""

    FEED_TEXT = "# abuse.ch Feodo Tracker - sample\n203.0.113.10\nnot-an-ip\n198.51.100.0/24\n\n2001:db8::7\n"

    def _mock_urlopen(self, monkeypatch, payload):
        import contextlib
        import io
        import urllib.request

        @contextlib.contextmanager
        def fake_urlopen(url, timeout=0):
            yield io.BytesIO(payload.encode("utf-8"))

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    def test_rejects_non_https_url(self, tmp_path):
        from modules.threat_intel import update_feed

        with pytest.raises(ValueError):
            update_feed(str(tmp_path / "x.csv"), url="http://feodotracker.abuse.ch/list.txt")

    def test_merges_and_preserves_manual_rows(self, tmp_path, monkeypatch):
        from modules.threat_intel import update_feed

        csv_file = tmp_path / "threat_intel.csv"
        csv_file.write_text("ip,category,confidence\n1.2.3.4,Manual Entry,75\n", encoding="utf-8")
        self._mock_urlopen(monkeypatch, self.FEED_TEXT)

        merged = update_feed(str(csv_file), url="https://example.invalid/feed.txt")
        # 203.0.113.10 + 198.51.100.0/24 + 2001:db8::7 (bad line skipped)
        assert merged == 3

        ti = ThreatIntel(csv_path=str(csv_file))
        assert ti.check_ip("1.2.3.4")["category"] == "Manual Entry"  # manual row preserved
        assert ti.check_ip("203.0.113.10")["category"] == "Botnet C2"
        assert ti.check_ip("198.51.100.77") is not None  # CIDR range loaded
        assert ti.check_ip("2001:db8::7") is not None

        # A backup of the pre-update CSV is kept
        assert (tmp_path / "threat_intel.csv.bak").read_text(encoding="utf-8").startswith("ip,category,confidence")

    def test_empty_feed_leaves_csv_untouched(self, tmp_path, monkeypatch):
        from modules.threat_intel import update_feed

        csv_file = tmp_path / "threat_intel.csv"
        original = "ip,category,confidence\n1.2.3.4,Manual Entry,75\n"
        csv_file.write_text(original, encoding="utf-8")
        self._mock_urlopen(monkeypatch, "# only comments\n\n")

        assert update_feed(str(csv_file), url="https://example.invalid/feed.txt") == 0
        assert csv_file.read_text(encoding="utf-8") == original

    def test_refetch_updates_existing_feed_row(self, tmp_path, monkeypatch):
        from modules.threat_intel import update_feed

        csv_file = tmp_path / "threat_intel.csv"
        self._mock_urlopen(monkeypatch, "203.0.113.10\n")
        update_feed(str(csv_file), url="https://example.invalid/feed.txt")
        update_feed(str(csv_file), url="https://example.invalid/feed.txt", confidence=95)

        ti = ThreatIntel(csv_path=str(csv_file))
        assert ti.check_ip("203.0.113.10")["confidence"] == 95
        assert ti.get_threat_count() == 1  # no duplicate rows


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
