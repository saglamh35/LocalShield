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

    def test_reload(self, feed, tmp_path):
        # Overwrite the feed with a single new malicious IP and reload
        (tmp_path / "threat_intel.csv").write_text(
            "ip,category,confidence\n10.20.30.40,Malware,80\n", encoding="utf-8"
        )
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
        assert cidr_feed.check_ip("10.10.0.255") is not None   # inside /24
        assert cidr_feed.check_ip("10.10.1.0") is None          # just outside /24

    def test_garbage_input_is_safe(self, cidr_feed):
        assert cidr_feed.check_ip("not-an-ip") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
