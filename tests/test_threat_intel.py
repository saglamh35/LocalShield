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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
