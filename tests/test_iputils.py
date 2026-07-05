"""
Unit tests for modules/iputils — the shared, family-neutral IP helpers.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import iputils


class TestNormalize:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("1.2.3.4", "1.2.3.4"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("2001:DB8::1", "2001:db8::1"),
            ("2001:db8::", "2001:db8::"),  # trailing '::' is part of the address
            ("1.2.3.4.", "1.2.3.4"),  # sentence-ending dot is stripped
            ("::1", "::1"),
            ("not-an-ip", None),
            ("", None),
            ("999.1.1.1", None),
        ],
    )
    def test_normalize(self, raw, expected):
        assert iputils.normalize_ip(raw) == expected


class TestExtractAll:
    def test_mixed_families(self):
        text = "Traffic between 8.8.8.8 and 2607:f8b0::1 at 12:30:45"
        assert iputils.extract_all_ips(text) == ["8.8.8.8", "2607:f8b0::1"]

    def test_bare_numbers_are_not_addresses(self):
        assert iputils.extract_all_ips("port 443 count 2026") == []

    def test_deduplicates_preserving_order(self):
        text = "from 1.2.3.4 to 5.6.7.8 and back to 1.2.3.4"
        assert iputils.extract_all_ips(text) == ["1.2.3.4", "5.6.7.8"]

    def test_empty_text(self):
        assert iputils.extract_all_ips("") == []


class TestExtractSource:
    def test_windows_pam_and_ssh_fields(self):
        text = (
            "Source Network Address: 203.0.113.7\n"
            "pam_unix: rhost=198.51.100.9\n"
            "Failed password for root from 2001:db8::5 port 22\n"
        )
        assert iputils.extract_source_ips(text) == ["203.0.113.7", "198.51.100.9", "2001:db8::5"]

    def test_ip_outside_source_fields_is_ignored(self):
        text = "Account Name: 8.8.8.8\nWorkstation Name: EVIL-1.2.3.4"
        assert iputils.extract_source_ips(text) == []

    def test_from_followed_by_word_is_ignored(self):
        # 'a' and 'face' are hex-shaped but not addresses
        assert iputils.extract_source_ips("received from a remote host, from face value") == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
