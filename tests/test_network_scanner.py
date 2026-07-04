"""
Unit tests for the network_scanner module.
Covers port risk classification, summary counts and demo-mode scanning.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import network_scanner
from modules.network_scanner import get_port_info, get_port_summary, scan_open_ports


class TestPortInfo:
    def test_high_risk_port(self):
        info = get_port_info(3389)  # RDP
        assert info["risk"] == "High"
        assert info["name"] == "RDP"

    def test_known_safe_port(self):
        info = get_port_info(443)  # HTTPS
        assert info["risk"] == "Low"
        assert info["name"] == "HTTPS"

    def test_unknown_port_defaults_to_low(self):
        info = get_port_info(64999)
        assert info["risk"] == "Low"
        assert "port" in info and info["port"] == 64999


class TestPortSummary:
    def test_counts(self):
        ports = [
            {"Port": 3389, "Risk": "High"},
            {"Port": 445, "Risk": "High"},
            {"Port": 443, "Risk": "Low"},
        ]
        summary = get_port_summary(ports)
        assert summary["Total"] == 3
        assert summary["High Risk"] == 2
        assert summary["Low Risk"] == 1

    def test_empty(self):
        summary = get_port_summary([])
        assert summary == {"Total": 0, "High Risk": 0, "Low Risk": 0}


class TestScanOpenPorts:
    def test_mock_mode_returns_demo_data(self):
        ports = scan_open_ports(mock=True)
        assert isinstance(ports, list)
        assert len(ports) > 0
        # Every demo entry has the expected schema
        for p in ports:
            assert {"Port", "Risk", "Service"}.issubset(p.keys())

    def test_real_scan_returns_list(self, monkeypatch):
        # Force a non-demo path with no connections so it stays fast and deterministic
        monkeypatch.setattr(network_scanner.config, "DEMO_MODE", False)
        monkeypatch.setattr(network_scanner.psutil, "net_connections", lambda kind="inet": [])
        ports = scan_open_ports(mock=False)
        assert ports == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
