"""
Unit tests for packet parsing in packet_capture. Builds real (in-memory) Scapy
packets — no capture, no network. Skips cleanly if Scapy is unavailable.
"""

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import packet_capture

pytestmark = pytest.mark.skipif(not packet_capture.SCAPY_AVAILABLE, reason="scapy not available")


def _sniffer():
    # Skip __init__ (it probes network interfaces); we only need _parse_packet.
    return packet_capture.PacketSniffer.__new__(packet_capture.PacketSniffer)


class TestParsePacket:
    def test_tcp_packet(self):
        from scapy.layers.inet import IP, TCP

        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=443)
        info = _sniffer()._parse_packet(pkt, datetime.now())
        assert info["source_ip"] == "1.2.3.4"
        assert info["dest_ip"] == "5.6.7.8"
        assert info["protocol"] == "TCP"
        assert info["port"] == 443

    def test_udp_packet(self):
        from scapy.layers.inet import IP, UDP

        pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53)
        info = _sniffer()._parse_packet(pkt, datetime.now())
        assert info["protocol"] == "UDP"
        assert info["port"] == 53

    def test_icmp_packet(self):
        from scapy.layers.inet import ICMP, IP

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        info = _sniffer()._parse_packet(pkt, datetime.now())
        assert info["protocol"] == "ICMP"

    def test_length_and_timestamp_present(self):
        from scapy.layers.inet import IP, TCP

        ts = datetime.now()
        info = _sniffer()._parse_packet(IP(dst="1.1.1.1") / TCP(), ts)
        assert info["timestamp"] == ts
        assert info["length"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
