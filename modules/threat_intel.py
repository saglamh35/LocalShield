"""
Threat Intelligence Module - Malicious IP lookup
Checks IPs against a list of known attacker addresses and reports their risk.
Production-Ready: CSV-based threat intelligence feed (IPv4 and IPv6).
"""

import csv
import ipaddress
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from modules import iputils

# Logging configuration
logger = logging.getLogger(__name__)

# A loaded network entry may be either family
_AnyNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class ThreatIntel:
    """
    Manages the threat intelligence database and performs IP lookups.

    The CSV 'ip' column accepts either a single address (IPv4 or IPv6, e.g.
    1.2.3.4 or 2001:db8::1) or a CIDR range (e.g. 185.220.0.0/16,
    2001:db8::/32). Single addresses are matched in O(1); ranges are checked
    against the queried address. Addresses are canonicalised on load and on
    lookup so equivalent IPv6 spellings always match.
    """

    def __init__(self, csv_path: str = "data/threat_intel.csv"):
        """
        Initialize ThreatIntel and load malicious IPs from the CSV file.

        Args:
            csv_path: Path to the threat intelligence CSV file
        """
        self.csv_path = Path(csv_path)
        # Dictionary mapping IP -> (category, confidence)
        self.threat_db: Dict[str, Tuple[str, int]] = {}
        # Set of exact IPs for fast lookups
        self.threat_ips: set[str] = set()
        # CIDR ranges: (network, entry_string, category, confidence)
        self.threat_networks: List[Tuple[_AnyNetwork, str, str, int]] = []

        self._load_threat_intel()

    def _load_threat_intel(self) -> None:
        """
        Load threat intelligence data from the CSV file.
        """
        try:
            if not self.csv_path.exists():
                logger.warning(f"⚠️  Threat intelligence file not found: {self.csv_path}")
                logger.warning("   Threat intelligence checks will be disabled.")
                return

            with open(self.csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                count = 0

                for row in reader:
                    ip = row.get("ip", "").strip()
                    category = row.get("category", "Unknown").strip()
                    confidence = int(row.get("confidence", 0))

                    # Skip benign IPs (confidence 0 or category "Benign")
                    if category.lower() == "benign" or confidence == 0:
                        continue

                    if not ip:
                        continue

                    if "/" in ip:
                        # CIDR range entry (either family)
                        try:
                            network = ipaddress.ip_network(ip, strict=False)
                            self.threat_networks.append((network, ip, category, confidence))
                            count += 1
                        except (ValueError, ipaddress.AddressValueError):
                            logger.warning(f"⚠️  Skipping invalid CIDR in threat feed: {ip}")
                    else:
                        # Single address entry — store the canonical form so
                        # any spelling of the same IPv6 address matches
                        key = iputils.normalize_ip(ip) or ip
                        self.threat_db[key] = (category, confidence)
                        self.threat_ips.add(key)
                        count += 1

                logger.info(
                    f"✅ Threat Intelligence loaded: {count} entries "
                    f"({len(self.threat_ips)} IPs, {len(self.threat_networks)} ranges)"
                )

        except Exception as e:
            logger.error(f"❌ Error loading threat intelligence: {e}", exc_info=True)
            logger.warning("   Threat intelligence checks will be disabled.")

    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Check whether an IP address is on the malicious list.

        Args:
            ip_address: IP address to check

        Returns:
            Dict[str, Any]: {'ip', 'category', 'confidence'} if malicious, otherwise None
        """
        if not ip_address or not ip_address.strip():
            return None

        # Canonicalise so e.g. '2001:DB8::1' matches a '2001:db8::1' entry
        ip_clean = iputils.normalize_ip(ip_address) or ip_address.strip()

        # 1. Exact IP match (O(1))
        if ip_clean in self.threat_ips:
            category, confidence = self.threat_db[ip_clean]
            logger.warning(f"🚨 THREAT INTEL MATCH: {ip_clean} - Category: {category}, Confidence: {confidence}%")
            return {"ip": ip_clean, "category": category, "confidence": confidence}

        # 2. CIDR range match
        if self.threat_networks:
            try:
                addr = ipaddress.ip_address(ip_clean)
            except (ValueError, ipaddress.AddressValueError):
                return None

            for network, entry, category, confidence in self.threat_networks:
                if addr.version == network.version and addr in network:
                    logger.warning(
                        f"🚨 THREAT INTEL MATCH: {ip_clean} in {entry} - "
                        f"Category: {category}, Confidence: {confidence}%"
                    )
                    return {"ip": ip_clean, "category": category, "confidence": confidence, "matched_range": entry}

        return None

    def reload(self) -> None:
        """
        Reload the threat intelligence database
        (useful when the CSV file has been updated).
        """
        self.threat_db.clear()
        self.threat_ips.clear()
        self.threat_networks.clear()
        self._load_threat_intel()

    def get_threat_count(self) -> int:
        """
        Return the number of loaded threat entries (single IPs + CIDR ranges).

        Returns:
            int: Number of malicious entries
        """
        return len(self.threat_ips) + len(self.threat_networks)
