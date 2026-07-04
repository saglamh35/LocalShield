"""
Threat Intelligence Module - Malicious IP lookup
Checks IPs against a list of known attacker addresses and reports their risk.
Production-Ready: CSV-based threat intelligence feed.
"""

import csv
import ipaddress
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Logging configuration
logger = logging.getLogger(__name__)


class ThreatIntel:
    """
    Manages the threat intelligence database and performs IP lookups.

    The CSV 'ip' column accepts either a single address (e.g. 1.2.3.4) or a
    CIDR range (e.g. 185.220.0.0/16). Single addresses are matched in O(1);
    ranges are checked against the queried address.
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
        self.threat_networks: List[Tuple[ipaddress.IPv4Network, str, str, int]] = []

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
                        # CIDR range entry
                        try:
                            network = ipaddress.IPv4Network(ip, strict=False)
                            self.threat_networks.append((network, ip, category, confidence))
                            count += 1
                        except (ValueError, ipaddress.AddressValueError):
                            logger.warning(f"⚠️  Skipping invalid CIDR in threat feed: {ip}")
                    else:
                        # Single address entry
                        self.threat_db[ip] = (category, confidence)
                        self.threat_ips.add(ip)
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

        ip_clean = ip_address.strip()

        # 1. Exact IP match (O(1))
        if ip_clean in self.threat_ips:
            category, confidence = self.threat_db[ip_clean]
            logger.warning(f"🚨 THREAT INTEL MATCH: {ip_clean} - Category: {category}, Confidence: {confidence}%")
            return {"ip": ip_clean, "category": category, "confidence": confidence}

        # 2. CIDR range match
        if self.threat_networks:
            try:
                addr = ipaddress.IPv4Address(ip_clean)
            except (ValueError, ipaddress.AddressValueError):
                return None

            for network, entry, category, confidence in self.threat_networks:
                if addr in network:
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
