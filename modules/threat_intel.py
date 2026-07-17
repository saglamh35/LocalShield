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
                    # One malformed row must not abort the rest of the feed.
                    try:
                        confidence = int(row.get("confidence", 0) or 0)
                    except (TypeError, ValueError):
                        logger.warning(f"⚠️  Skipping threat feed row with invalid confidence: {row}")
                        continue

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


# --- Opt-in feed updater -----------------------------------------------------
#
# LocalShield is offline-first: nothing below runs automatically. Operators who
# WANT an up-to-date blocklist run `python -m modules.threat_intel --update`,
# which downloads a public feed and merges it into the local CSV. The runtime
# lookup path above never touches the network.

# abuse.ch Feodo Tracker: actively-used botnet C2 addresses, plain text format
DEFAULT_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
DEFAULT_FEED_CATEGORY = "Botnet C2"
DEFAULT_FEED_CONFIDENCE = 90


def _parse_feed_text(text: str) -> List[str]:
    """
    Extract valid IP addresses / CIDR ranges from a plain-text feed.
    Lines starting with '#' are comments; anything that does not parse as an
    address or network is skipped (a hostile feed line must never propagate).
    """
    entries: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line:
            try:
                entries.append(str(ipaddress.ip_network(line, strict=False)))
            except ValueError:
                logger.debug(f"Skipping invalid feed CIDR: {line!r}")
            continue
        normalized = iputils.normalize_ip(line)
        if normalized:
            entries.append(normalized)
        else:
            logger.debug(f"Skipping invalid feed line: {line!r}")
    return entries


def update_feed(
    csv_path: str = "data/threat_intel.csv",
    url: str = DEFAULT_FEED_URL,
    category: str = DEFAULT_FEED_CATEGORY,
    confidence: int = DEFAULT_FEED_CONFIDENCE,
    timeout: int = 30,
) -> int:
    """
    Download a plain-text IP blocklist and merge it into the local CSV feed.

    Existing rows are preserved (manual entries are never lost); a downloaded
    IP that already exists updates that row's category/confidence. The CSV is
    written atomically and the previous version is kept as `<csv_path>.bak`.

    Returns:
        int: Number of feed entries merged in (new + refreshed)
    """
    import os
    import tempfile
    import urllib.request

    if not url.lower().startswith("https://"):
        raise ValueError(f"Feed URL must use https:// (got {url!r})")

    logger.info(f"Downloading threat feed: {url}")
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - operator-configured feed URL, one-off manual update  # nosec B310
        text = response.read().decode("utf-8", errors="replace")

    entries = _parse_feed_text(text)
    if not entries:
        logger.warning("Feed contained no valid entries — local CSV left untouched.")
        return 0

    # Load the existing CSV (manual + previous feed rows), keyed by IP
    path = Path(csv_path)
    rows: Dict[str, Dict[str, str]] = {}
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                if ip:
                    rows[ip] = {
                        "ip": ip,
                        "category": (row.get("category") or "Unknown").strip(),
                        "confidence": (row.get("confidence") or "0").strip(),
                    }

    for entry in entries:
        rows[entry] = {"ip": entry, "category": category, "confidence": str(confidence)}

    # Atomic write: tmp file in the same directory, then os.replace
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        with open(path, "rb") as src, open(f"{path}.bak", "wb") as dst:
            dst.write(src.read())

    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".csv.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "category", "confidence"])
            writer.writeheader()
            writer.writerows(rows.values())
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise

    logger.info(f"✅ Threat feed merged: {len(entries)} feed entries, {len(rows)} total rows in {path}")
    return len(entries)


def _main() -> int:
    """CLI entry point: python -m modules.threat_intel --update [--url ...] [--csv ...]"""
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="LocalShield threat-intel feed tools (opt-in; the runtime never fetches on its own)."
    )
    parser.add_argument("--update", action="store_true", help="Download the feed and merge it into the local CSV")
    parser.add_argument("--url", default=DEFAULT_FEED_URL, help=f"Feed URL (default: {DEFAULT_FEED_URL})")
    parser.add_argument("--csv", default="data/threat_intel.csv", help="Local CSV path to merge into")
    parser.add_argument("--category", default=DEFAULT_FEED_CATEGORY, help="Category label for feed entries")
    parser.add_argument(
        "--confidence", type=int, default=DEFAULT_FEED_CONFIDENCE, help="Confidence score for feed entries (1-100)"
    )
    args = parser.parse_args()

    if not args.update:
        parser.print_help()
        return 1

    try:
        merged = update_feed(args.csv, url=args.url, category=args.category, confidence=args.confidence)
    except Exception as e:
        logger.error(f"Feed update failed: {e}")
        return 1
    print(f"Merged {merged} feed entries into {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
