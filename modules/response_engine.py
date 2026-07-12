"""
Response Engine Module - Active Response
Blocks IP addresses (IPv4 and IPv6) via the Windows Firewall.
Production-Ready: with error handling and logging.
"""

import ipaddress
import logging
import subprocess
from typing import Iterable, List, Optional

from modules import iputils

try:
    import config

    _DEFAULT_ALLOWLIST = list(getattr(config, "SAFE_IPS", []))
    _DEFAULT_DRY_RUN = bool(getattr(config, "RESPONSE_DRY_RUN", False))
except Exception:  # config import should never fail, but stay defensive
    _DEFAULT_ALLOWLIST = []
    _DEFAULT_DRY_RUN = False

# Logging configuration
logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Manages IP-blocking operations through the Windows Firewall.
    """

    def __init__(self, allowlist: Optional[Iterable[str]] = None, dry_run: Optional[bool] = None):
        """
        Initialize the FirewallManager.

        Args:
            allowlist: Critical IPs that must never be blocked
                       (defaults to config.SAFE_IPS)
            dry_run: When True, all safety checks and audit records run but
                     no firewall command is executed (defaults to
                     config.RESPONSE_DRY_RUN)
        """
        self.blocked_ips: set[str] = set()  # Track blocked IPs
        # Critical IPs that must never be blocked (e.g. DNS, gateway).
        # Normalized so '2001:DB8::1' in config matches '2001:db8::1' in a log.
        source = allowlist if allowlist is not None else _DEFAULT_ALLOWLIST
        self.allowlist: set[str] = {iputils.normalize_ip(ip) or str(ip) for ip in source}
        self.dry_run: bool = _DEFAULT_DRY_RUN if dry_run is None else dry_run

    def is_valid_ipv4(self, ip_str: str) -> bool:
        """
        Check whether the given string is a valid IPv4 address.
        (Kept for backward compatibility; prefer is_valid_ip.)
        """
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False

    def is_valid_ip(self, ip_str: str) -> bool:
        """Check whether the string is a valid IPv4 or IPv6 address."""
        return iputils.is_valid_ip(ip_str)

    def is_private_ip(self, ip_str: str) -> bool:
        """
        Check whether the IP address is private/local (either family):
        RFC1918 / ULA ranges, loopback and link-local.

        Args:
            ip_str: IP address to check

        Returns:
            bool: True if it is a private IP (False for invalid input)
        """
        return iputils.is_private_ip(ip_str)

    def extract_ips_from_text(self, text: str) -> List[str]:
        """
        Extract IPv4/IPv6 addresses found anywhere in a block of text.

        Positions are not trusted — use extract_source_ips_from_text to pick
        blocking targets; this scan is for read-only lookups (threat intel).

        Args:
            text: Text to search for IP addresses

        Returns:
            List[str]: Normalized, de-duplicated valid IPs in order found
        """
        return iputils.extract_all_ips(text)

    def extract_source_ips_from_text(self, text: str) -> List[str]:
        """
        Extract only IPs that appear in structured SOURCE-ADDRESS fields
        (Windows 'Source Network Address:', PAM 'rhost=', SSH 'from <ip>').

        Use this — not extract_ips_from_text — to pick blocking targets.
        A generic scan would also pick up IPs embedded in attacker-controlled
        strings (usernames, workstation names), letting an attacker trick the
        auto-response into blocking arbitrary third-party addresses.

        Args:
            text: Log text to search

        Returns:
            List[str]: Ordered, de-duplicated list of valid source IPs
        """
        return iputils.extract_source_ips(text)

    @staticmethod
    def _rule_name(ip_address: str) -> str:
        """Firewall rule name for an IP ('.' and ':' are not name-safe)."""
        return f"LocalShield_Block_{ip_address.replace('.', '_').replace(':', '-')}"

    def block_ip(self, ip_address: str) -> bool:
        """
        Block an IP address in the Windows Firewall.

        Args:
            ip_address: IP address to block

        Returns:
            bool: True if the block succeeded
        """
        # IP validation + normalization (IPv6 addresses have many spellings;
        # the canonical form keeps dedup/allowlist comparisons reliable)
        normalized = iputils.normalize_ip(ip_address)
        if normalized is None:
            logger.warning(f"❌ Invalid IP address: {ip_address}")
            return False
        ip_address = normalized

        # Private IP check
        if self.is_private_ip(ip_address):
            logger.warning(f"⚠️  Private IP address not blocked (safety): {ip_address}")
            return False

        # Allowlist check - never block critical infrastructure (DNS, gateway, ...)
        if ip_address in self.allowlist:
            logger.warning(f"⚠️  Allowlisted IP not blocked (safety): {ip_address}")
            return False

        # Check whether it is already blocked
        if ip_address in self.blocked_ips:
            logger.info(f"ℹ️  IP address already blocked: {ip_address}")
            return True

        # Build the Windows Firewall rule
        rule_name = self._rule_name(ip_address)

        # Dry-run: every safety check above still applies, but no firewall
        # command is executed — the would-be action is only logged/audited.
        if self.dry_run:
            self.blocked_ips.add(ip_address)
            logger.warning(f"🧪 [DRY-RUN] Would block IP address: {ip_address} (rule: {rule_name})")
            return True

        try:
            # netsh advfirewall firewall add rule command
            # dir=in : inbound (incoming) traffic
            # action=block : drop the traffic
            # remoteip : the IP address to block
            command = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address}",
                "enable=yes",
            ]

            # Run the command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,  # Do not raise on non-zero exit
            )

            # Success check
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                logger.warning(f"🛡️  IP address blocked successfully: {ip_address} (rule: {rule_name})")
                return True
            else:
                # Inspect the error output
                error_output = result.stderr.lower()

                # If the rule already exists, that is not an error.
                # "zaten var" is netsh's message on Turkish-locale Windows.
                if "already exists" in error_output or "zaten var" in error_output:
                    self.blocked_ips.add(ip_address)
                    logger.info(f"ℹ️  Firewall rule already exists: {rule_name}")
                    return True
                else:
                    logger.error(f"❌ IP block error ({ip_address}): {result.stderr}")
                    return False

        except subprocess.TimeoutExpired:
            logger.error(f"❌ IP block timed out: {ip_address}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected IP block error ({ip_address}): {e}", exc_info=True)
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """
        Remove the block on an IP address in the Windows Firewall.

        Args:
            ip_address: IP address to unblock

        Returns:
            bool: True if the operation succeeded
        """
        ip_address = iputils.normalize_ip(ip_address) or ip_address
        rule_name = self._rule_name(ip_address)

        # Dry-run: mirror block_ip — no firewall command is executed.
        if self.dry_run:
            self.blocked_ips.discard(ip_address)
            logger.info(f"🧪 [DRY-RUN] Would unblock IP address: {ip_address}")
            return True

        try:
            command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]

            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)

            if result.returncode == 0:
                self.blocked_ips.discard(ip_address)
                logger.info(f"✅ IP address unblocked: {ip_address}")
                return True
            else:
                logger.warning(f"⚠️  Could not remove IP block ({ip_address}): {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"❌ IP unblock error ({ip_address}): {e}", exc_info=True)
            return False
