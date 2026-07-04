"""
Response Engine Module - Active Response
Blocks IP addresses via the Windows Firewall.
Production-Ready: with error handling and logging.
"""
import ipaddress
import logging
import re
import subprocess
from typing import Iterable, List, Optional

try:
    import config
    _DEFAULT_ALLOWLIST = list(getattr(config, "SAFE_IPS", []))
except Exception:  # config import should never fail, but stay defensive
    _DEFAULT_ALLOWLIST = []

# Logging configuration
logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Manages IP-blocking operations through the Windows Firewall.
    """

    def __init__(self, allowlist: Optional[Iterable[str]] = None):
        """
        Initialize the FirewallManager.

        Args:
            allowlist: Critical IPs that must never be blocked
                       (defaults to config.SAFE_IPS)
        """
        self.blocked_ips: set[str] = set()  # Track blocked IPs
        # Critical IPs that must never be blocked (e.g. DNS, gateway)
        self.allowlist: set[str] = set(allowlist if allowlist is not None else _DEFAULT_ALLOWLIST)

    def is_valid_ipv4(self, ip_str: str) -> bool:
        """
        Check whether the given string is a valid IPv4 address.

        Args:
            ip_str: IP address string to check

        Returns:
            bool: True if it is a valid IPv4 address
        """
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False

    def is_private_ip(self, ip_str: str) -> bool:
        """
        Check whether the IP address is private/local.

        Private IP ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 127.0.0.0/8 (Loopback)
        - 169.254.0.0/16 (Link-local)

        Args:
            ip_str: IP address to check

        Returns:
            bool: True if it is a private IP
        """
        try:
            ip = ipaddress.IPv4Address(ip_str)
            # Use the ipaddress library's built-in properties:
            # is_private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            # is_loopback: 127.0.0.0/8
            # is_link_local: 169.254.0.0/16
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except (ValueError, ipaddress.AddressValueError):
            # Return False for an invalid IP address
            return False

    def extract_ips_from_text(self, text: str) -> List[str]:
        """
        Extract IPv4 addresses from a block of text.

        Args:
            text: Text to search for IP addresses

        Returns:
            List[str]: List of valid IP addresses found
        """
        # IPv4 regex pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, text)

        # Keep only valid IPs
        valid_ips = []
        for match in matches:
            if self.is_valid_ipv4(match):
                valid_ips.append(match)

        return valid_ips

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
        patterns = [
            r'Source Network Address:\s*(\d{1,3}(?:\.\d{1,3}){3})',
            r'rhost=(\d{1,3}(?:\.\d{1,3}){3})',
            r'\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})',
        ]

        found: List[str] = []
        for pattern in patterns:
            for match in re.findall(pattern, text, re.IGNORECASE):
                if self.is_valid_ipv4(match) and match not in found:
                    found.append(match)

        return found

    def block_ip(self, ip_address: str) -> bool:
        """
        Block an IP address in the Windows Firewall.

        Args:
            ip_address: IP address to block

        Returns:
            bool: True if the block succeeded
        """
        # IP validation
        if not self.is_valid_ipv4(ip_address):
            logger.warning(f"❌ Invalid IP address: {ip_address}")
            return False

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
        rule_name = f"LocalShield_Block_{ip_address.replace('.', '_')}"

        try:
            # netsh advfirewall firewall add rule command
            # dir=in : inbound (incoming) traffic
            # action=block : drop the traffic
            # remoteip : the IP address to block
            command = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                'enable=yes'
            ]

            # Run the command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False  # Do not raise on non-zero exit
            )

            # Success check
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                logger.warning(f"🛡️  IP address blocked successfully: {ip_address} (rule: {rule_name})")
                return True
            else:
                # Inspect the error output
                error_output = result.stderr.lower()

                # If the rule already exists, that is not an error
                if 'already exists' in error_output or 'zaten var' in error_output:
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
        rule_name = f"LocalShield_Block_{ip_address.replace('.', '_')}"

        try:
            command = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )

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
