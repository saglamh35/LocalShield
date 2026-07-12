"""
FirewallManager Test Script
Manually tests the Windows Firewall IP blocking module.

Usage:
    python test_firewall.py [ip_address]

The default test IP (9.9.9.9, Quad9 DNS) is public and NOT on the
config.SAFE_IPS allowlist — allowlisted IPs such as 1.1.1.1 or 8.8.8.8
are always refused by FirewallManager, so testing with them would fail
by design. Remember to delete the rule after the test (instructions are
printed at the end).
"""

import argparse
import logging
import sys

import config
from modules.response_engine import FirewallManager

# Logging configuration (console output)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

DEFAULT_TEST_IP = "9.9.9.9"  # Quad9 DNS: public, routable, not allowlisted


def main() -> None:
    """FirewallManager test function"""
    parser = argparse.ArgumentParser(description="Manually test FirewallManager IP blocking.")
    parser.add_argument(
        "ip",
        nargs="?",
        default=DEFAULT_TEST_IP,
        help=f"Public IP address to block for the test (default: {DEFAULT_TEST_IP})",
    )
    args = parser.parse_args()
    test_ip = args.ip

    print("=" * 60)
    print("🛡️  LocalShield - FirewallManager Test")
    print("=" * 60)
    print()

    # Create a FirewallManager instance
    firewall_manager = FirewallManager()

    print(f"📋 Test IP address: {test_ip}")
    print()

    # Guard: allowlisted IPs are always refused by design
    if test_ip in config.SAFE_IPS:
        print(f"   ❌ {test_ip} is on the SAFE_IPS allowlist and will never be blocked.")
        print("      Pick a public IP that is not allowlisted (e.g. the default).")
        return

    # IP validation test
    print("🔍 Checking IP validity...")
    if firewall_manager.is_valid_ipv4(test_ip):
        print(f"   ✅ IP address is valid: {test_ip}")
    else:
        print(f"   ❌ IP address is invalid: {test_ip}")
        return

    # Private IP check
    if firewall_manager.is_private_ip(test_ip):
        print("   ⚠️  This is a private IP address (will not be blocked)")
        return
    else:
        print("   ✅ This is a public IP address (can be blocked)")

    print()
    print("🚀 Starting IP block operation in the Windows Firewall...")
    print("   ⚠️  Note: this operation may require administrator privileges.")
    print()

    rule_name = f"LocalShield_Block_{test_ip.replace('.', '_')}"

    # Block the IP
    try:
        result = firewall_manager.block_ip(test_ip)

        if result:
            print("=" * 60)
            print("✅ SUCCESS: IP address blocked in the Windows Firewall!")
            print("=" * 60)
            print()
            print(f"📌 Blocked IP: {test_ip}")
            print(f"📌 Firewall rule name: {rule_name}")
            print()
        else:
            print("=" * 60)
            print("❌ ERROR: IP address could not be blocked!")
            print("=" * 60)
            print()
            print("💡 Possible reasons:")
            print("   - Administrator privileges may be missing")
            print("   - The Windows Firewall service may not be running")
            print("   - The rule may already exist")
            print()

    except Exception as e:
        print("=" * 60)
        print("❌ UNEXPECTED ERROR!")
        print("=" * 60)
        print(f"Error message: {e}")
        print()
        import traceback

        traceback.print_exc()
        return

    # Instructions for verifying in the Windows Firewall
    print("=" * 60)
    print("🔍 Windows Firewall Verification")
    print("=" * 60)
    print()
    print("To verify that the block was applied:")
    print()
    print("1️⃣  Open PowerShell or CMD AS ADMINISTRATOR")
    print()
    print("2️⃣  Run this command:")
    print(f"   netsh advfirewall firewall show rule name={rule_name}")
    print()
    print("3️⃣  Alternatively, check from the Windows Firewall GUI:")
    print("   - Windows Firewall > Advanced Settings")
    print("   - Inbound Rules > look for rules starting with 'LocalShield_Block_'")
    print()
    print("4️⃣  To delete the rule (after the test):")
    print(f"   netsh advfirewall firewall delete rule name={rule_name}")
    print()
    print("=" * 60)
    print("✅ Test completed!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test stopped by the user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Unexpected error during the test: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
