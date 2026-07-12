"""
Test script for PacketSniffer module
Tests if scapy and npcap work correctly on Windows
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.packet_capture import PacketSniffer


async def test():
    print("=" * 60)
    print("🔌 PacketSniffer Test - Windows Compatibility Check")
    print("=" * 60)
    print()

    try:
        # Check if scapy is available
        try:
            from scapy.all import get_if_list  # noqa: F401

            print("✅ Scapy library is installed")
        except ImportError:
            print("❌ ERROR: Scapy library is not installed")
            print("   Run: pip install scapy")
            return

        # Create the sniffer
        print("\n📡 Creating PacketSniffer instance...")
        sniffer = PacketSniffer(max_packets=100)

        if not sniffer.interface:
            print("❌ ERROR: No network interface detected")
            print("   Make sure you have an active network connection")
            return

        print(f"✅ Network interface detected: {sniffer.interface}")
        print(f"✅ Max packets buffer: {sniffer.max_packets}")

        print("\n🚀 Starting packet capture...")
        sniffer.start()

        print("⏳ Capturing traffic for 5 seconds...")
        print("   (Make some network activity: browse web, ping, etc.)")

        # Show progress
        for i in range(5):
            await asyncio.sleep(1)
            current_count = len(sniffer.packet_data)
            print(f"   [{i + 1}/5] Packets captured so far: {current_count}", end="\r")

        print()  # New line after progress

        # Gather statistics
        print("\n📊 Gathering statistics...")
        stats = sniffer.get_traffic_stats()
        df = sniffer.get_recent_packets(count=10)

        print("\n🛑 Stopping packet capture...")
        sniffer.stop()

        # Results
        print("\n" + "=" * 60)
        print("✅ TEST SUCCESSFUL!")
        print("=" * 60)
        print(f"\n📦 Total packets captured: {stats.get('total_packets', 0)}")
        print(f"📊 Packets in buffer: {stats.get('packets_in_buffer', 0)}")
        print(f"📊 DataFrame row count: {len(df)}")

        if stats.get("top_source_ips"):
            print("\n🔝 Source IPs generating the most traffic:")
            for item in stats["top_source_ips"][:5]:
                print(f"   {item['ip']}: {item['count']} packets")

        if stats.get("top_protocols"):
            print("\n🔝 Most used protocols:")
            for item in stats["top_protocols"][:5]:
                print(f"   {item['protocol']}: {item['count']} packets")

        if len(df) > 0:
            print(f"\n📋 Last {min(5, len(df))} packet sample:")
            print(df.head().to_string(index=False))

        print("\n" + "=" * 60)
        print("✅ System is ready for Dashboard integration!")
        print("=" * 60)

    except PermissionError as e:
        print("\n" + "=" * 60)
        print("❌ ERROR: Administrator privileges required!")
        print("=" * 60)
        print(f"\nError message: {e}")
        print("\n💡 Solution:")
        print("   1. Close the Terminal/PowerShell window")
        print("   2. Right-click the Terminal -> 'Run as Administrator'")
        print("   3. Run test_sniffer.py again")
        print("\n   OR")
        print("   - Open CMD as Administrator")
        print("   - cd C:\\Path\\To\\LocalShield")
        print("   - python test_sniffer.py")

    except Exception as e:
        print("\n" + "=" * 60)
        print("❌ ERROR:")
        print("=" * 60)
        print(f"\n{type(e).__name__}: {e}")
        print("\n💡 Possible solutions:")
        print("   1. Is Npcap installed? https://npcap.com/")
        print("   2. Is the terminal running as Administrator?")
        print("   3. Is Scapy installed? (pip install scapy)")
        print("   4. Is there an active network connection?")
        import traceback

        print("\n📋 Detailed error:")
        traceback.print_exc()


if __name__ == "__main__":
    print("\n")
    asyncio.run(test())
    print("\n")
