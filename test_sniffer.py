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
import time


async def test():
    print("=" * 60)
    print("🔌 PacketSniffer Test - Windows Compatibility Check")
    print("=" * 60)
    print()
    
    try:
        # Check if scapy is available
        try:
            from scapy.all import get_if_list
            print("✅ Scapy library is installed")
        except ImportError:
            print("❌ ERROR: Scapy library is not installed")
            print("   Run: pip install scapy")
            return
        
        # Sniffer oluştur
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
            print(f"   [{i+1}/5] Packets captured so far: {current_count}", end='\r')
        
        print()  # New line after progress
        
        # İstatistikleri al
        print("\n📊 Gathering statistics...")
        stats = sniffer.get_traffic_stats()
        df = sniffer.get_recent_packets(count=10)
        
        print("\n🛑 Stopping packet capture...")
        sniffer.stop()
        
        # Results
        print("\n" + "=" * 60)
        print("✅ TEST BAŞARILI!")
        print("=" * 60)
        print(f"\n📦 Toplam Yakalanan Paket: {stats.get('total_packets', 0)}")
        print(f"📊 Buffer'daki Paket Sayısı: {stats.get('packets_in_buffer', 0)}")
        print(f"📊 DataFrame Satır Sayısı: {len(df)}")
        
        if stats.get('top_source_ips'):
            print(f"\n🔝 En çok trafik yaratan Source IP'ler:")
            for item in stats['top_source_ips'][:5]:
                print(f"   {item['ip']}: {item['count']} paket")
        
        if stats.get('top_protocols'):
            print(f"\n🔝 En çok kullanılan Protokoller:")
            for item in stats['top_protocols'][:5]:
                print(f"   {item['protocol']}: {item['count']} paket")
        
        if len(df) > 0:
            print(f"\n📋 Son {min(5, len(df))} paket örneği:")
            print(df.head().to_string(index=False))
        
        print("\n" + "=" * 60)
        print("✅ Sistem Dashboard entegrasyonuna hazır!")
        print("=" * 60)
        
    except PermissionError as e:
        print("\n" + "=" * 60)
        print("❌ HATA: Yönetici izni gerekli!")
        print("=" * 60)
        print(f"\nHata mesajı: {e}")
        print("\n💡 Çözüm:")
        print("   1. Terminal/PowerShell'i kapat")
        print("   2. Terminal'i sağ tıkla -> 'Yönetici Olarak Çalıştır'")
        print("   3. Tekrar test_sniffer.py'yi çalıştır")
        print("\n   VEYA")
        print("   - CMD'yi Yönetici olarak aç")
        print("   - cd C:\\Path\\To\\LocalShield")
        print("   - python test_sniffer.py")
        
    except Exception as e:
        print("\n" + "=" * 60)
        print("❌ HATA:")
        print("=" * 60)
        print(f"\n{type(e).__name__}: {e}")
        print("\n💡 Olası çözümler:")
        print("   1. Npcap kurulu mu? https://npcap.com/")
        print("   2. Terminal Yönetici olarak çalışıyor mu?")
        print("   3. Scapy kurulu mu? (pip install scapy)")
        print("   4. Aktif bir ağ bağlantısı var mı?")
        import traceback
        print("\n📋 Detaylı hata:")
        traceback.print_exc()


if __name__ == "__main__":
    print("\n")
    asyncio.run(test())
    print("\n")

