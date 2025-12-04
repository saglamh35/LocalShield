"""
FirewallManager Test Script
Windows Firewall IP engelleme modülünü test eder
"""
import sys
import logging
from modules.response_engine import FirewallManager

# Logging yapılandırması (konsola çıktı)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def main():
    """FirewallManager test fonksiyonu"""
    print("=" * 60)
    print("🛡️  LocalShield - FirewallManager Test")
    print("=" * 60)
    print()
    
    # FirewallManager örneği oluştur
    firewall_manager = FirewallManager()
    
    # Test IP adresi (Cloudflare DNS - Public IP)
    test_ip = "1.1.1.1"
    
    print(f"📋 Test IP Adresi: {test_ip}")
    print(f"ℹ️  Bu IP adresi Cloudflare DNS sunucusudur (Public IP - test için uygundur)")
    print()
    
    # IP validasyonu testi
    print("🔍 IP Validasyonu Kontrolü...")
    if firewall_manager.is_valid_ipv4(test_ip):
        print(f"   ✅ IP adresi geçerli: {test_ip}")
    else:
        print(f"   ❌ IP adresi geçersiz: {test_ip}")
        return
    
    # Private IP kontrolü
    if firewall_manager.is_private_ip(test_ip):
        print(f"   ⚠️  Bu bir private IP adresi (engellenmeyecek)")
        return
    else:
        print(f"   ✅ Bu bir public IP adresi (engellenebilir)")
    
    print()
    print("🚀 Windows Firewall'da IP engelleme işlemi başlatılıyor...")
    print("   ⚠️  Not: Bu işlem yönetici yetkileri gerektirebilir.")
    print()
    
    # IP'yi engelle
    try:
        result = firewall_manager.block_ip(test_ip)
        
        if result:
            print("=" * 60)
            print("✅ BAŞARILI: IP adresi Windows Firewall'da engellendi!")
            print("=" * 60)
            print()
            print(f"📌 Engellenen IP: {test_ip}")
            print(f"📌 Firewall Kural Adı: LocalShield_Block_{test_ip.replace('.', '_')}")
            print()
        else:
            print("=" * 60)
            print("❌ HATA: IP adresi engellenemedi!")
            print("=" * 60)
            print()
            print("💡 Olası nedenler:")
            print("   - Yönetici yetkileri eksik olabilir")
            print("   - Windows Firewall servisi çalışmıyor olabilir")
            print("   - Kural zaten mevcut olabilir")
            print()
    
    except Exception as e:
        print("=" * 60)
        print("❌ BEKLENMEYEN HATA!")
        print("=" * 60)
        print(f"Hata mesajı: {e}")
        print()
        import traceback
        traceback.print_exc()
        return
    
    # Windows Firewall kontrolü için talimatlar
    print("=" * 60)
    print("🔍 Windows Firewall Kontrolü")
    print("=" * 60)
    print()
    print("Engellemenin başarılı olduğunu kontrol etmek için:")
    print()
    print("1️⃣  PowerShell veya CMD'yi YÖNETİCİ OLARAK açın")
    print()
    print("2️⃣  Şu komutu çalıştırın:")
    print(f"   netsh advfirewall firewall show rule name=LocalShield_Block_{test_ip.replace('.', '_')}")
    print()
    print("3️⃣  Alternatif olarak, Windows Firewall GUI'den kontrol edin:")
    print("   - Windows Güvenlik Duvarı > Gelişmiş Ayarlar")
    print("   - Gelen Kuralları > 'LocalShield_Block_' ile başlayan kuralları arayın")
    print()
    print("4️⃣  Kuralı silmek için (test sonrası):")
    print(f"   netsh advfirewall firewall delete rule name=LocalShield_Block_{test_ip.replace('.', '_')}")
    print()
    print("=" * 60)
    print("✅ Test tamamlandı!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test kullanıcı tarafından durduruldu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Test sırasında beklenmeyen hata: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

