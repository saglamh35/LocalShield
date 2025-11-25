"""
Saldırı Simülasyonu - Demo Aracı
Veritabanına fake brute force logları enjekte eder (Event ID 4625)
Amaç: Log Watcher'ı beklemeden Dashboard'da MITRE T1110 etiketinin görünmesini test etmek
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from db_manager import init_db, insert_log
import config


def simulate_brute_force_attack(
    num_attempts: int = 5,
    time_window_seconds: int = 60,
    attacker_name: str = "ATTACKER",
    db_path: str = None
):
    """
    Fake brute force saldırısı simüle eder.
    
    Args:
        num_attempts: Kaç başarısız giriş denemesi simüle edilecek (varsayılan: 5)
        time_window_seconds: Bu denemeler kaç saniye içinde yapılacak (varsayılan: 60)
        attacker_name: Saldırgan kullanıcı adı (varsayılan: "ATTACKER")
        db_path: Veritabanı yolu (varsayılan: config.DB_PATH)
    """
    db_path = db_path or config.DB_PATH
    
    print("=" * 60)
    print("🛡️  LocalShield - Saldırı Simülasyonu")
    print("=" * 60)
    print(f"📊 Simüle edilecek deneme sayısı: {num_attempts}")
    print(f"⏰ Zaman penceresi: {time_window_seconds} saniye")
    print(f"👤 Saldırgan: {attacker_name}")
    print(f"💾 Veritabanı: {db_path}")
    print("=" * 60)
    print()
    
    # Veritabanını başlat
    try:
        conn = init_db(db_path)
        print("✅ Veritabanı bağlantısı başarılı")
    except Exception as e:
        print(f"❌ Veritabanı bağlantı hatası: {e}")
        return
    
    # Zaman aralığını hesapla
    base_time = datetime.now()
    time_interval = time_window_seconds / num_attempts if num_attempts > 1 else 0
    
    print(f"🚀 {num_attempts} adet fake log kaydı ekleniyor...")
    print()
    
    # Her deneme için log kaydı oluştur
    for i in range(num_attempts):
        # Zamanı hesapla (eşit aralıklarla dağıt)
        timestamp = base_time + timedelta(seconds=i * time_interval)
        
        # Event mesajı oluştur (gerçekçi Windows Event 4625 formatı)
        message = f"""An account failed to log on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       {attacker_name}
    Account Domain:      WORKGROUP
    Logon ID:           0x00000000

Logon Type:            3

Account For Which Logon Failed:
    Security ID:        NULL SID
    Account Name:       {attacker_name}
    Account Domain:     WORKGROUP

Failure Information:
    Failure Reason:     Unknown user name or bad password.
    Status:             0xC000006D
    Sub Status:         0xC000006A

Process Information:
    Caller Process ID:  0x00000000
    Caller Process Name: -

Network Information:
    Workstation Name:   {attacker_name}-PC
    Source Network Address: 192.168.1.100
    Source Port:       445

Detailed Authentication Information:
    Logon Process:      NtLmSsp
    Authentication Package: NTLM
    Transited Services: -
    Package Name (NTLM only): -
    Key Length:         0

This event is generated when a logon request fails. It is generated on the computer where access was attempted.

The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).

The Process Information fields indicate which account and process attempted the logon.

The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The authentication information fields provide detailed information about this specific logon request.
- Transited services indicate which intermediate services have participated in this logon request.
- Package name indicates which sub-protocol was used among the NTLM protocols.
- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."""
        
        # AI analizi (kural motoru tetiklenirse bu override edilecek)
        ai_analysis = f"Başarısız logon denemesi tespit edildi. Kullanıcı: {attacker_name}"
        
        # Risk seviyesi (kural motoru tetiklenirse "Yüksek" olacak)
        risk_score = "Orta"  # Tek tek denemeler için orta, 5+ denemede Yüksek olacak
        
        # MITRE tekniği (kural motoru tetiklenirse "T1110" olacak)
        mitre_technique = None  # Kural motoru tetiklenene kadar None
        
        try:
            log_id = insert_log(
                timestamp=timestamp,
                event_id="4625",
                message=message[:500],  # İlk 500 karakter
                ai_analysis=ai_analysis,
                risk_score=risk_score,
                mitre_technique=mitre_technique,
                conn=conn
            )
            
            print(f"  ✅ Log #{i+1} eklendi (ID: {log_id}, Zaman: {timestamp.strftime('%H:%M:%S')})")
            
        except Exception as e:
            print(f"  ❌ Log #{i+1} eklenirken hata: {e}")
    
    # Bağlantıyı kapat
    conn.close()
    
    print()
    print("=" * 60)
    print("✅ Simülasyon tamamlandı!")
    print()
    print("💡 Şimdi Dashboard'ı açın ve şunları kontrol edin:")
    print("   - Event ID 4625 logları görünüyor mu?")
    print("   - 5+ deneme varsa MITRE T1110 etiketi görünüyor mu?")
    print("   - Risk seviyesi 'Yüksek' olarak işaretlenmiş mi?")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="LocalShield - Brute Force Saldırısı Simülasyonu"
    )
    parser.add_argument(
        "-n", "--num-attempts",
        type=int,
        default=5,
        help="Simüle edilecek başarısız giriş denemesi sayısı (varsayılan: 5)"
    )
    parser.add_argument(
        "-t", "--time-window",
        type=int,
        default=60,
        help="Zaman penceresi (saniye) (varsayılan: 60)"
    )
    parser.add_argument(
        "-u", "--user",
        type=str,
        default="ATTACKER",
        help="Saldırgan kullanıcı adı (varsayılan: ATTACKER)"
    )
    parser.add_argument(
        "-d", "--db-path",
        type=str,
        default=None,
        help="Veritabanı yolu (varsayılan: config.DB_PATH)"
    )
    
    args = parser.parse_args()
    
    simulate_brute_force_attack(
        num_attempts=args.num_attempts,
        time_window_seconds=args.time_window,
        attacker_name=args.user,
        db_path=args.db_path
    )

