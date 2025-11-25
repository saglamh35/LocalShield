"""
Log Watcher - Windows Security Event Log'larını sürekli dinleyen servis
"""
import time
import sys
from datetime import datetime
from typing import Optional
import re

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
except ImportError:
    print("HATA: pywin32 kütüphanesi kurulu değil. 'pip install pywin32' komutu ile kurun.")
    sys.exit(1)

import config
from db_manager import init_db, insert_log
from modules.ai_engine import Brain


class LogWatcher:
    """
    Windows Security Event Log'larını sürekli dinleyen ve AI ile analiz eden sınıf
    """
    
    def __init__(self):
        """LogWatcher'ı başlatır"""
        self.brain = Brain()
        self.db_conn = init_db(config.DB_PATH)
        self.log_handle = None
        self.last_check_time = datetime.now()  # Son kontrol zamanı
        self.check_interval = 5  # 5 saniyede bir kontrol et
        
    def open_event_log(self):
        """Windows Event Log'unu açar"""
        try:
            self.log_handle = win32evtlog.OpenEventLog(
                None,  # Local machine
                config.EVENT_LOG_NAME
            )
            print(f"✅ '{config.EVENT_LOG_NAME}' log'u başarıyla açıldı.")
            
        except Exception as e:
            print(f"❌ Event Log açılamadı: {e}")
            print("💡 Yönetici haklarıyla çalıştırdığınızdan emin olun.")
            raise
    
    def close_event_log(self):
        """Windows Event Log'unu kapatır"""
        if self.log_handle:
            try:
                win32evtlog.CloseEventLog(self.log_handle)
                self.log_handle = None
            except Exception as e:
                print(f"⚠️  Log kapatılırken hata: {e}")
    
    def get_event_message(self, event):
        """
        Event'ten okunabilir mesaj metnini alır
        
        Args:
            event: win32evtlog event nesnesi
            
        Returns:
            str: Event mesajı
        """
        try:
            # Win32evtlogutil ile mesajı formatla
            message = win32evtlogutil.SafeFormatMessage(event, config.EVENT_LOG_NAME)
            if not message or message.strip() == "":
                # Mesaj alınamazsa StringInserts'ten oluştur
                if event.StringInserts:
                    message = " | ".join(str(insert) for insert in event.StringInserts)
                else:
                    message = "Mesaj alınamadı"
            return message
        except Exception as e:
            # Mesaj alınamazsa alternatif yöntemler dene
            if event.StringInserts:
                return " | ".join(str(insert) for insert in event.StringInserts)
            return f"Event ID {event.EventID} (Mesaj parse edilemedi: {e})"
    
    def parse_risk_level(self, analysis: str) -> str:
        """
        AI analizinden risk seviyesini çıkarır (Yeni Eğitici Markdown formatı için)
        
        Yeni format:
        🕵️‍♂️ Olay Analizi
        Kullanıcı: ...
        Durum: ...
        Risk: [Düşük/Orta/Yüksek]
        
        Args:
            analysis: AI analiz metni (Markdown formatında)
        
        Returns:
            str: Risk seviyesi (Düşük/Orta/Yüksek)
        """
        # Yeni format: "Risk: [Düşük/Orta/Yüksek]" satırını ara
        # Bu satır genellikle "🕵️‍♂️ Olay Analizi" bölümünde bulunur
        # Regex: "Risk:" kelimesinden sonra gelen risk seviyesini yakala
        match = re.search(r'Risk:\s*([Düşük|Orta|Yüksek]+)', analysis, re.IGNORECASE | re.MULTILINE)
        
        if match:
            risk = match.group(1).strip()
            # Türkçe karakterleri ve büyük/küçük harf kontrolü
            risk_lower = risk.lower()
            if "yüksek" in risk_lower or "high" in risk_lower:
                return "Yüksek"
            elif "orta" in risk_lower or "medium" in risk_lower:
                return "Orta"
            elif "düşük" in risk_lower or "low" in risk_lower:
                return "Düşük"
        
        # Eski format desteği (geriye dönük uyumluluk için)
        # "🛑 Risk: Yüksek" formatını da destekle
        match_old = re.search(r'🛑\s*Risk:\s*([Düşük|Orta|Yüksek]+)', analysis, re.IGNORECASE)
        if match_old:
            risk = match_old.group(1).strip()
            risk_lower = risk.lower()
            if "yüksek" in risk_lower or "high" in risk_lower:
                return "Yüksek"
            elif "orta" in risk_lower or "medium" in risk_lower:
                return "Orta"
            elif "düşük" in risk_lower or "low" in risk_lower:
                return "Düşük"
        
        # Eğer hiçbir eşleşme bulunamazsa, analiz içeriğinden tahmin et
        analysis_lower = analysis.lower()
        if any(keyword in analysis_lower for keyword in ['brute', 'saldırı', 'attack', 'unauthorized', 'yetkisiz', 'şüpheli', 'suspicious']):
            return "Yüksek"
        elif any(keyword in analysis_lower for keyword in ['başarısız', 'failed', 'failed logon', 'sıradışı', 'unusual']):
            return "Orta"
        
        return "Orta"  # Varsayılan
    
    def process_event(self, event):
        """
        Tek bir event'i işler: AI'ye gönderir, veritabanına kaydeder
        
        Args:
            event: win32evtlog event nesnesi
        """
        try:
            # Event bilgilerini al
            event_id = str(event.EventID)
            event_time = event.TimeGenerated
            message = self.get_event_message(event)
            
            # StringInserts'ten ek bilgiler al (AI'ın analiz edebilmesi için)
            additional_info = ""
            if event.StringInserts:
                # StringInserts genellikle Event ID'ye göre farklı alanlar içerir
                # Örneğin: Account Name, Workstation Name, Source Network Address vb.
                inserts_str = " | ".join([str(insert) for insert in event.StringInserts if insert])
                if inserts_str:
                    additional_info = f"\nEk Detaylar (StringInserts): {inserts_str}"
            
            # Event'i zengin bir formatta birleştir (AI'ın daha iyi analiz edebilmesi için)
            log_text = f"""Event ID: {event_id}
Zaman: {event_time}
Mesaj: {message}{additional_info}

Not: Mesaj içinde 'Account Name', 'Workstation Name', 'Source Network Address', 'Logon Type' gibi alanları özellikle tarayın."""
            
            # AI'ye gönder ve analiz ettir
            print(f"\n🔍 Event ID {event_id} analiz ediliyor...")
            analysis = self.brain.analyze(log_text)
            
            # Risk seviyesini parse et
            risk_level = self.parse_risk_level(analysis)
            
            # Veritabanına kaydet (ai_analysis artık Markdown formatında)
            insert_log(
                timestamp=event_time,
                event_id=event_id,
                message=message[:500],  # Mesaj çok uzunsa kısalt
                ai_analysis=analysis,  # Artık zengin Markdown formatında
                risk_score=risk_level,
                conn=self.db_conn
            )
            
            # Ekrana yazdır
            print(f"✅ Log işlendi: {event_id} - {risk_level}")
            
        except Exception as e:
            print(f"❌ Event işlenirken hata: {e}")
    
    def check_new_events(self):
        """Yeni event'leri kontrol eder ve işler"""
        try:
            # Her seferinde log'u kapatıp aç (yeni logları görmek için)
            self.close_event_log()
            self.open_event_log()
            
            if not self.log_handle:
                return
            
            # Son kontrol zamanından sonraki event'leri oku
            # En yeni kayıtlardan başlayarak oku (backwards read)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(
                self.log_handle,
                flags,
                0,
                100  # Maksimum 100 event oku
            )
            
            if events:
                new_events = []
                current_time = datetime.now()
                
                # Event'leri zaman damgasına göre filtrele
                for event in events:
                    event_time = event.TimeGenerated
                    # Son kontrol zamanından sonraki event'leri al
                    if event_time > self.last_check_time:
                        new_events.append(event)
                
                # Yeni event'leri zaman sırasına göre sırala (en eskiden en yeniye)
                new_events.sort(key=lambda e: e.TimeGenerated)
                
                # Yeni event'leri işle
                for event in new_events:
                    self.process_event(event)
            
            # Son kontrol zamanını güncelle
            self.last_check_time = datetime.now()
                    
        except Exception as e:
            # Hata durumunda
            error_code = getattr(e, 'winerror', None)
            error_msg = str(e).lower()
            
            if error_code == 122:  # ERROR_INSUFFICIENT_BUFFER
                # Buffer çok küçük, bu normal olabilir
                pass
            elif "no more data" in error_msg or "no more events" in error_msg or "no records" in error_msg:
                # Yeni log yok, bu normal
                pass
            elif error_code == 1223:  # ERROR_NO_MORE_ITEMS
                # Daha fazla item yok, normal
                pass
            else:
                print(f"⚠️  Log okuma hatası: {e}")
                # Log'u yeniden kurmayı dene
                try:
                    self.close_event_log()
                    time.sleep(1)
                except:
                    pass
    
    def run(self):
        """Sonsuz döngüde log'ları dinler"""
        print("🛡️  LocalShield Log Watcher başlatılıyor...")
        print("=" * 60)
        
        try:
            # Event Log'u aç
            self.open_event_log()
            
            print(f"⏰ Her {self.check_interval} saniyede bir yeni log kontrol ediliyor...")
            print("💡 Çıkmak için Ctrl+C tuşlarına basın.")
            print("=" * 60)
            
            # Sonsuz döngü
            while True:
                try:
                    self.check_new_events()
                except KeyboardInterrupt:
                    print("\n\n⚠️  Kullanıcı tarafından durduruldu.")
                    break
                except Exception as e:
                    print(f"❌ Beklenmeyen hata: {e}")
                
                # 5 saniye bekle
                time.sleep(self.check_interval)
                
        except Exception as e:
            print(f"❌ Kritik hata: {e}")
        finally:
            # Temizlik
            self.close_event_log()
            if self.db_conn:
                self.db_conn.close()
            print("\n🛡️  LocalShield Log Watcher kapatıldı.")


if __name__ == "__main__":
    watcher = LogWatcher()
    watcher.run()

