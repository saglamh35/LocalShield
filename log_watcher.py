"""
Log Watcher - Windows Security Event Log'larını sürekli dinleyen servis
Production-Ready: Asenkron yapı ve logging ile güncellendi
"""
import asyncio
import sys
import logging
from datetime import datetime
from typing import Optional, List, Any
from concurrent.futures import ThreadPoolExecutor

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
from modules.detection_engine import DetectionEngine

# Logging yapılandırması
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class LogWatcher:
    """
    Windows Security Event Log'larını asenkron olarak dinleyen ve AI ile analiz eden sınıf
    Production-Ready: AsyncIO kullanarak non-blocking yapı
    """
    
    def __init__(self) -> None:
        """LogWatcher'ı başlatır"""
        self.brain = Brain()
        self.detection_engine = DetectionEngine()  # Kural Motoru
        self.db_conn = init_db(config.DB_PATH)
        self.log_handle: Optional[Any] = None
        self.last_check_time = datetime.now()
        self.check_interval: int = config.CHECK_INTERVAL
        self.executor = ThreadPoolExecutor(max_workers=3)  # Thread pool for blocking operations
        self.running: bool = False
    
    def open_event_log(self) -> None:
        """Windows Event Log'unu açar (senkron işlem)"""
        try:
            self.log_handle = win32evtlog.OpenEventLog(
                None,  # Local machine
                config.EVENT_LOG_NAME
            )
            logger.info(f"'{config.EVENT_LOG_NAME}' log'u başarıyla açıldı")
            
        except Exception as e:
            logger.error(f"Event Log açılamadı: {e}")
            logger.warning("💡 Yönetici haklarıyla çalıştırdığınızdan emin olun.")
            raise
    
    def close_event_log(self) -> None:
        """Windows Event Log'unu kapatır"""
        if self.log_handle:
            try:
                win32evtlog.CloseEventLog(self.log_handle)
                self.log_handle = None
            except Exception as e:
                logger.warning(f"Log kapatılırken hata: {e}")
    
    def get_event_message(self, event: Any) -> str:
        """
        Event'ten okunabilir mesaj metnini alır
        
        Args:
            event: win32evtlog event nesnesi
        
        Returns:
            str: Event mesajı
        """
        try:
            message = win32evtlogutil.SafeFormatMessage(event, config.EVENT_LOG_NAME)
            if not message or message.strip() == "":
                if event.StringInserts:
                    message = " | ".join(str(insert) for insert in event.StringInserts)
                else:
                    message = "Mesaj alınamadı"
            return message
        except Exception as e:
            if event.StringInserts:
                return " | ".join(str(insert) for insert in event.StringInserts)
            return f"Event ID {event.EventID} (Mesaj parse edilemedi: {e})"
    
    async def process_event_async(self, event: Any) -> None:
        """
        Tek bir event'i asenkron olarak işler: AI'ye gönderir, veritabanına kaydeder
        
        Args:
            event: win32evtlog event nesnesi
        """
        try:
            # Event bilgilerini al
            event_id = str(event.EventID)
            event_time = event.TimeGenerated
            message = self.get_event_message(event)
            
            # StringInserts'ten ek bilgiler al
            additional_info = ""
            if event.StringInserts:
                inserts_str = " | ".join([str(insert) for insert in event.StringInserts if insert])
                if inserts_str:
                    additional_info = f"\nEk Detaylar (StringInserts): {inserts_str}"
            
            # Event'i zengin bir formatta birleştir
            log_text = f"""Event ID: {event_id}
Zaman: {event_time}
Mesaj: {message}{additional_info}

Not: Mesaj içinde 'Account Name', 'Workstation Name', 'Source Network Address', 'Logon Type' gibi alanları özellikle tarayın."""
            
            # ÖNCE: Kural Motoru kontrolü (Hızlı ve Kesin)
            logger.info(f"Event ID {event_id} kural motorunda kontrol ediliyor...")
            loop = asyncio.get_event_loop()
            detection_result = await loop.run_in_executor(
                self.executor,
                self.detection_engine.check_event,
                event_id,
                event_time,
                message
            )
            
            # Kural Motoru sonucu
            rule_risk_level: Optional[str] = None
            mitre_technique: Optional[str] = None
            rule_match_message: Optional[str] = None
            
            if detection_result:
                rule_risk_level = detection_result.get('risk_level')
                mitre_technique = detection_result.get('mitre_technique')
                rule_match_message = detection_result.get('match_message')
                logger.warning(f"🔴 KURAL EŞLEŞMESİ: {detection_result.get('rule_name')} - Risk: {rule_risk_level}, MITRE: {mitre_technique}")
            
            # SONRA: AI analizini thread pool'da çalıştır (blocking operation)
            logger.info(f"Event ID {event_id} AI ile analiz ediliyor...")
            analysis, ai_risk_level = await loop.run_in_executor(
                self.executor,
                self.brain.analyze,
                log_text
            )
            
            # Kural Motoru override mantığı: Eğer Kural Motoru "Yüksek Risk" derse, AI'ın risk skorunu override et
            final_risk_level = ai_risk_level
            final_analysis = analysis
            
            if rule_risk_level:
                # Kural Motoru sonucunu AI analizine ekle
                if rule_match_message:
                    final_analysis = f"{rule_match_message}\n\n---\n\n{analysis}"
                
                # Kural Motoru "Yüksek Risk" derse, AI'ın risk skorunu override et
                if rule_risk_level == "Yüksek":
                    final_risk_level = "Yüksek"
                    logger.warning(f"⚠️ Kural Motoru risk skorunu override etti: {ai_risk_level} -> {final_risk_level}")
                else:
                    # Kural Motoru "Yüksek" değilse, AI'ın skorunu kullan ama kural sonucunu da göster
                    final_risk_level = ai_risk_level
            
            # Veritabanına kaydet (thread pool'da çalıştır)
            # DÜZELTME: conn=None yaparak her thread'in kendi connection'ını açmasını sağlıyoruz
            # SQLite thread-safe değil, bu yüzden her thread kendi connection'ını kullanmalı
            await loop.run_in_executor(
                self.executor,
                lambda: insert_log(
                    timestamp=event_time,
                    event_id=event_id,
                    message=message[:500],
                    ai_analysis=final_analysis,
                    risk_score=final_risk_level,
                    mitre_technique=mitre_technique,
                    conn=None  # Her thread kendi connection'ını açacak
                )
            )
            
            logger.info(f"Log işlendi: Event ID {event_id} - Risk: {final_risk_level} - MITRE: {mitre_technique or 'N/A'}")
            
        except Exception as e:
            logger.error(f"Event işlenirken hata: {e}", exc_info=True)
    
    async def check_new_events_async(self) -> None:
        """Yeni event'leri asenkron olarak kontrol eder ve işler"""
        try:
            # Event log okuma işlemini thread pool'da çalıştır (blocking operation)
            loop = asyncio.get_event_loop()
            events = await loop.run_in_executor(
                self.executor,
                self._read_events_sync
            )
            
            if events:
                # Yeni event'leri asenkron olarak işle
                tasks = []
                for event in events:
                    task = self.process_event_async(event)
                    tasks.append(task)
                
                # Tüm event'leri paralel işle
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
            
            # Son kontrol zamanını güncelle
            self.last_check_time = datetime.now()
                    
        except Exception as e:
            error_code = getattr(e, 'winerror', None)
            error_msg = str(e).lower()
            
            # Normal hataları loglamadan atla
            if error_code == 122 or error_code == 1223:
                pass
            elif "no more data" in error_msg or "no more events" in error_msg or "no records" in error_msg:
                pass
            else:
                logger.warning(f"Log okuma hatası: {e}")
                # Log'u yeniden kurmayı dene
                try:
                    self.close_event_log()
                    await asyncio.sleep(1)
                except Exception:
                    pass
    
    def _read_events_sync(self) -> List[Any]:
        """
        Event'leri senkron olarak okur (thread pool'da çalıştırılacak)
        
        Returns:
            list: Yeni event'lerin listesi
        """
        try:
            # Her seferinde log'u kapatıp aç (yeni logları görmek için)
            self.close_event_log()
            self.open_event_log()
            
            if not self.log_handle:
                return []
            
            # Son kontrol zamanından sonraki event'leri oku
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
                    if event_time > self.last_check_time:
                        new_events.append(event)
                
                # Yeni event'leri zaman sırasına göre sırala
                new_events.sort(key=lambda e: e.TimeGenerated)
                return new_events
            
            return []
            
        except Exception as e:
            error_code = getattr(e, 'winerror', None)
            error_msg = str(e).lower()
            
            # Normal hataları sessizce atla
            if error_code == 122 or error_code == 1223:
                return []
            elif "no more data" in error_msg or "no more events" in error_msg:
                return []
            
            logger.warning(f"Event okuma hatası: {e}")
            return []
    
    async def run_async(self) -> None:
        """Asenkron olarak log'ları dinler"""
        logger.info("🛡️  LocalShield Log Watcher başlatılıyor...")
        logger.info("=" * 60)
        
        try:
            # Event Log'u aç (senkron işlem, thread pool'da çalıştır)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self.executor, self.open_event_log)
            
            logger.info(f"⏰ Her {self.check_interval} saniyede bir yeni log kontrol ediliyor...")
            logger.info("💡 Çıkmak için Ctrl+C tuşlarına basın.")
            logger.info("=" * 60)
            
            self.running = True
            
            # Asenkron döngü
            while self.running:
                try:
                    await self.check_new_events_async()
                    await asyncio.sleep(self.check_interval)
                except KeyboardInterrupt:
                    logger.info("\n\n⚠️  Kullanıcı tarafından durduruldu.")
                    self.running = False
                    break
                except Exception as e:
                    logger.error(f"Beklenmeyen hata: {e}", exc_info=True)
                    await asyncio.sleep(1)  # Hata durumunda kısa bekle
                    
        except Exception as e:
            logger.error(f"Kritik hata: {e}", exc_info=True)
        finally:
            # Temizlik
            self.close_event_log()
            if self.db_conn:
                self.db_conn.close()
            self.executor.shutdown(wait=True)
            logger.info("\n🛡️  LocalShield Log Watcher kapatıldı.")
    
    def run(self) -> None:
        """
        Senkron wrapper - asenkron run_async'i çalıştırır
        Geriye dönük uyumluluk için
        """
        try:
            asyncio.run(self.run_async())
        except KeyboardInterrupt:
            logger.info("Log Watcher durduruldu.")


if __name__ == "__main__":
    watcher = LogWatcher()
    watcher.run()
