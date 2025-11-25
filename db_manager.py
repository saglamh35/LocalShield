"""
Database Manager - SQLite veritabanı yönetimi
Production-Ready: Type hints ve logging ile güncellendi
"""
import sqlite3
import logging
from datetime import datetime
from typing import Optional, List, Tuple
from pathlib import Path

import config

# Logging yapılandırması
logger = logging.getLogger(__name__)


def init_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    SQLite veritabanını oluşturur ve security_logs tablosunu hazırlar.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: config.DB_PATH)
    
    Returns:
        sqlite3.Connection: Veritabanı bağlantısı
    """
    db_path = db_path or config.DB_PATH
    
    try:
        # Thread-safe connection: timeout ve WAL modu ile
        conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
        # WAL (Write-Ahead Logging) modunu etkinleştir (daha iyi performans ve thread-safety)
        conn.execute('PRAGMA journal_mode=WAL')
        cursor = conn.cursor()
        
        # security_logs tablosunu oluştur
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                event_id TEXT,
                message TEXT,
                ai_analysis TEXT,
                risk_score TEXT,
                mitre_technique TEXT
            )
        ''')
        
        # Mevcut tablolara mitre_technique sütunu ekle (eğer yoksa)
        try:
            cursor.execute('ALTER TABLE security_logs ADD COLUMN mitre_technique TEXT')
            conn.commit()
            logger.debug("'mitre_technique' sütunu eklendi")
        except sqlite3.OperationalError:
            # Sütun zaten varsa hata verme
            pass
        
        conn.commit()
        logger.info(f"Veritabanı '{db_path}' başarıyla oluşturuldu/bağlandı")
        logger.debug("'security_logs' tablosu hazır")
        
        return conn
    except Exception as e:
        logger.error(f"Veritabanı başlatma hatası: {e}", exc_info=True)
        raise


def insert_log(
    timestamp: datetime,
    event_id: Optional[str] = None,
    message: Optional[str] = None,
    ai_analysis: Optional[str] = None,
    risk_score: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    db_path: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None
) -> int:
    """
    security_logs tablosuna yeni bir log kaydı ekler.
    
    Args:
        timestamp: Kayıt zamanı (datetime nesnesi)
        event_id: Event ID (opsiyonel)
        message: Log mesajı (opsiyonel)
        ai_analysis: AI analiz sonucu (opsiyonel)
        risk_score: Risk skoru (opsiyonel)
        mitre_technique: MITRE ATT&CK tekniği (opsiyonel)
        db_path: Veritabanı dosya yolu (varsayılan: config.DB_PATH)
        conn: Mevcut veritabanı bağlantısı (opsiyonel, verilmezse yeni bağlantı açar)
    
    Returns:
        int: Eklenen kaydın ID'si
    """
    should_close = False
    if conn is None:
        db_path = db_path or config.DB_PATH
        # Thread-safe connection: timeout ve WAL modu ile
        conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
        # WAL (Write-Ahead Logging) modunu etkinleştir (daha iyi performans ve thread-safety)
        conn.execute('PRAGMA journal_mode=WAL')
        should_close = True
    
    try:
        cursor = conn.cursor()
        
        # Timestamp'i string formatına çevir
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO security_logs (timestamp, event_id, message, ai_analysis, risk_score, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp_str, event_id, message, ai_analysis, risk_score, mitre_technique))
        
        conn.commit()
        log_id: int = cursor.lastrowid
        
        logger.debug(f"Log kaydı eklendi. ID: {log_id}, Event ID: {event_id}, Risk: {risk_score}")
        return log_id
        
    except Exception as e:
        logger.error(f"Log ekleme hatası: {e}", exc_info=True)
        raise
    finally:
        if should_close:
            conn.close()


def get_all_logs(
    db_path: Optional[str] = None,
    limit: Optional[int] = None,
    order_by: str = 'DESC'
) -> List[Tuple[int, str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]]:
    """
    security_logs tablosundan tüm log kayıtlarını getirir.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: config.DB_PATH)
        limit: Maksimum kayıt sayısı (opsiyonel)
        order_by: Sıralama yönü ('DESC' veya 'ASC', varsayılan: 'DESC')
    
    Returns:
        list: Log kayıtlarının listesi (tuple listesi: id, timestamp, event_id, message, ai_analysis, risk_score, mitre_technique)
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        
        query = f'''
            SELECT id, timestamp, event_id, message, ai_analysis, risk_score, mitre_technique
            FROM security_logs
            ORDER BY timestamp {order_by}
        '''
        
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query)
        results: List[Tuple[int, str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]] = cursor.fetchall()
        
        logger.debug(f"{len(results)} log kaydı getirildi (limit: {limit})")
        return results
        
    except Exception as e:
        logger.error(f"Log okuma hatası: {e}", exc_info=True)
        return []
    finally:
        conn.close()


def get_high_risk_count(db_path: Optional[str] = None) -> int:
    """
    Yüksek riskli olay sayısını döndürür.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: config.DB_PATH)
    
    Returns:
        int: Yüksek riskli olay sayısı
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM security_logs
            WHERE risk_score = 'Yüksek'
        ''')
        count: int = cursor.fetchone()[0]
        return count
        
    except Exception as e:
        logger.error(f"Yüksek riskli olay sayısı hesaplama hatası: {e}", exc_info=True)
        return 0
    finally:
        conn.close()


def get_total_log_count(db_path: Optional[str] = None) -> int:
    """
    Toplam log sayısını döndürür.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: config.DB_PATH)
    
    Returns:
        int: Toplam log sayısı
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM security_logs')
        count: int = cursor.fetchone()[0]
        return count
        
    except Exception as e:
        logger.error(f"Toplam log sayısı hesaplama hatası: {e}", exc_info=True)
        return 0
    finally:
        conn.close()


def get_latest_detection(db_path: Optional[str] = None) -> Optional[str]:
    """
    En son tespit edilen olayın zamanını döndürür.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: config.DB_PATH)
    
    Returns:
        str: Son tespit zamanı (varsa), yoksa None
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp FROM security_logs
            ORDER BY timestamp DESC
            LIMIT 1
        ''')
        result = cursor.fetchone()
        return result[0] if result else None
        
    except Exception as e:
        logger.error(f"Son tespit zamanı alma hatası: {e}", exc_info=True)
        return None
    finally:
        conn.close()


def clear_all_logs(db_path: Optional[str] = None) -> bool:
    """
    Veritabanındaki tüm log kayıtlarını siler (tablo yapısı korunur).
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: config.DB_PATH)
    
    Returns:
        bool: İşlem başarılıysa True, hata varsa False
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM security_logs')
        conn.commit()
        
        deleted_count = cursor.rowcount
        logger.info(f"Tüm log kayıtları silindi. Silinen kayıt sayısı: {deleted_count}")
        return True
        
    except Exception as e:
        logger.error(f"Log kayıtları silinirken hata: {e}", exc_info=True)
        conn.rollback()
        return False
    finally:
        conn.close()


# Test için örnek kullanım
if __name__ == "__main__":
    # Logging yapılandırması
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Veritabanını başlat
    conn = init_db(config.DB_PATH)
    
    # Örnek log kaydı ekle
    now = datetime.now()
    insert_log(
        timestamp=now,
        event_id="4625",
        message="Yönetici hesabına yanlış şifre girildi",
        ai_analysis="Potansiyel brute-force saldırısı tespit edildi.",
        risk_score="Yüksek",
        conn=conn
    )
    
    # Bağlantıyı kapat
    conn.close()
    logger.info("Test tamamlandı!")
