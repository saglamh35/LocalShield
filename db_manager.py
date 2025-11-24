import sqlite3
from datetime import datetime
from typing import Optional


def init_db(db_path: str = 'logs.db'):
    """
    SQLite veritabanını oluşturur ve security_logs tablosunu hazırlar.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: 'logs.db')
    
    Returns:
        sqlite3.Connection: Veritabanı bağlantısı
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # security_logs tablosunu oluştur
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            event_id TEXT,
            message TEXT,
            ai_analysis TEXT,
            risk_score TEXT
        )
    ''')
    
    conn.commit()
    print(f"Veritabanı '{db_path}' başarıyla oluşturuldu/bağlandı.")
    print("'security_logs' tablosu hazır.")
    
    return conn


def insert_log(
    timestamp: datetime,
    event_id: Optional[str] = None,
    message: Optional[str] = None,
    ai_analysis: Optional[str] = None,
    risk_score: Optional[str] = None,
    db_path: str = 'logs.db',
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
        db_path: Veritabanı dosya yolu (varsayılan: 'logs.db')
        conn: Mevcut veritabanı bağlantısı (opsiyonel, verilmezse yeni bağlantı açar)
    
    Returns:
        int: Eklenen kaydın ID'si
    """
    should_close = False
    if conn is None:
        conn = sqlite3.connect(db_path)
        should_close = True
    
    try:
        cursor = conn.cursor()
        
        # Timestamp'i string formatına çevir
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO security_logs (timestamp, event_id, message, ai_analysis, risk_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp_str, event_id, message, ai_analysis, risk_score))
        
        conn.commit()
        log_id = cursor.lastrowid
        
        print(f"Log kaydı eklendi. ID: {log_id}")
        return log_id
        
    finally:
        if should_close:
            conn.close()


def get_all_logs(db_path: str = 'logs.db', limit: Optional[int] = None, order_by: str = 'DESC'):
    """
    security_logs tablosundan tüm log kayıtlarını getirir.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: 'logs.db')
        limit: Maksimum kayıt sayısı (opsiyonel)
        order_by: Sıralama yönü ('DESC' veya 'ASC', varsayılan: 'DESC')
    
    Returns:
        list: Log kayıtlarının listesi (tuple listesi)
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        query = f'''
            SELECT id, timestamp, event_id, message, ai_analysis, risk_score
            FROM security_logs
            ORDER BY timestamp {order_by}
        '''
        
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query)
        results = cursor.fetchall()
        return results
        
    finally:
        conn.close()


def get_high_risk_count(db_path: str = 'logs.db') -> int:
    """
    Yüksek riskli olay sayısını döndürür.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: 'logs.db')
    
    Returns:
        int: Yüksek riskli olay sayısı
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT COUNT(*) FROM security_logs
            WHERE risk_score = 'Yüksek'
        ''')
        count = cursor.fetchone()[0]
        return count
        
    finally:
        conn.close()


def get_total_log_count(db_path: str = 'logs.db') -> int:
    """
    Toplam log sayısını döndürür.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: 'logs.db')
    
    Returns:
        int: Toplam log sayısı
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT COUNT(*) FROM security_logs')
        count = cursor.fetchone()[0]
        return count
        
    finally:
        conn.close()


def get_latest_detection(db_path: str = 'logs.db') -> Optional[str]:
    """
    En son tespit edilen olayın zamanını döndürür.
    
    Args:
        db_path: Veritabanı dosya yolu (varsayılan: 'logs.db')
    
    Returns:
        str: Son tespit zamanı (varsa), yoksa None
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT timestamp FROM security_logs
            ORDER BY timestamp DESC
            LIMIT 1
        ''')
        result = cursor.fetchone()
        return result[0] if result else None
        
    finally:
        conn.close()


# Test için örnek kullanım
if __name__ == "__main__":
    # Veritabanını başlat
    conn = init_db('logs.db')
    
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
    print("\nTest tamamlandı!")

