"""
LocalShield - Yapılandırma Dosyası
Production-Ready: .env dosyası desteği ve type hints ile güncellendi
"""
import os
from pathlib import Path
from typing import List

try:
    from dotenv import load_dotenv
    load_dotenv()  # .env dosyasını yükle
except ImportError:
    # python-dotenv yoksa devam et (varsayılan değerler kullanılacak)
    pass


# Ollama Model Ayarları
MODEL_NAME: str = os.getenv("OLLAMA_MODEL_NAME", "gemma3:4b")

# Veritabanı Ayarları
DB_PATH: str = os.getenv("DB_PATH", "logs.db")

# Windows Event Log Ayarları
EVENT_LOG_NAME: str = os.getenv("EVENT_LOG_NAME", "Security")
MAX_LOGS_TO_READ: int = int(os.getenv("MAX_LOGS_TO_READ", "10"))

# Streamlit Dashboard Ayarları
DASHBOARD_TITLE: str = os.getenv("DASHBOARD_TITLE", "🛡️ LocalShield - AI-Powered Offline SIEM")
DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "8501"))

# Log Watcher Ayarları
CHECK_INTERVAL: int = int(os.getenv("CHECK_INTERVAL", "5"))  # saniye

# Logging Ayarları
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE: str = os.getenv("LOG_FILE", "localshield.log")

# Güvenli Kullanıcı Listesi (Düşük Risk Olarak Değerlendirilecek)
# Sistem kullanıcıları ve mevcut kullanıcı otomatik olarak eklenir
SAFE_USERS: List[str] = [
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "Administrator",  # Yönetici hesapları (normal işlemler için)
]

# Dinamik kullanıcı algılama - Mevcut kullanıcıyı otomatik ekle
try:
    current_user = os.getlogin()
    if current_user and current_user not in SAFE_USERS:
        SAFE_USERS.append(current_user)
except Exception:
    # os.getlogin() bazı sistemlerde çalışmayabilir, alternatif yöntemler dene
    try:
        current_user = os.environ.get('USERNAME') or os.environ.get('USER')
        if current_user and current_user not in SAFE_USERS:
            SAFE_USERS.append(current_user)
    except Exception:
        pass  # Kullanıcı adı alınamazsa devam et
