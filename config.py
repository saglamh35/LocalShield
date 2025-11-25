"""
LocalShield - Yapılandırma Dosyası
Tüm sabit ayarlar burada tanımlanır.
"""
import os

# Ollama Model Ayarları
MODEL_NAME = "gemma3:4b"  # veya "llama3.2" - Ollama'da kurulu model adınız

# Veritabanı Ayarları
DB_PATH = "logs.db"

# Windows Event Log Ayarları
EVENT_LOG_NAME = "Security"  # Windows Security logları
MAX_LOGS_TO_READ = 10  # Tek seferde okunacak maksimum log sayısı

# Streamlit Dashboard Ayarları
DASHBOARD_TITLE = "🛡️ LocalShield - AI-Powered Offline SIEM"
DASHBOARD_PORT = 8501

# Güvenli Kullanıcı Listesi (Düşük Risk Olarak Değerlendirilecek)
# Sistem kullanıcıları ve mevcut kullanıcı otomatik olarak eklenir
SAFE_USERS = [
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

