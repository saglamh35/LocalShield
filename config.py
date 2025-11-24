"""
LocalShield - Yapılandırma Dosyası
Tüm sabit ayarlar burada tanımlanır.
"""

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

