"""
Threat Intelligence Module - Zararlı IP Kontrolü
Bilinen saldırgan IP'lerini kontrol eder ve risk seviyesini belirler
Production-Ready: CSV-based threat intelligence feed
"""
import csv
import logging
from pathlib import Path
from typing import Optional, Dict, Tuple

# Logging yapılandırması
logger = logging.getLogger(__name__)


class ThreatIntel:
    """
    Threat Intelligence veritabanını yöneten ve IP kontrolü yapan sınıf
    """
    
    def __init__(self, csv_path: str = "data/threat_intel.csv"):
        """
        ThreatIntel'i başlatır ve CSV dosyasından zararlı IP'leri yükler
        
        Args:
            csv_path: Threat intelligence CSV dosyasının yolu
        """
        self.csv_path = Path(csv_path)
        # IP -> (category, confidence) mapping için dictionary
        self.threat_db: Dict[str, Tuple[str, int]] = {}
        # Hızlı arama için IP set'i
        self.threat_ips: set[str] = set()
        
        self._load_threat_intel()
    
    def _load_threat_intel(self) -> None:
        """
        CSV dosyasından threat intelligence verilerini yükler
        """
        try:
            if not self.csv_path.exists():
                logger.warning(f"⚠️  Threat intelligence dosyası bulunamadı: {self.csv_path}")
                logger.warning("   Threat intelligence kontrolü devre dışı kalacak.")
                return
            
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                count = 0
                
                for row in reader:
                    ip = row.get('ip', '').strip()
                    category = row.get('category', 'Unknown').strip()
                    confidence = int(row.get('confidence', 0))
                    
                    # Benign IP'leri atla (confidence 0 veya category "Benign")
                    if category.lower() == 'benign' or confidence == 0:
                        continue
                    
                    if ip:
                        self.threat_db[ip] = (category, confidence)
                        self.threat_ips.add(ip)
                        count += 1
                
                logger.info(f"✅ Threat Intelligence yüklendi: {count} zararlı IP")
                
        except Exception as e:
            logger.error(f"❌ Threat intelligence yükleme hatası: {e}", exc_info=True)
            logger.warning("   Threat intelligence kontrolü devre dışı kalacak.")
    
    def check_ip(self, ip_address: str) -> Optional[Dict[str, any]]:
        """
        IP adresinin zararlı listede olup olmadığını kontrol eder
        
        Args:
            ip_address: Kontrol edilecek IP adresi
        
        Returns:
            Dict[str, any]: Eğer IP zararlıysa {'category': str, 'confidence': int}, değilse None
        """
        if not ip_address or not ip_address.strip():
            return None
        
        ip_clean = ip_address.strip()
        
        # Hızlı O(1) kontrolü için set kullan
        if ip_clean in self.threat_ips:
            category, confidence = self.threat_db[ip_clean]
            logger.warning(f"🚨 THREAT INTEL MATCH: {ip_clean} - Category: {category}, Confidence: {confidence}%")
            return {
                'ip': ip_clean,
                'category': category,
                'confidence': confidence
            }
        
        return None
    
    def reload(self) -> None:
        """
        Threat intelligence veritabanını yeniden yükler
        (CSV dosyası güncellendiğinde kullanılabilir)
        """
        self.threat_db.clear()
        self.threat_ips.clear()
        self._load_threat_intel()
    
    def get_threat_count(self) -> int:
        """
        Yüklenen zararlı IP sayısını döndürür
        
        Returns:
            int: Zararlı IP sayısı
        """
        return len(self.threat_ips)

