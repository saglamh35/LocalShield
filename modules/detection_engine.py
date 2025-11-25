"""
Detection Engine Module - Kural Motoru
Production-Ready: YAML tabanlı kural sistemi ve MITRE ATT&CK entegrasyonu
"""
import yaml
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

# Logging yapılandırması
logger = logging.getLogger(__name__)


class DetectionRule:
    """Tek bir detection rule'ı temsil eden sınıf"""
    
    def __init__(self, rule_data: Dict[str, Any], rule_file: str):
        """
        DetectionRule oluşturur.
        
        Args:
            rule_data: YAML dosyasından parse edilmiş kural verisi
            rule_file: Kural dosyasının adı
        """
        self.name: str = rule_data.get('name', 'Unknown Rule')
        self.description: str = rule_data.get('description', '')
        self.enabled: bool = rule_data.get('enabled', True)
        self.priority: str = rule_data.get('priority', 'medium')
        self.conditions: Dict[str, Any] = rule_data.get('conditions', {})
        self.risk_level: str = rule_data.get('risk_level', 'Orta')
        self.mitre_technique: Optional[str] = rule_data.get('mitre_technique')
        self.match_message: str = rule_data.get('match_message', f'Detection Rule Match: {self.name}')
        self.filters: Dict[str, Any] = rule_data.get('filters', {})
        self.rule_file: str = rule_file
        
        # Zaman penceresi ve eşik değerleri
        self.time_window: int = self.conditions.get('time_window', 60)  # saniye
        self.threshold: int = self.conditions.get('threshold', 5)
        self.event_id: Optional[str] = self.conditions.get('event_id')
        
        # Tekrar sayısını takip etmek için (event_id -> [(timestamp, user), ...])
        self.event_history: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    
    def matches(self, event_id: str, timestamp: datetime, message: str = "") -> bool:
        """
        Event'in bu kurala uyup uymadığını kontrol eder.
        
        Args:
            event_id: Event ID
            timestamp: Event zamanı
            message: Event mesajı (opsiyonel, filtreleme için)
        
        Returns:
            bool: Kural eşleşiyorsa True
        """
        if not self.enabled:
            return False
        
        # Event ID kontrolü
        if self.event_id and event_id != self.event_id:
            return False
        
        # Kullanıcı filtreleme
        if self.filters:
            exclude_users = self.filters.get('exclude_users', [])
            include_users = self.filters.get('include_users', [])
            
            # Mesajdan kullanıcı adını çıkarmaya çalış (basit regex)
            user_in_message = self._extract_user_from_message(message)
            
            if exclude_users and user_in_message:
                if user_in_message.upper() in [u.upper() for u in exclude_users]:
                    return False
            
            if include_users and user_in_message:
                if user_in_message.upper() not in [u.upper() for u in include_users]:
                    return False
        
        # Zaman penceresi kontrolü (eğer threshold varsa)
        if self.threshold > 0:
            # Eski kayıtları temizle (time_window'dan eski olanları)
            cutoff_time = timestamp - timedelta(seconds=self.time_window)
            self.event_history[event_id] = [
                (ts, user) for ts, user in self.event_history[event_id]
                if ts > cutoff_time
            ]
            
            # Yeni event'i ekle
            user_in_message = self._extract_user_from_message(message)
            self.event_history[event_id].append((timestamp, user_in_message or 'UNKNOWN'))
            
            # Eşik kontrolü
            if len(self.event_history[event_id]) >= self.threshold:
                return True
        
        return False
    
    def _extract_user_from_message(self, message: str) -> Optional[str]:
        """
        Mesajdan kullanıcı adını çıkarmaya çalışır.
        
        Args:
            message: Event mesajı
        
        Returns:
            str: Kullanıcı adı (varsa), yoksa None
        """
        if not message:
            return None
        
        # Basit pattern matching (Account Name, User Name gibi alanları ara)
        import re
        
        patterns = [
            r'Account Name:\s*([^\s\n]+)',
            r'User Name:\s*([^\s\n]+)',
            r'Account Name\s+([^\s\n]+)',
            r'User\s+([^\s\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def get_result(self) -> Dict[str, Any]:
        """
        Kural eşleştiğinde döndürülecek sonuç bilgilerini getirir.
        
        Returns:
            dict: Kural sonucu (risk_level, mitre_technique, match_message)
        """
        return {
            'risk_level': self.risk_level,
            'mitre_technique': self.mitre_technique,
            'match_message': self.match_message,
            'rule_name': self.name
        }


class DetectionEngine:
    """
    YAML tabanlı detection rule'ları yükleyen ve logları kontrol eden motor.
    """
    
    def __init__(self, rules_dir: str = "rules"):
        """
        DetectionEngine'i başlatır.
        
        Args:
            rules_dir: Kural dosyalarının bulunduğu dizin
        """
        self.rules_dir = Path(rules_dir)
        self.rules: List[DetectionRule] = []
        self.load_rules()
    
    def load_rules(self) -> None:
        """rules/ dizinindeki tüm YAML dosyalarını yükler"""
        try:
            if not self.rules_dir.exists():
                logger.warning(f"Kural dizini bulunamadı: {self.rules_dir}")
                return
            
            # Tüm YAML dosyalarını bul
            yaml_files = list(self.rules_dir.glob("*.yaml")) + list(self.rules_dir.glob("*.yml"))
            
            if not yaml_files:
                logger.warning(f"Kural dizininde YAML dosyası bulunamadı: {self.rules_dir}")
                return
            
            # Her YAML dosyasını yükle
            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, 'r', encoding='utf-8') as f:
                        rule_data = yaml.safe_load(f)
                    
                    if rule_data:
                        rule = DetectionRule(rule_data, yaml_file.name)
                        self.rules.append(rule)
                        logger.info(f"Kural yüklendi: {rule.name} ({yaml_file.name})")
                
                except Exception as e:
                    logger.error(f"Kural yüklenirken hata ({yaml_file}): {e}", exc_info=True)
            
            logger.info(f"Toplam {len(self.rules)} kural yüklendi")
        
        except Exception as e:
            logger.error(f"Kurallar yüklenirken hata: {e}", exc_info=True)
    
    def check_event(
        self,
        event_id: str,
        timestamp: datetime,
        message: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Bir event'i tüm kurallara göre kontrol eder.
        
        Args:
            event_id: Event ID
            timestamp: Event zamanı
            message: Event mesajı
        
        Returns:
            dict: Eğer kural eşleşirse, kural sonucu (risk_level, mitre_technique, match_message)
                 Eşleşme yoksa None
        """
        # Tüm kuralları kontrol et (priority'ye göre sırala: high -> medium -> low)
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_rules = sorted(
            self.rules,
            key=lambda r: priority_order.get(r.priority.lower(), 99)
        )
        
        for rule in sorted_rules:
            if rule.matches(event_id, timestamp, message):
                logger.warning(
                    f"🔴 KURAL EŞLEŞMESİ: {rule.name} - Event ID: {event_id}, "
                    f"Risk: {rule.risk_level}, MITRE: {rule.mitre_technique}"
                )
                return rule.get_result()
        
        return None
    
    def reload_rules(self) -> None:
        """Kuralları yeniden yükler (hot reload)"""
        self.rules.clear()
        self.load_rules()
        logger.info("Kurallar yeniden yüklendi")

