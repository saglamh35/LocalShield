"""
Response Engine Module - Active Response (Otomatik Müdahale)
Windows Firewall üzerinden IP engelleme işlemleri
Production-Ready: Error handling ve logging ile güncellendi
"""
import subprocess
import re
import logging
import ipaddress
from typing import Optional, List

# Logging yapılandırması
logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Windows Firewall üzerinden IP engelleme işlemlerini yöneten sınıf
    """
    
    def __init__(self):
        """FirewallManager'ı başlatır"""
        self.blocked_ips: set[str] = set()  # Engellenen IP'leri takip et
    
    def is_valid_ipv4(self, ip_str: str) -> bool:
        """
        IPv4 adresinin geçerli olup olmadığını kontrol eder
        
        Args:
            ip_str: Kontrol edilecek IP adresi string'i
        
        Returns:
            bool: Geçerli IPv4 ise True
        """
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    def is_private_ip(self, ip_str: str) -> bool:
        """
        IP adresinin private/local olup olmadığını kontrol eder
        
        Private IP aralıkları:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 127.0.0.0/8 (Loopback)
        - 169.254.0.0/16 (Link-local)
        
        Args:
            ip_str: Kontrol edilecek IP adresi
        
        Returns:
            bool: Private IP ise True
        """
        try:
            ip = ipaddress.IPv4Address(ip_str)
            # ipaddress kütüphanesinin yerleşik özelliklerini kullan
            # is_private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            # is_loopback: 127.0.0.0/8
            # is_link_local: 169.254.0.0/16
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except (ValueError, ipaddress.AddressValueError):
            # Geçersiz IP adresi için False döndür
            return False
    
    def extract_ips_from_text(self, text: str) -> List[str]:
        """
        Metinden IPv4 adreslerini çıkarır
        
        Args:
            text: IP adreslerinin aranacağı metin
        
        Returns:
            List[str]: Bulunan IP adresleri listesi
        """
        # IPv4 regex pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, text)
        
        # Geçerli IP'leri filtrele
        valid_ips = []
        for match in matches:
            if self.is_valid_ipv4(match):
                valid_ips.append(match)
        
        return valid_ips
    
    def block_ip(self, ip_address: str) -> bool:
        """
        Windows Firewall'da bir IP adresini engeller
        
        Args:
            ip_address: Engellenecek IP adresi
        
        Returns:
            bool: Engelleme başarılı ise True
        """
        # IP validasyonu
        if not self.is_valid_ipv4(ip_address):
            logger.warning(f"❌ Geçersiz IP adresi: {ip_address}")
            return False
        
        # Private IP kontrolü
        if self.is_private_ip(ip_address):
            logger.warning(f"⚠️  Private IP adresi engellenmedi (güvenlik): {ip_address}")
            return False
        
        # Zaten engellenmiş mi kontrol et
        if ip_address in self.blocked_ips:
            logger.info(f"ℹ️  IP adresi zaten engellenmiş: {ip_address}")
            return True
        
        # Windows Firewall kuralı oluştur
        rule_name = f"LocalShield_Block_{ip_address.replace('.', '_')}"
        
        try:
            # netsh advfirewall firewall add rule komutu
            # Yön: inbound (gelen trafik)
            # Action: block (engelle)
            # RemoteIP: engellenecek IP
            command = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                'enable=yes'
            ]
            
            # Komutu çalıştır
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False  # Hata durumunda exception fırlatma
            )
            
            # Başarı kontrolü
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                logger.warning(f"🛡️  IP adresi başarıyla engellendi: {ip_address} (Kural: {rule_name})")
                return True
            else:
                # Hata mesajını kontrol et
                error_output = result.stderr.lower()
                
                # Eğer kural zaten varsa, bu bir hata değil
                if 'already exists' in error_output or 'zaten var' in error_output:
                    self.blocked_ips.add(ip_address)
                    logger.info(f"ℹ️  Firewall kuralı zaten mevcut: {rule_name}")
                    return True
                else:
                    logger.error(f"❌ IP engelleme hatası ({ip_address}): {result.stderr}")
                    return False
                    
        except subprocess.TimeoutExpired:
            logger.error(f"❌ IP engelleme zaman aşımı: {ip_address}")
            return False
        except Exception as e:
            logger.error(f"❌ IP engelleme beklenmeyen hatası ({ip_address}): {e}", exc_info=True)
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Windows Firewall'dan bir IP adresinin engelini kaldırır
        
        Args:
            ip_address: Engeli kaldırılacak IP adresi
        
        Returns:
            bool: İşlem başarılı ise True
        """
        rule_name = f"LocalShield_Block_{ip_address.replace('.', '_')}"
        
        try:
            command = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip_address)
                logger.info(f"✅ IP adresi engeli kaldırıldı: {ip_address}")
                return True
            else:
                logger.warning(f"⚠️  IP engeli kaldırılamadı ({ip_address}): {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"❌ IP engeli kaldırma hatası ({ip_address}): {e}", exc_info=True)
            return False

