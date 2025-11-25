"""
Network Scanner Module - Açık Portları Tarayan Modül
"""
import psutil
import socket
from typing import List, Dict, Optional, Any


# Yüksek riskli portlar (güvenlik açısından kritik)
HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Proxy",
    135: "MSRPC",
    139: "NetBIOS"
}

# Düşük riskli ama yaygın portlar
KNOWN_SAFE_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S"
}


def get_process_name(pid: int) -> str:
    """
    Process ID'den uygulama adını alır
    
    Args:
        pid: Process ID
    
    Returns:
        str: Uygulama adı veya "Bilinmiyor"
    """
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Erişim Reddedildi"
    except Exception:
        return "Bilinmiyor"


def get_port_info(port: int, pid: Optional[int] = None) -> Dict[str, Any]:
    """
    Port hakkında bilgi toplar
    
    Args:
        port: Port numarası
        pid: Process ID (opsiyonel)
    
    Returns:
        dict: Port bilgisi (ad, risk, açıklama)
    """
    port_info = {
        "port": port,
        "name": "Bilinmeyen",
        "risk": "Düşük",
        "description": "Bilinmeyen servis"
    }
    
    # Yüksek riskli portları kontrol et
    if port in HIGH_RISK_PORTS:
        port_info["name"] = HIGH_RISK_PORTS[port]
        port_info["risk"] = "Yüksek"
        port_info["description"] = f"{HIGH_RISK_PORTS[port]} servisi - Güvenlik açısından dikkatli olunmalı"
        return port_info
    
    # Bilinen güvenli portları kontrol et
    if port in KNOWN_SAFE_PORTS:
        port_info["name"] = KNOWN_SAFE_PORTS[port]
        port_info["risk"] = "Düşük"
        port_info["description"] = f"{KNOWN_SAFE_PORTS[port]} servisi - Genelde güvenli"
        return port_info
    
    # Bilinmeyen portlar için socket servisini sorgula
    try:
        service_name = socket.getservbyport(port, 'tcp')
        port_info["name"] = service_name.upper()
        port_info["description"] = f"{service_name.upper()} servisi"
    except (OSError, socket.error):
        port_info["name"] = "Bilinmeyen"
        port_info["description"] = "Bilinmeyen servis"
    
    return port_info


def scan_open_ports() -> List[Dict[str, Any]]:
    """
    Bilgisayardaki LISTEN (Dinleme) modundaki tüm TCP portlarını tarar
    
    Returns:
        list: Port bilgileri listesi (port, pid, process_name, risk, description)
    """
    open_ports = []
    
    try:
        # Tüm network bağlantılarını al
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            try:
                # Sadece LISTEN durumundaki TCP bağlantılarını al
                if conn.status == psutil.CONN_LISTEN and conn.type == socket.SOCK_STREAM:
                    port = conn.laddr.port
                    pid = conn.pid
                    
                    # Port bilgisini al
                    port_info = get_port_info(port, pid)
                    
                    # Process adını al
                    if pid:
                        process_name = get_process_name(pid)
                    else:
                        process_name = "Bilinmiyor"
                    
                    # Port bilgisini ekle
                    port_data = {
                        "Port": port,
                        "PID": pid if pid else "N/A",
                        "Uygulama": process_name,
                        "Servis": port_info["name"],
                        "Risk": port_info["risk"],
                        "Açıklama": port_info["description"]
                    }
                    
                    open_ports.append(port_data)
            
            except (psutil.AccessDenied, AttributeError, OSError) as e:
                # Erişim reddedildi veya bilgi alınamadı, devam et
                continue
            except Exception as e:
                # Beklenmeyen hata, logla ama devam et
                print(f"⚠️  Port tarama hatası: {e}")
                continue
    
    except psutil.AccessDenied:
        print("❌ Yönetici hakları gerekli. Port taraması için yönetici olarak çalıştırın.")
        return []
    except Exception as e:
        print(f"❌ Port tarama sırasında kritik hata: {e}")
        return []
    
    # Port numarasına göre sırala
    open_ports.sort(key=lambda x: x["Port"])
    
    return open_ports


def get_port_summary(ports: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Port tarama sonuçlarının özetini döndürür
    
    Args:
        ports: Port bilgileri listesi
    
    Returns:
        dict: Özet istatistikler
    """
    summary = {
        "Toplam": len(ports),
        "Yüksek Risk": 0,
        "Düşük Risk": 0
    }
    
    for port_info in ports:
        if port_info.get("Risk") == "Yüksek":
            summary["Yüksek Risk"] += 1
        else:
            summary["Düşük Risk"] += 1
    
    return summary

