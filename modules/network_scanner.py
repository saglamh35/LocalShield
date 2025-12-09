"""
Network Scanner Module - Module for Scanning Open Ports
"""
import psutil
import socket
from typing import List, Dict, Optional, Any
import config


# High-risk ports (critical from security perspective)
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

# Low-risk but common ports
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
    Gets application name from Process ID
    
    Args:
        pid: Process ID
    
    Returns:
        str: Application name or "Unknown"
    """
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Access Denied"
    except Exception:
        return "Unknown"


def get_port_info(port: int, pid: Optional[int] = None) -> Dict[str, Any]:
    """
    Collects information about a port
    
    Args:
        port: Port number
        pid: Process ID (optional)
    
    Returns:
        dict: Port information (name, risk, description)
    """
    port_info = {
        "port": port,
        "name": "Unknown",
        "risk": "Low",
        "description": "Unknown service"
    }
    
    # Check high-risk ports
    if port in HIGH_RISK_PORTS:
        port_info["name"] = HIGH_RISK_PORTS[port]
        port_info["risk"] = "High"
        port_info["description"] = f"{HIGH_RISK_PORTS[port]} service - Should be carefully monitored from security perspective"
        return port_info
    
    # Check known safe ports
    if port in KNOWN_SAFE_PORTS:
        port_info["name"] = KNOWN_SAFE_PORTS[port]
        port_info["risk"] = "Low"
        port_info["description"] = f"{KNOWN_SAFE_PORTS[port]} service - Generally safe"
        return port_info
    
    # Query socket service for unknown ports
    try:
        service_name = socket.getservbyport(port, 'tcp')
        port_info["name"] = service_name.upper()
        port_info["description"] = f"{service_name.upper()} service"
    except (OSError, socket.error):
        port_info["name"] = "Unknown"
        port_info["description"] = "Unknown service"
    
    return port_info


def scan_open_ports(mock: bool = False) -> List[Dict[str, Any]]:
    """
    Scans all TCP ports in LISTEN mode on the computer
    
    Args:
        mock: If True, returns demo data instead of real scan (default: False, uses config.DEMO_MODE)
    
    Returns:
        list: List of port information (port, pid, process_name, risk, description)
    """
    # Check demo mode
    use_demo = mock or config.DEMO_MODE
    
    if use_demo:
        # Return demo port data for screenshots
        return [
            {
                "Port": 445,
                "PID": 4,
                "Application": "System",
                "Service": "SMB",
                "Risk": "High",
                "Description": "SMB service - Should be carefully monitored from security perspective"
            },
            {
                "Port": 3389,
                "PID": 1234,
                "Application": "svchost.exe",
                "Service": "RDP",
                "Risk": "High",
                "Description": "RDP service - Should be carefully monitored from security perspective"
            },
            {
                "Port": 135,
                "PID": 567,
                "Application": "svchost.exe",
                "Service": "MSRPC",
                "Risk": "High",
                "Description": "MSRPC service - Should be carefully monitored from security perspective"
            },
            {
                "Port": 80,
                "PID": 8901,
                "Application": "nginx",
                "Service": "HTTP",
                "Risk": "Low",
                "Description": "HTTP service - Generally safe"
            },
            {
                "Port": 443,
                "PID": 8901,
                "Application": "nginx",
                "Service": "HTTPS",
                "Risk": "Low",
                "Description": "HTTPS service - Generally safe"
            }
        ]
    
    open_ports = []
    
    try:
        # Get all network connections
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            try:
                # Get only TCP connections in LISTEN state
                if conn.status == psutil.CONN_LISTEN and conn.type == socket.SOCK_STREAM:
                    port = conn.laddr.port
                    pid = conn.pid
                    
                    # Get port information
                    port_info = get_port_info(port, pid)
                    
                    # Get process name
                    if pid:
                        process_name = get_process_name(pid)
                    else:
                        process_name = "Unknown"
                    
                    # Add port information
                    port_data = {
                        "Port": port,
                        "PID": pid if pid else "N/A",
                        "Application": process_name,
                        "Service": port_info["name"],
                        "Risk": port_info["risk"],
                        "Description": port_info["description"]
                    }
                    
                    open_ports.append(port_data)
            
            except (psutil.AccessDenied, AttributeError, OSError) as e:
                # Access denied or information unavailable, continue
                continue
            except Exception as e:
                # Unexpected error, log but continue
                print(f"⚠️  Port scan error: {e}")
                continue
    
    except psutil.AccessDenied:
        print("❌ Administrator privileges required. Run as administrator for port scanning.")
        return []
    except Exception as e:
        print(f"❌ Critical error during port scan: {e}")
        return []
    
    # Sort by port number
    open_ports.sort(key=lambda x: x["Port"])
    
    return open_ports


def get_port_summary(ports: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Returns summary of port scan results
    
    Args:
        ports: List of port information
    
    Returns:
        dict: Summary statistics
    """
    summary = {
        "Total": len(ports),
        "High Risk": 0,
        "Low Risk": 0
    }
    
    for port_info in ports:
        if port_info.get("Risk") == "High" or port_info.get("Risk") == "Yüksek":
            summary["High Risk"] += 1
        else:
            summary["Low Risk"] += 1
    
    return summary

