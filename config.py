"""
LocalShield - Configuration File
Production-Ready: Updated with .env file support and type hints
"""

import os
from typing import List

try:
    from dotenv import load_dotenv

    load_dotenv()  # Load .env file
except ImportError:
    # Continue if python-dotenv is not available (default values will be used)
    pass


# Ollama Model Settings
MODEL_NAME: str = os.getenv("OLLAMA_MODEL_NAME", "gemma3:4b")
# Hard timeout (seconds) for a single Ollama request, so a hung/slow model
# cannot permanently occupy an analysis worker thread.
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "60"))

# Database Settings
DB_PATH: str = os.getenv("DB_PATH", "logs.db")

# Windows Event Log Settings
EVENT_LOG_NAME: str = os.getenv("EVENT_LOG_NAME", "Security")
SYSMON_LOG_NAME: str = os.getenv("SYSMON_LOG_NAME", "Microsoft-Windows-Sysmon/Operational")

# Streamlit Dashboard Settings
DASHBOARD_TITLE: str = os.getenv("DASHBOARD_TITLE", "🛡️ LocalShield - AI-Powered SIEM")

# Log Watcher Settings
CHECK_INTERVAL: int = int(os.getenv("CHECK_INTERVAL", "5"))  # seconds

# Logging Settings
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE: str = os.getenv("LOG_FILE", "localshield.log")

# Notification Settings (offline-first)
# Minimum severity that triggers a notification: Low | Medium | High
NOTIFY_MIN_SEVERITY: str = os.getenv("NOTIFY_MIN_SEVERITY", "High")
# Alert-log file: the always-on, fully-offline notification channel
ALERT_LOG_FILE: str = os.getenv("ALERT_LOG_FILE", "alerts.log")
# Desktop toast (opt-in, best-effort on Windows, offline)
NOTIFY_DESKTOP: bool = os.getenv("NOTIFY_DESKTOP", "False").lower() in ("true", "1", "yes")
# Webhook URL (opt-in, the ONLY networked channel; empty = disabled)
NOTIFY_WEBHOOK_URL: str = os.getenv("NOTIFY_WEBHOOK_URL", "")

# Incident grouping: window (seconds) within which same-key detections are
# rolled into one open incident instead of separate alerts.
INCIDENT_WINDOW: int = int(os.getenv("INCIDENT_WINDOW", "1800"))  # 30 minutes

# Demo Mode Settings
# Set to True to enable demo mode (generates fake data for screenshots)
DEMO_MODE: bool = os.getenv("DEMO_MODE", "False").lower() in ("true", "1", "yes")

# Firewall allowlist - critical IPs that must NEVER be auto-blocked.
# Prevents the active-response engine from cutting off DNS/gateway and locking
# you out. Extra IPs can be added via SAFE_IPS="a,b,c" (comma-separated).
SAFE_IPS: List[str] = [
    "8.8.8.8",
    "8.8.4.4",  # Google DNS
    "1.1.1.1",
    "1.0.0.1",  # Cloudflare DNS
]
_extra_safe_ips = os.getenv("SAFE_IPS", "")
if _extra_safe_ips:
    SAFE_IPS.extend(ip.strip() for ip in _extra_safe_ips.split(",") if ip.strip())

# Safe User List (Will be evaluated as Low Risk)
# System users and current user are automatically added
SAFE_USERS: List[str] = [
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "Administrator",  # Administrator accounts (for normal operations)
]

# Dynamic user detection - Automatically add current user
try:
    current_user = os.getlogin()
    if current_user and current_user not in SAFE_USERS:
        SAFE_USERS.append(current_user)
except Exception:
    # os.getlogin() may not work on some systems, try alternative methods
    try:
        current_user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if current_user and current_user not in SAFE_USERS:
            SAFE_USERS.append(current_user)
    except Exception:
        pass  # Continue if username cannot be retrieved
