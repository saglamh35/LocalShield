"""
LocalShield - Configuration File
Production-Ready: Updated with .env file support and type hints
"""
import os
from pathlib import Path
from typing import List

try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file
except ImportError:
    # Continue if python-dotenv is not available (default values will be used)
    pass


# Ollama Model Settings
MODEL_NAME: str = os.getenv("OLLAMA_MODEL_NAME", "gemma3:4b")

# Database Settings
DB_PATH: str = os.getenv("DB_PATH", "logs.db")

# Windows Event Log Settings
EVENT_LOG_NAME: str = os.getenv("EVENT_LOG_NAME", "Security")
SYSMON_LOG_NAME: str = os.getenv("SYSMON_LOG_NAME", "Microsoft-Windows-Sysmon/Operational")
MAX_LOGS_TO_READ: int = int(os.getenv("MAX_LOGS_TO_READ", "10"))

# Streamlit Dashboard Settings
DASHBOARD_TITLE: str = os.getenv("DASHBOARD_TITLE", "🛡️ LocalShield - AI-Powered Offline SIEM")
DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "8501"))

# Log Watcher Settings
CHECK_INTERVAL: int = int(os.getenv("CHECK_INTERVAL", "5"))  # seconds

# Logging Settings
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE: str = os.getenv("LOG_FILE", "localshield.log")

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
        current_user = os.environ.get('USERNAME') or os.environ.get('USER')
        if current_user and current_user not in SAFE_USERS:
            SAFE_USERS.append(current_user)
    except Exception:
        pass  # Continue if username cannot be retrieved
