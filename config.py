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
# Delete security_logs / actions rows older than this many days.
# 0 (default) disables the purge entirely — nothing is ever deleted.
LOG_RETENTION_DAYS: int = int(os.getenv("LOG_RETENTION_DAYS", "0"))

# Windows Event Log Settings
EVENT_LOG_NAME: str = os.getenv("EVENT_LOG_NAME", "Security")
SYSMON_LOG_NAME: str = os.getenv("SYSMON_LOG_NAME", "Microsoft-Windows-Sysmon/Operational")

# Streamlit Dashboard Settings
DASHBOARD_TITLE: str = os.getenv("DASHBOARD_TITLE", "🛡️ LocalShield - AI-Powered SIEM")

# Log Watcher Settings
CHECK_INTERVAL: int = int(os.getenv("CHECK_INTERVAL", "5"))  # seconds

# Logging Settings
# Validated here: callers resolve this with getattr(logging, LOG_LEVEL),
# which would happily return any attribute of the logging module (e.g. a
# class) for a typo'd value instead of a level.
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "INFO"
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

# Active Response (SOAR) Settings
# Dry-run: run every safety check and audit record, but never execute a real
# firewall command. Useful for evaluating the response layer risk-free.
RESPONSE_DRY_RUN: bool = os.getenv("RESPONSE_DRY_RUN", "False").lower() in ("true", "1", "yes")
# Automatic block expiry in minutes. 0 (default) = blocks are permanent.
# With a value > 0, the watcher lifts each block after the duration elapses.
BLOCK_DURATION_MINUTES: int = int(os.getenv("BLOCK_DURATION_MINUTES", "0"))

# Vulnerability Scanning (Trivy-based, offline-first)
# LocalShield stays offline-first: Trivy's vulnerability DB is downloaded ONCE
# (e.g. `trivy image --download-db-only`) and then used air-gapped, exactly like
# the local Ollama model. The scanner degrades gracefully if Trivy is absent.
# Path to the Trivy binary (default: resolve 'trivy' on PATH).
TRIVY_PATH: str = os.getenv("TRIVY_PATH", "trivy")
# Directory holding the pre-downloaded Trivy DB (empty = Trivy's default cache).
TRIVY_CACHE_DIR: str = os.getenv("TRIVY_CACHE_DIR", "")
# Comma-separated container images to scan, e.g. "python:3.9-slim,nginx:1.18".
VULN_SCAN_IMAGES: List[str] = [img.strip() for img in os.getenv("VULN_SCAN_IMAGES", "").split(",") if img.strip()]
# Comma-separated filesystem paths to scan (host rootfs / project directories).
VULN_SCAN_PATHS: List[str] = [p.strip() for p in os.getenv("VULN_SCAN_PATHS", "").split(",") if p.strip()]
# Minimum CVE severity that triggers a per-scan notification: Low | Medium | High | Critical
VULN_NOTIFY_MIN_SEVERITY: str = os.getenv("VULN_NOTIFY_MIN_SEVERITY", "High")

# Vulnerability Remediation (Ansible-based SOAR, dry-run by default)
# Generates an Ansible playbook that upgrades the affected packages across the
# affected hosts. Honors RESPONSE_DRY_RUN: by default the playbook is rendered
# and audited but NEVER executed — review-before-run, like the firewall SOAR.
# Directory where generated remediation playbooks are written.
REMEDIATION_OUTPUT_DIR: str = os.getenv("REMEDIATION_OUTPUT_DIR", ".")
# Path to the ansible-playbook binary (default: resolve on PATH).
ANSIBLE_PLAYBOOK_PATH: str = os.getenv("ANSIBLE_PLAYBOOK_PATH", "ansible-playbook")

# Metrics Exporter (Prometheus text-exposition, offline-first)
# Exposes LocalShield SIEM + vulnerability KPIs at http://METRICS_HOST:METRICS_PORT/metrics
# for a Prometheus scrape + Grafana dashboard. Stdlib http.server only — no new deps.
# Binds localhost by default; expose wider only behind a trusted network/proxy.
METRICS_HOST: str = os.getenv("METRICS_HOST", "127.0.0.1")
METRICS_PORT: int = int(os.getenv("METRICS_PORT", "9109"))

# Firewall allowlist - critical IPs that must NEVER be auto-blocked.
# Prevents the active-response engine from cutting off DNS/gateway and locking
# you out. Extra IPs can be added via SAFE_IPS="a,b,c" (comma-separated).
SAFE_IPS: List[str] = [
    "8.8.8.8",
    "8.8.4.4",  # Google DNS (IPv4)
    "1.1.1.1",
    "1.0.0.1",  # Cloudflare DNS (IPv4)
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",  # Google DNS (IPv6)
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",  # Cloudflare DNS (IPv6)
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
