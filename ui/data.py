"""Cached data loaders backing the dashboard (DB, rules, threat feed, heartbeat)."""

from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

import config
from db_manager import get_all_logs, get_heartbeat

# ui/data.py lives one level below the repo root, where rules/ sits.
_REPO_ROOT = Path(__file__).resolve().parent.parent


@st.cache_data(ttl=5)  # 5 second cache
def load_data() -> "pd.DataFrame":
    """Loads log data from database"""
    try:
        logs = get_all_logs(config.DB_PATH, limit=1000)

        if not logs:
            return pd.DataFrame()

        # Create DataFrame (including mitre_technique)
        df = pd.DataFrame(
            logs, columns=["ID", "Time", "Event ID", "Message", "AI Analysis", "Risk Level", "MITRE Technique"]
        )

        # Convert Time column to datetime
        try:
            df["Time"] = pd.to_datetime(df["Time"])
        except Exception:
            pass

        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=10)
def get_active_rule_count() -> int:
    """Counts enabled YAML detection rules on disk (cheap, cached)."""
    try:
        import yaml

        rules_dir = _REPO_ROOT / "rules"
        count = 0
        for f in list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            items = data if isinstance(data, list) else [data]
            for item in items:
                if isinstance(item, dict) and item.get("enabled", True):
                    count += 1
        return count
    except Exception:
        return 0


@st.cache_data(ttl=10)
def get_threat_feed_count() -> int:
    """Counts entries in the threat-intel feed (single IPs + CIDR ranges)."""
    try:
        from modules.threat_intel import ThreatIntel

        return ThreatIntel().get_threat_count()
    except Exception:
        return 0


def get_watcher_status() -> "tuple[str, str]":
    """
    Derive the log watcher's live status from its DB heartbeat.

    Returns:
        (css_class, label): "" / "stale" / "offline" and the badge text.
        A dashboard-only deployment (e.g. Docker) has no watcher and
        honestly shows "Watcher Offline".
    """
    last_seen = get_heartbeat("log_watcher", db_path=config.DB_PATH)
    if last_seen is not None:
        age = (datetime.now() - last_seen).total_seconds()
        if age <= 30:
            return "", "Monitoring Active"
        if age <= 300:
            return "stale", "Watcher Stale"
    return "offline", "Watcher Offline"
