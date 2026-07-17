"""Page assembly: header, KPI row, sidebar, tabs and the auto-refresh footer."""

from datetime import datetime

import pandas as pd
import streamlit as st
import streamlit.components.v1 as st_components

import config
from db_manager import (
    get_blocked_ips,
    get_high_risk_count,
    get_latest_detection,
    get_open_incident_count,
    get_total_log_count,
)
from modules.mitre import summarize as mitre_summarize
from ui.components import render_kpi
from ui.data import get_active_rule_count, get_threat_feed_count, get_watcher_status, load_data
from ui.sidebar import render_sidebar
from ui.theme import apply_theme
from ui.views import chat, incidents, logs, network_scan, response, traffic, vulnerabilities


def run() -> None:
    """Builds the whole dashboard page."""
    # Page configuration — must be the first Streamlit call.
    st.set_page_config(
        page_title="LocalShield Dashboard", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded"
    )
    apply_theme()

    # Pull the headline numbers once
    try:
        total_logs = get_total_log_count(config.DB_PATH)
        high_risk = get_high_risk_count(config.DB_PATH)
        latest = get_latest_detection(config.DB_PATH)
        blocked = get_blocked_ips(config.DB_PATH)
        rule_count = get_active_rule_count()
        feed_count = get_threat_feed_count()
        open_incidents = get_open_incident_count(config.DB_PATH)
    except Exception:
        total_logs = high_risk = rule_count = feed_count = open_incidents = 0
        latest = None
        blocked = []

    # Latest-detection label
    if latest:
        try:
            latest_str = pd.to_datetime(latest).strftime("%b %d, %H:%M")
        except Exception:
            latest_str = str(latest)
    else:
        latest_str = "No events yet"

    # --- Professional header with live status (driven by the watcher heartbeat) ---
    status_class, status_label = get_watcher_status()
    st.markdown(
        f"""
        <div class="ls-header">
            <span class="ls-badge-shield">🛡️</span>
            <div>
                <h1>LocalShield</h1>
                <div class="sub">AI-Powered Offline SIEM · Windows Event &amp; Network Threat Detection</div>
            </div>
            <div class="ls-status {status_class}"><span class="ls-dot"></span> {status_label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- KPI row (all core capabilities at a glance) ---
    # load_data() can return a column-less empty DataFrame (empty DB or load
    # error) even when the uncached total_logs count is non-zero, so guard the
    # column access instead of trusting total_logs.
    df_kpi = load_data()
    df_techniques = mitre_summarize(df_kpi["MITRE Technique"].tolist()) if "MITRE Technique" in df_kpi.columns else []
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    render_kpi(k1, "📊", "Total Events", f"{total_logs:,}", "ingested & analyzed", "var(--ls-info)")
    render_kpi(
        k2,
        "🚨",
        "High Risk",
        f"{high_risk:,}",
        f"{(high_risk / total_logs * 100):.0f}% of events" if total_logs else "none",
        "var(--ls-high)",
    )
    render_kpi(k3, "🔥", "Open Incidents", f"{open_incidents}", "need triage", "var(--ls-high)")
    render_kpi(k4, "🎯", "ATT&CK Techniques", f"{len(df_techniques)}", "detected", "var(--ls-accent)")
    render_kpi(k5, "⛔", "Blocked IPs", f"{len(blocked)}", "auto-response", "var(--ls-med)")
    render_kpi(k6, "🧠", "Active Rules", f"{rule_count}", f"{feed_count} threat-intel entries", "var(--ls-low)")

    st.caption(f"⏱️ Latest detection: **{latest_str}**  ·  🔒 Offline · local LLM · no data leaves this machine")
    st.markdown("")

    # Sidebar - Filters
    filters = render_sidebar()

    st.markdown("")

    # Tab structure
    tab_logs, tab_incidents, tab_response, tab_traffic, tab_network, tab_vulns, tab_chat = st.tabs(
        [
            "📋 Log Analysis",
            "🔥 Incidents",
            "🛡️ Active Response",
            "🌐 Network Traffic",
            "🔍 Network Scan",
            "🐞 Vulnerabilities",
            "💬 AI Assistant",
        ]
    )

    with tab_logs:
        logs.render(filters)

    with tab_incidents:
        incidents.render()

    with tab_response:
        response.render()

    with tab_traffic:
        traffic.render()

    with tab_network:
        network_scan.render()

    with tab_vulns:
        vulnerabilities.render()

    with tab_chat:
        chat.render()

    # Bottom section - refresh status + opt-in auto-refresh
    st.markdown("---")
    col_refresh1, col_refresh2, col_refresh3 = st.columns([1, 2, 1])
    with col_refresh2:
        current_time = datetime.now().strftime("%H:%M:%S")
        status = "on" if filters["auto_refresh"] else "off"
        st.caption(f"🔄 Last update: {current_time}  ·  Auto-refresh: {status}")

    # Auto-refresh is opt-in (sidebar toggle). When enabled, reload after 5s,
    # but never while the user is typing in the AI chat input.
    # NOTE: st.markdown never executes <script> tags, so this must go through
    # components.html, whose iframe does run scripts. The iframe is same-origin
    # (srcdoc), so window.parent reaches the actual dashboard page.
    if filters["auto_refresh"]:
        auto_refresh_script = """
        <script>
            setTimeout(function(){
                var doc = window.parent.document;
                var chatInput = doc.querySelector('[data-testid="stChatInput"] textarea');
                if (!chatInput || doc.activeElement !== chatInput) {
                    window.parent.location.reload();
                }
            }, 5000);
        </script>
        """
        st_components.html(auto_refresh_script, height=0)
