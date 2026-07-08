"""
Streamlit Dashboard - LocalShield Professional SIEM Interface
"""

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

import config
from db_manager import (
    clear_all_logs,
    get_all_logs,
    get_blocked_ips,
    get_high_risk_count,
    get_incidents,
    get_latest_detection,
    get_open_incident_count,
    get_recent_actions,
    get_total_log_count,
    get_vulnerabilities,
    get_vulnerability_counts,
)
from modules.chat_manager import ask_assistant
from modules.mitre import summarize as mitre_summarize
from modules.network_scanner import get_port_summary, scan_open_ports
from modules.packet_capture import PacketSniffer

# Page configuration
st.set_page_config(page_title="LocalShield Dashboard", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# Custom CSS - Professional SOC console design
st.markdown(
    """
<style>
    :root {
        --ls-accent: #2dd4bf;
        --ls-bg: #0d1117;
        --ls-surface: #161b22;
        --ls-surface-2: #1c2230;
        --ls-line: #2a323d;
        --ls-text: #e6edf3;
        --ls-muted: #8b949e;
        --ls-high: #f85149;
        --ls-med: #e3a008;
        --ls-low: #3fb950;
        --ls-info: #58a6ff;
    }

    /* Base */
    .stApp { background: var(--ls-bg); }
    .block-container { padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1400px; }
    h1, h2, h3, h4 { letter-spacing: -0.01em; }
    hr { border-color: var(--ls-line) !important; }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: var(--ls-surface);
        border-right: 1px solid var(--ls-line);
    }
    [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { font-size: 0.95rem; }

    /* Tabs -> pill/underline bar */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background: var(--ls-surface);
        padding: 5px;
        border-radius: 12px;
        border: 1px solid var(--ls-line);
    }
    .stTabs [data-baseweb="tab"] {
        height: 40px;
        border-radius: 8px;
        padding: 0 16px;
        color: var(--ls-muted);
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background: var(--ls-surface-2) !important;
        color: var(--ls-accent) !important;
    }

    /* Native metric cards */
    [data-testid="stMetric"] {
        background: var(--ls-surface);
        border: 1px solid var(--ls-line);
        border-radius: 12px;
        padding: 14px 18px;
    }
    [data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; }

    /* Expanders / log cards */
    [data-testid="stExpander"] {
        border: 1px solid var(--ls-line);
        border-radius: 10px;
        margin-bottom: 8px;
        background: var(--ls-surface);
    }
    [data-testid="stExpander"] summary:hover { color: var(--ls-accent); }

    /* Buttons */
    .stButton > button {
        border-radius: 9px;
        border: 1px solid var(--ls-line);
        font-weight: 600;
    }
    .stButton > button:hover { border-color: var(--ls-accent); color: var(--ls-accent); }

    /* Risk text helpers */
    .risk-high { color: var(--ls-high); font-weight: 700; }
    .risk-medium { color: var(--ls-med); font-weight: 700; }
    .risk-low { color: var(--ls-low); font-weight: 700; }

    /* ---- Custom LocalShield components ---- */
    .ls-header {
        display: flex; align-items: center; gap: 16px;
        padding: 18px 22px; margin-bottom: 6px;
        background: linear-gradient(120deg, var(--ls-surface) 0%, #10202a 100%);
        border: 1px solid var(--ls-line); border-radius: 16px;
        position: relative; overflow: hidden;
    }
    .ls-header::before {
        content:""; position:absolute; left:0; top:0; bottom:0; width:4px;
        background: var(--ls-accent);
    }
    .ls-badge-shield { font-size: 2.1rem; line-height: 1; }
    .ls-header h1 { margin: 0; font-size: 1.7rem; color: var(--ls-text); }
    .ls-header .sub { color: var(--ls-muted); font-size: 0.9rem; margin-top: 2px; }
    .ls-status {
        margin-left: auto; display: flex; align-items: center; gap: 8px;
        font-size: 0.82rem; color: var(--ls-low); font-weight: 600;
        background: rgba(63,185,80,.1); border: 1px solid rgba(63,185,80,.3);
        padding: 6px 12px; border-radius: 20px; white-space: nowrap;
    }
    .ls-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ls-low);
        box-shadow: 0 0 0 0 rgba(63,185,80,.6); animation: lspulse 2s infinite; }
    @keyframes lspulse {
        0% { box-shadow: 0 0 0 0 rgba(63,185,80,.5); }
        70% { box-shadow: 0 0 0 7px rgba(63,185,80,0); }
        100% { box-shadow: 0 0 0 0 rgba(63,185,80,0); }
    }
    @media (prefers-reduced-motion: reduce) { .ls-dot { animation: none; } }

    .ls-kpi {
        background: var(--ls-surface); border: 1px solid var(--ls-line);
        border-radius: 13px; padding: 15px 17px; height: 100%;
        border-top: 3px solid var(--kpi-accent, var(--ls-accent));
    }
    .ls-kpi .k-top { display:flex; align-items:center; justify-content:space-between; }
    .ls-kpi .k-ico { font-size: 1.15rem; opacity: .9; }
    .ls-kpi .k-label { color: var(--ls-muted); font-size: .74rem; text-transform: uppercase;
        letter-spacing: .06em; font-weight: 600; }
    .ls-kpi .k-val { font-size: 1.9rem; font-weight: 750; line-height: 1.1; margin-top: 6px;
        font-variant-numeric: tabular-nums; color: var(--ls-text); }
    .ls-kpi .k-foot { color: var(--ls-muted); font-size: .76rem; margin-top: 3px; }

    .ls-chip {
        display:inline-block; font-size:.72rem; font-weight:700; padding:3px 9px;
        border-radius: 6px; letter-spacing:.03em;
    }
    .chip-high { color: var(--ls-high); background: rgba(248,81,73,.13); }
    .chip-med  { color: var(--ls-med);  background: rgba(227,160,8,.13); }
    .chip-low  { color: var(--ls-low);  background: rgba(63,185,80,.13); }

    .ls-ip-card {
        display:flex; align-items:center; gap:12px;
        background: var(--ls-surface); border:1px solid var(--ls-line);
        border-left: 3px solid var(--ls-high); border-radius: 10px;
        padding: 12px 15px; margin-bottom: 8px;
    }
    .ls-ip-card .ip { font-family: ui-monospace, Menlo, monospace; font-weight:700; font-size:.98rem; }
    .ls-ip-card .meta { color: var(--ls-muted); font-size:.8rem; }
    .ls-ip-card .tag { margin-left:auto; font-size:.72rem; color: var(--ls-high);
        background: rgba(248,81,73,.12); padding:3px 9px; border-radius:6px; font-weight:700; }
</style>
""",
    unsafe_allow_html=True,
)


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

        rules_dir = Path(__file__).parent / "rules"
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


def render_kpi(column, icon, label, value, foot="", accent="var(--ls-accent)") -> None:
    """Renders a single professional KPI card into the given column."""
    column.markdown(
        f"""
        <div class="ls-kpi" style="--kpi-accent:{accent}">
            <div class="k-top">
                <span class="k-label">{label}</span>
                <span class="k-ico">{icon}</span>
            </div>
            <div class="k-val">{value}</div>
            <div class="k-foot">{foot}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_risk_icon(risk_level) -> str:
    """Returns icon based on risk level"""
    if pd.isna(risk_level):
        return "❓"

    risk_str = str(risk_level).strip().lower()
    if "high" in risk_str or "yüksek" in risk_str:
        return "🔴"
    elif "medium" in risk_str or "orta" in risk_str:
        return "🟠"
    elif "low" in risk_str or "düşük" in risk_str:
        return "🟢"
    return "⚪"


def get_risk_color_class(risk_level) -> str:
    """Returns CSS class based on risk level"""
    if pd.isna(risk_level):
        return ""

    risk_str = str(risk_level).strip().lower()
    if "high" in risk_str or "yüksek" in risk_str:
        return "risk-high"
    elif "medium" in risk_str or "orta" in risk_str:
        return "risk-medium"
    elif "low" in risk_str or "düşük" in risk_str:
        return "risk-low"
    return ""


def translate_risk_level(risk_level) -> str:
    """
    Translates Turkish risk levels to English for UI display.

    Args:
        risk_level: Risk level string (can be Turkish or English)

    Returns:
        str: English risk level
    """
    if pd.isna(risk_level):
        return "Unspecified"

    risk_str = str(risk_level).strip()
    risk_lower = risk_str.lower()

    # Turkish to English mapping
    if "yüksek" in risk_lower or "high" in risk_lower:
        return "High"
    elif "orta" in risk_lower or "medium" in risk_lower:
        return "Medium"
    elif "düşük" in risk_lower or "low" in risk_lower:
        return "Low"
    elif "critical" in risk_lower:
        return "Critical"

    # If already in English, capitalize properly
    if risk_str.lower() in ["high", "medium", "low", "critical"]:
        return risk_str.capitalize()

    return risk_str  # Return as-is if unknown


def filter_data(df, risk_filters, event_id_filter, text_search=None, date_range=None) -> "pd.DataFrame":
    """Filters data"""
    filtered_df = df.copy()

    # Date-range filter (inclusive). date_range is (start_date, end_date) or None.
    if date_range and "Time" in filtered_df.columns:
        try:
            start, end = date_range
            if start is not None and end is not None:
                times = pd.to_datetime(filtered_df["Time"], errors="coerce")
                start_ts = pd.Timestamp(start)
                end_ts = pd.Timestamp(end) + pd.Timedelta(days=1)  # inclusive end day
                filtered_df = filtered_df[(times >= start_ts) & (times < end_ts)]
        except Exception:
            pass

    # Risk level filter
    if risk_filters:
        filtered_df = filtered_df[filtered_df["Risk Level"].str.contains("|".join(risk_filters), case=False, na=False)]

    # Event ID filter
    if event_id_filter:
        filtered_df = filtered_df[
            filtered_df["Event ID"].astype(str).str.contains(event_id_filter, case=False, na=False)
        ]

    # Advanced Search (Text Search) - Search in Message, AI Analysis, MITRE Technique
    if text_search and text_search.strip():
        search_term = text_search.strip().lower()
        mask = (
            filtered_df["Message"].astype(str).str.lower().str.contains(search_term, na=False)
            | filtered_df["AI Analysis"].astype(str).str.lower().str.contains(search_term, na=False)
            | filtered_df["MITRE Technique"].astype(str).str.lower().str.contains(search_term, na=False)
        )
        filtered_df = filtered_df[mask]

    return filtered_df


def create_timeline_chart(df) -> Any:
    """Log intensity chart by timeline (Area Chart)"""
    if df.empty or "Time" not in df.columns:
        return None

    try:
        # Group by timestamp (15-minute intervals)
        df_chart = df.copy()

        # Convert Time column to datetime (if not already)
        if not pd.api.types.is_datetime64_any_dtype(df_chart["Time"]):
            df_chart["Time"] = pd.to_datetime(df_chart["Time"], errors="coerce")

        # Filter invalid dates
        df_chart = df_chart[df_chart["Time"].notna()]

        if df_chart.empty:
            return None

        # Split into 15-minute intervals
        df_chart["Time_Interval"] = df_chart["Time"].dt.floor("15min")
        timeline_data = df_chart.groupby("Time_Interval").size().reset_index(name="Log Count")

        chart = (
            alt.Chart(timeline_data)
            .mark_area(interpolate="monotone", fillOpacity=0.6, stroke="#1f77b4", strokeWidth=2)
            .encode(
                x=alt.X("Time_Interval:T", title="Time", axis=alt.Axis(format="%H:%M")),
                y=alt.Y("Log Count:Q", title="Log Count"),
                tooltip=[
                    alt.Tooltip("Time_Interval:T", format="%Y-%m-%d %H:%M", title="Time"),
                    alt.Tooltip("Log Count:Q", title="Log Count"),
                ],
            )
            .properties(height=300, title="Log Intensity by Timeline")
            .configure_axis(gridColor="rgba(255,255,255,0.1)")
            .configure_view(strokeWidth=0)
        )

        return chart
    except Exception:
        # Silently ignore error (show empty chart)
        return None


def create_risk_distribution_chart(df) -> Any:
    """Risk level distribution chart (Donut Chart)"""
    if df.empty or "Risk Level" not in df.columns:
        return None

    try:
        # Normalize risk levels
        df_chart = df.copy()
        df_chart["Risk_Level_Normal"] = df_chart["Risk Level"].apply(
            lambda x: (
                "High"
                if "high" in str(x).lower() or "yüksek" in str(x).lower()
                else "Medium"
                if "medium" in str(x).lower() or "orta" in str(x).lower()
                else "Low"
                if "low" in str(x).lower() or "düşük" in str(x).lower()
                else "Unspecified"
            )
        )

        risk_counts = df_chart["Risk_Level_Normal"].value_counts().reset_index()
        risk_counts.columns = ["Risk Level", "Count"]

        # Color palette
        color_map = {"High": "#ff4444", "Medium": "#ffaa00", "Low": "#44ff44", "Unspecified": "#888888"}
        risk_counts["Color"] = risk_counts["Risk Level"].map(color_map).fillna("#888888")

        chart = (
            alt.Chart(risk_counts)
            .mark_arc(innerRadius=60, outerRadius=120)
            .encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(
                    field="Risk Level",
                    type="nominal",
                    scale=alt.Scale(domain=risk_counts["Risk Level"].tolist(), range=risk_counts["Color"].tolist()),
                    legend=alt.Legend(title="Risk Level"),
                ),
                tooltip=["Risk Level:N", "Count:Q"],
            )
            .properties(height=300, title="Risk Level Distribution")
        )

        return chart
    except Exception as e:
        st.error(f"Error creating risk distribution chart: {e}")
        return None


def create_mitre_chart(df) -> tuple:
    """
    MITRE ATT&CK coverage: detected techniques as a horizontal bar chart,
    coloured by tactic. Returns (chart, summary_rows) or (None, []).
    """
    if df.empty or "MITRE Technique" not in df.columns:
        return None, []

    try:
        rows = mitre_summarize(df["MITRE Technique"].tolist())
        if not rows:
            return None, []

        chart_df = pd.DataFrame(rows)
        chart_df["label"] = chart_df["id"] + " – " + chart_df["name"]

        chart = (
            alt.Chart(chart_df)
            .mark_bar()
            .encode(
                x=alt.X("count:Q", title="Detections"),
                y=alt.Y("label:N", title="Technique", sort="-x"),
                color=alt.Color("tactic:N", title="Tactic"),
                tooltip=[
                    alt.Tooltip("id:N", title="Technique"),
                    alt.Tooltip("name:N", title="Name"),
                    alt.Tooltip("tactic:N", title="Tactic"),
                    alt.Tooltip("count:Q", title="Detections"),
                ],
            )
            .properties(
                height=max(200, 32 * len(chart_df)),
                title="MITRE ATT&CK Techniques Detected",
            )
        )
        return chart, rows
    except Exception:
        return None, []


def render_log_card(row) -> None:
    """Renders a log entry as a card"""
    risk_level_raw = str(row.get("Risk Level", "Unspecified"))
    risk_level_en = translate_risk_level(risk_level_raw)  # Translate to English
    risk_icon = get_risk_icon(risk_level_raw)  # Icon based on original (works with both)
    risk_class = get_risk_color_class(risk_level_raw)  # CSS class based on original

    # Time format
    try:
        if pd.notna(row.get("Time")):
            if isinstance(row["Time"], pd.Timestamp):
                time_str = row["Time"].strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(row["Time"], str):
                # If string, parse it
                try:
                    dt = pd.to_datetime(row["Time"])
                    time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    time_str = row["Time"]
            else:
                time_str = str(row["Time"])
        else:
            time_str = "Unknown"
    except Exception:
        time_str = str(row.get("Time", "Unknown"))

    event_id = str(row.get("Event ID", "N/A"))

    # Get MITRE technique
    mitre_technique = row.get("MITRE Technique", None)
    mitre_display = ""
    if mitre_technique and pd.notna(mitre_technique) and str(mitre_technique).strip():
        mitre_display = f" 🔴 {mitre_technique}"

    # Create header - use English risk level
    header = f"{risk_icon} {time_str} - {risk_level_en}{mitre_display} - Event ID: {event_id}"

    # Expander content
    with st.expander(header, expanded=False):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("**📋 Event Details**")
            st.write(f"**ID:** `{row.get('ID', 'N/A')}`")
            st.write(f"**Event ID:** `{event_id}`")
            st.write(f"**Time:** `{time_str}`")
            risk_display = f"<span class='{risk_class}'>**{risk_level_en}** {risk_icon}</span>"
            st.markdown(f"**Risk Level:** {risk_display}", unsafe_allow_html=True)

            # Show MITRE Technique
            if mitre_technique and pd.notna(mitre_technique) and str(mitre_technique).strip():
                st.markdown(f"**🔴 MITRE ATT&CK:** `{mitre_technique}`")

        with col2:
            st.markdown("**🤖 AI Analysis**")
            ai_analysis = str(row.get("AI Analysis", "No analysis"))
            if ai_analysis and ai_analysis != "No analysis":
                # Convert AI analysis to more readable format
                st.info(f"💭 {ai_analysis}")
            else:
                st.warning("⚠️ Analysis not found")

        st.markdown("---")
        st.markdown("**📝 Full Message**")
        message = str(row.get("Message", "No message"))
        if message and len(message) > 0:
            # Make message more readable
            st.code(message, language=None)
        else:
            st.caption("No message content available.")


def main() -> None:
    """Main dashboard function"""

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

    # --- Professional header with live status ---
    st.markdown(
        """
        <div class="ls-header">
            <span class="ls-badge-shield">🛡️</span>
            <div>
                <h1>LocalShield</h1>
                <div class="sub">AI-Powered Offline SIEM · Windows Event &amp; Network Threat Detection</div>
            </div>
            <div class="ls-status"><span class="ls-dot"></span> Monitoring Active</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- KPI row (all core capabilities at a glance) ---
    df_techniques = mitre_summarize(load_data()["MITRE Technique"].tolist()) if total_logs else []
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
    with st.sidebar:
        st.header("🔍 Filters")

        # Risk level filter
        risk_options = ["High", "Medium", "Low"]
        selected_risks = st.multiselect("Risk Level", options=risk_options, default=[])

        # Event ID filter
        event_id_filter = st.text_input("Event ID", placeholder="E.g.: 4625, 4624...")

        # Advanced Search (Text Search)
        text_search = st.text_input(
            "🔎 Advanced Search", placeholder="Search in Message, AI Analysis or MITRE Technique..."
        )

        # Date-range filter (optional)
        use_date_filter = st.checkbox("📅 Filter by date range", value=False)
        date_range = None
        if use_date_filter:
            date_range = st.date_input("Date range", value=(), help="Pick a start and end date to narrow the logs.")
            # st.date_input returns a tuple only once both ends are chosen
            if not (isinstance(date_range, (tuple, list)) and len(date_range) == 2):
                date_range = None

        # Log page size (pagination)
        page_size = st.selectbox("Logs per page", options=[10, 25, 50, 100], index=1)

        st.markdown("---")
        st.caption("💡 Clear selections to reset filters.")

        # Live view
        st.markdown("---")
        st.header("🔄 Live View")
        auto_refresh = st.checkbox(
            "Auto-refresh (5s)",
            value=False,
            help="Periodically reload the Log and Network tabs. Leave off while reading or using the AI chat.",
        )

        # Clear Database Button
        st.markdown("---")
        st.header("⚙️ Management")

        # Session state for confirmation check
        if "confirm_reset" not in st.session_state:
            st.session_state.confirm_reset = False

        if not st.session_state.confirm_reset:
            if st.button("🗑️ Clear Database", type="secondary", use_container_width=True):
                st.session_state.confirm_reset = True
                st.rerun()
        else:
            st.warning("⚠️ All log entries will be deleted! This action cannot be undone.")
            col_confirm1, col_confirm2 = st.columns(2)
            with col_confirm1:
                if st.button("✅ Confirm", type="primary", use_container_width=True):
                    if clear_all_logs(config.DB_PATH):
                        st.session_state.confirm_reset = False
                        st.success("✅ Database cleared successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Error clearing database.")
            with col_confirm2:
                if st.button("❌ Cancel", use_container_width=True):
                    st.session_state.confirm_reset = False
                    st.rerun()

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
        # Log Analysis tab
        # Charts
        df = load_data()

        if not df.empty:
            # Chart row
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                timeline_chart = create_timeline_chart(df)
                if timeline_chart:
                    st.altair_chart(timeline_chart, use_container_width=True)
                else:
                    st.info("Could not create timeline chart.")

            with chart_col2:
                risk_chart = create_risk_distribution_chart(df)
                if risk_chart:
                    st.altair_chart(risk_chart, use_container_width=True)
                else:
                    st.info("Could not create risk distribution chart.")

            # MITRE ATT&CK coverage
            mitre_chart, mitre_rows = create_mitre_chart(df)
            if mitre_chart is not None:
                st.markdown("---")
                st.subheader("🎯 MITRE ATT&CK Coverage")
                tactics = sorted({r["tactic"] for r in mitre_rows})
                mc1, mc2 = st.columns([3, 1])
                with mc1:
                    st.altair_chart(mitre_chart, use_container_width=True)
                with mc2:
                    st.metric("Techniques", len(mitre_rows))
                    st.metric("Tactics", len(tactics))
                    st.caption("Tactics observed: " + ", ".join(tactics))

            st.markdown("---")

            # Filtering
            filtered_df = filter_data(df, selected_risks, event_id_filter, text_search, date_range)

            # Add Severity column (map from Risk Level)
            if not filtered_df.empty and "Risk Level" in filtered_df.columns:
                filtered_df["Severity"] = filtered_df["Risk Level"].apply(
                    lambda x: (
                        "Critical"
                        if "high" in str(x).lower() or "yüksek" in str(x).lower()
                        else "High"
                        if "high" in str(x).lower()
                        else "Medium"
                        if "medium" in str(x).lower() or "orta" in str(x).lower()
                        else "Low"
                        if "low" in str(x).lower() or "düşük" in str(x).lower()
                        else "Unspecified"
                    )
                )

            # CSV Download Button and Log Header
            col_header1, col_header2 = st.columns([3, 1])
            with col_header1:
                st.subheader(f"📋 Security Logs ({len(filtered_df)} entries)")
            with col_header2:
                if not filtered_df.empty:
                    # Download as CSV
                    csv = filtered_df.to_csv(index=False, encoding="utf-8-sig")
                    st.download_button(
                        label="📥 Download as CSV",
                        data=csv,
                        file_name=f"localshield_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )

            if filtered_df.empty:
                st.info("🔍 No logs found matching filter criteria.")
            else:
                # Prepare display dataframe with selected columns
                display_columns = ["Time", "Event ID", "Severity", "Risk Level", "MITRE Technique", "Message"]
                available_columns = [col for col in display_columns if col in filtered_df.columns]
                display_df = filtered_df[available_columns].copy()

                # Translate Risk Level and Severity columns to English
                if "Risk Level" in display_df.columns:
                    display_df["Risk Level"] = display_df["Risk Level"].apply(translate_risk_level)
                if "Severity" in display_df.columns:
                    display_df["Severity"] = display_df["Severity"].apply(translate_risk_level)

                # Highlight high/critical risk rows
                def highlight_risk(row):
                    risk = str(row.get("Severity", row.get("Risk Level", ""))).lower()
                    if "high" in risk or "critical" in risk:
                        return ["background-color: #ff4444; color: white; font-weight: bold;"] * len(row)
                    elif "medium" in risk:
                        return ["background-color: #ffaa00; color: white;"] * len(row)
                    return [""] * len(row)

                # Display table in expander (collapsed by default)
                with st.expander("🔍 Show Raw Data / Table View", expanded=False):
                    st.dataframe(
                        display_df.style.apply(highlight_risk, axis=1),
                        use_container_width=True,
                        hide_index=True,
                        height=400,
                    )

                st.markdown("---")

                # Create card for each log (paginated to keep the page responsive)
                st.subheader("📋 Log Entries")
                total = len(filtered_df)
                total_pages = max(1, (total + page_size - 1) // page_size)

                page = 1
                if total_pages > 1:
                    page = st.number_input(
                        f"Page (1–{total_pages}, {page_size}/page)", min_value=1, max_value=total_pages, value=1, step=1
                    )

                start_idx = (int(page) - 1) * page_size
                end_idx = start_idx + page_size
                page_df = filtered_df.iloc[start_idx:end_idx]
                st.caption(f"Showing {start_idx + 1}–{min(end_idx, total)} of {total} entries")

                for idx, row in page_df.iterrows():
                    render_log_card(row)
        else:
            st.info("📭 No log entries found yet. Make sure the log watcher is running.")

    # --- INCIDENTS ---
    with tab_incidents:
        st.subheader("🔥 Incidents")
        st.caption(
            "Related high-risk detections grouped by source IP (or rule) within a time window — triage incidents, not a flat stream of events."
        )

        try:
            all_incidents = get_incidents(limit=200, db_path=config.DB_PATH)
        except Exception as e:
            all_incidents = []
            st.error(f"Could not load incidents: {e}")

        open_inc = [i for i in all_incidents if i[7] == "open"]
        i1, i2, i3 = st.columns(3)
        render_kpi(i1, "🔥", "Open Incidents", f"{len(open_inc)}", "need triage", "var(--ls-high)")
        render_kpi(i2, "📁", "Total Incidents", f"{len(all_incidents)}", "all time", "var(--ls-info)")
        total_grouped = sum(i[5] for i in all_incidents)
        render_kpi(i3, "🧩", "Events Grouped", f"{total_grouped}", "into incidents", "var(--ls-accent)")
        st.markdown("")

        if all_incidents:
            sev_chip = {"critical": "chip-high", "high": "chip-high", "medium": "chip-med", "low": "chip-low"}
            for inc_id, key, title, first_seen, last_seen, count, max_sev, status in all_incidents:
                sev = str(max_sev or "medium").lower()
                chip = sev_chip.get(sev, "chip-med")
                border = "var(--ls-high)" if sev in ("high", "critical") else "var(--ls-med)"
                status_badge = "🟢 open" if status == "open" else "⚪ closed"
                st.markdown(
                    f"""
                    <div class="ls-ip-card" style="border-left-color:{border}">
                        <div>
                            <div class="ip">#{inc_id} · {key}</div>
                            <div class="meta">{(title or "Incident")[:90]}</div>
                            <div class="meta">{count} event(s) · {first_seen} → {last_seen} · {status_badge}</div>
                        </div>
                        <span class="ls-chip {chip}" style="margin-left:auto">{sev.upper()}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("✅ No incidents yet. High-risk detections will be grouped here as they occur.")

    # --- ACTIVE RESPONSE (SOAR) ---
    with tab_response:
        st.subheader("🛡️ Active Response (SOAR)")
        st.caption(
            "Automated Windows Firewall actions — IPs blocked in response to high-risk events, with a full audit trail."
        )

        try:
            blocked_ips = get_blocked_ips(config.DB_PATH)
            actions = get_recent_actions(limit=100, db_path=config.DB_PATH)
        except Exception as e:
            blocked_ips, actions = [], []
            st.error(f"Could not load response data: {e}")

        r1, r2, r3 = st.columns(3)
        render_kpi(r1, "⛔", "Currently Blocked", f"{len(blocked_ips)}", "firewall rules active", "var(--ls-high)")
        render_kpi(r2, "📜", "Logged Actions", f"{len(actions)}", "audit-trail entries", "var(--ls-info)")
        render_kpi(
            r3,
            "🔐",
            "Allowlisted IPs",
            f"{len(getattr(config, 'SAFE_IPS', []))}",
            "never auto-blocked",
            "var(--ls-low)",
        )
        st.markdown("")

        col_block, col_audit = st.columns([1, 1])

        with col_block:
            st.markdown("##### ⛔ Blocked IP Addresses")
            if blocked_ips:
                for ip, rule_name, blocked_at, reason in blocked_ips:
                    when = str(blocked_at or "")
                    st.markdown(
                        f"""
                        <div class="ls-ip-card">
                            <div>
                                <div class="ip">{ip}</div>
                                <div class="meta">{reason or "Blocked"} · {when}</div>
                            </div>
                            <span class="tag">{rule_name or "BLOCKED"}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.info("✅ No IPs are currently blocked. High-risk events with a hostile source IP will appear here.")

        with col_audit:
            st.markdown("##### 📜 Response Audit Trail")
            if actions:
                audit_df = pd.DataFrame(actions, columns=["ID", "Time", "Action", "Target", "Details"])
                audit_df = audit_df[["Time", "Action", "Target", "Details"]]
                st.dataframe(audit_df, use_container_width=True, hide_index=True, height=360)
            else:
                st.info("No automated actions recorded yet.")

        st.markdown("---")
        st.caption(
            "🔒 **Safety by design:** block targets are taken only from structured source-address fields "
            "(never a blanket text scan), private IPs and an allowlist of critical addresses (DNS/gateway) "
            "are never blocked, and every action is persisted for audit."
        )

    # --- NETWORK TRAFFIC ---
    with tab_traffic:
        st.subheader("🌐 Network Traffic Monitor")
        st.caption("Real-time packet capture and analysis (Wireshark-like view)")

        # Initialize sniffer in session state
        if "sniffer" not in st.session_state:
            try:
                st.session_state.sniffer = PacketSniffer(max_packets=1000)
                st.session_state.sniffer_running = False
            except Exception as e:
                st.error(f"❌ Error initializing packet sniffer: {e}")
                st.info("💡 Make sure Npcap is installed and you're running as Administrator.")
                st.session_state.sniffer = None
                st.session_state.sniffer_running = False

        # Control Panel
        col_control1, col_control2, col_control3 = st.columns([2, 1, 1])

        with col_control1:
            # Status display
            if st.session_state.sniffer and st.session_state.sniffer_running:
                stats = st.session_state.sniffer.get_traffic_stats()
                interface = stats.get("interface", "Unknown")
                # Try to get IP from interface
                try:
                    from scapy.all import get_if_addr

                    ip = get_if_addr(interface) if interface else "Unknown"
                    st.success(f"🟢 **Listening on** {interface[:50]}... (IP: {ip})")
                except Exception:
                    st.success(f"🟢 **Listening on** {interface[:50]}...")
            elif st.session_state.sniffer:
                st.info("⚪ **Stopped** - Click 'Start Sniffer' to begin capturing packets")
            else:
                st.error("❌ **Sniffer not available**")

        with col_control2:
            if st.session_state.sniffer:
                if not st.session_state.sniffer_running:
                    if st.button("🟢 Start Sniffer", type="primary", use_container_width=True):
                        try:
                            st.session_state.sniffer.start()
                            st.session_state.sniffer_running = True
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error starting sniffer: {e}")
                else:
                    if st.button("🔴 Stop Sniffer", type="secondary", use_container_width=True):
                        try:
                            st.session_state.sniffer.stop()
                            st.session_state.sniffer_running = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error stopping sniffer: {e}")

        with col_control3:
            if st.session_state.sniffer and st.session_state.sniffer_running:
                # PCAP download button - simplified version
                if st.button("📥 Capture PCAP (30s)", use_container_width=True):
                    try:
                        import os
                        import tempfile

                        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
                        temp_file.close()

                        # Capture for 30 seconds (async)
                        with st.spinner("⏳ Capturing packets for 30 seconds..."):
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            try:
                                filepath = loop.run_until_complete(
                                    st.session_state.sniffer.start_capture_to_file(temp_file.name, duration=30.0)
                                )

                                # Read file and provide download
                                if os.path.exists(filepath):
                                    with open(filepath, "rb") as f:
                                        pcap_data = f.read()

                                    st.download_button(
                                        label="📥 Download PCAP File",
                                        data=pcap_data,
                                        file_name=f"localshield_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
                                        mime="application/vnd.tcpdump.pcap",
                                        use_container_width=True,
                                    )
                                    os.unlink(filepath)  # Clean up
                            finally:
                                loop.close()
                    except Exception as e:
                        st.error(f"Error capturing PCAP: {e}")

        st.markdown("---")

        # Metrics
        if st.session_state.sniffer:
            stats = st.session_state.sniffer.get_traffic_stats()

            col_metric1, col_metric2, col_metric3 = st.columns(3)

            with col_metric1:
                total_packets = stats.get("total_packets", 0)
                st.metric("📦 Total Packets", total_packets)

            with col_metric2:
                active_ips = len(
                    set(
                        [ip["ip"] for ip in stats.get("top_source_ips", [])]
                        + [ip["ip"] for ip in stats.get("top_dest_ips", [])]
                    )
                )
                st.metric("🌐 Active IPs", active_ips)

            with col_metric3:
                buffer_usage = stats.get("packets_in_buffer", 0)
                buffer_max = st.session_state.sniffer.max_packets
                buffer_pct = (buffer_usage / buffer_max * 100) if buffer_max > 0 else 0
                st.metric("💾 Buffer Usage", f"{buffer_usage}/{buffer_max} ({buffer_pct:.1f}%)")

            st.markdown("---")

            # Live Packet Table
            st.subheader("📋 Recent Packets")
            try:
                recent_packets_df = st.session_state.sniffer.get_recent_packets(count=50)

                if not recent_packets_df.empty:
                    st.dataframe(recent_packets_df, use_container_width=True, hide_index=True, height=400)
                else:
                    st.info("📭 No packets captured yet. Start the sniffer and generate some network traffic.")
            except Exception as e:
                st.error(f"Error loading packets: {e}")

            st.markdown("---")

            # Charts
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                st.subheader("🔝 Top Source IPs")
                top_source_ips = stats.get("top_source_ips", [])[:10]
                if top_source_ips:
                    source_df = pd.DataFrame(top_source_ips)
                    source_chart = (
                        alt.Chart(source_df)
                        .mark_bar()
                        .encode(
                            x=alt.X("count:Q", title="Packet Count"),
                            y=alt.Y("ip:N", title="Source IP", sort="-x"),
                            tooltip=["ip:N", "count:Q"],
                        )
                        .properties(height=300, title="Top 10 Source IPs")
                    )
                    st.altair_chart(source_chart, use_container_width=True)
                else:
                    st.info("No source IP data available yet.")

            with chart_col2:
                st.subheader("📊 Protocol Distribution")
                top_protocols = stats.get("top_protocols", [])
                if top_protocols:
                    protocol_df = pd.DataFrame(top_protocols)
                    protocol_chart = (
                        alt.Chart(protocol_df)
                        .mark_arc(innerRadius=60, outerRadius=120)
                        .encode(
                            theta=alt.Theta(field="count", type="quantitative"),
                            color=alt.Color(field="protocol", type="nominal", legend=alt.Legend(title="Protocol")),
                            tooltip=["protocol:N", "count:Q"],
                        )
                        .properties(height=300, title="Protocol Distribution")
                    )
                    st.altair_chart(protocol_chart, use_container_width=True)
                else:
                    st.info("No protocol data available yet.")
        else:
            st.warning(
                "⚠️ Packet sniffer is not available. Make sure Npcap is installed and you're running as Administrator."
            )

    with tab_network:
        # Network Scan tab
        st.subheader("🌐 Network Scan - Open Ports")
        st.markdown("This section shows TCP ports in LISTEN mode on your computer.")

        # Port scan button
        col_btn1, col_btn2, col_btn3 = st.columns([1, 2, 1])
        with col_btn2:
            scan_button = st.button("🔍 Scan Ports Now", type="primary", use_container_width=True)

        # Show port scan results
        if scan_button or "port_scan_results" not in st.session_state:
            with st.spinner("Scanning ports, please wait..."):
                try:
                    ports = scan_open_ports()
                    st.session_state.port_scan_results = ports
                    st.session_state.port_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    st.error(f"❌ Error during port scan: {e}")
                    st.session_state.port_scan_results = []

        # Show results
        if "port_scan_results" in st.session_state and st.session_state.port_scan_results:
            ports = st.session_state.port_scan_results
            scan_time = st.session_state.get("port_scan_time", "Unknown")

            # Summary metrics
            summary = get_port_summary(ports)
            col_sum1, col_sum2, col_sum3 = st.columns(3)

            with col_sum1:
                st.metric("🔌 Total Open Ports", summary["Total"])
            with col_sum2:
                st.metric("🚨 High Risk Ports", summary["High Risk"], delta_color="inverse")
            with col_sum3:
                st.metric("✅ Low Risk Ports", summary["Low Risk"])

            st.caption(f"📅 Last scan: {scan_time}")
            st.markdown("---")

            # Port table
            if ports:
                # Create DataFrame
                df_ports = pd.DataFrame(ports)

                # Highlight high risk ports
                def highlight_high_risk(row):
                    styles = [""] * len(row)
                    if row["Risk"] == "High" or row["Risk"] == "Yüksek":
                        return ["background-color: #ff4444; color: white; font-weight: bold;"] * len(row)
                    return styles

                # Add icon to Risk column
                df_ports_display = df_ports.copy()
                df_ports_display["Risk"] = df_ports_display["Risk"].apply(
                    lambda x: f"🚨 {x}" if x == "High" or x == "Yüksek" else f"✅ {x}"
                )

                styled_df = df_ports_display.style.apply(highlight_high_risk, axis=1)

                st.dataframe(styled_df, use_container_width=True, hide_index=True, height=500)

                # Warning for high risk ports
                high_risk_ports = [p for p in ports if p["Risk"] == "High" or p["Risk"] == "Yüksek"]
                if high_risk_ports:
                    st.warning(
                        f"⚠️ **{len(high_risk_ports)} high risk port(s) detected!** "
                        "These ports should be carefully examined from a security perspective."
                    )

                    # High risk port details
                    with st.expander("🚨 High Risk Port Details", expanded=True):
                        for port_info in high_risk_ports:
                            st.markdown(f"""
                            **Port {port_info["Port"]}** - {port_info.get("Service", port_info.get("Servis", "N/A"))}
                            - **PID:** {port_info["PID"]}
                            - **Application:** {port_info.get("Application", port_info.get("Uygulama", "N/A"))}
                            - **Description:** {port_info.get("Description", port_info.get("Açıklama", "N/A"))}
                            """)
                            st.markdown("---")
            else:
                st.info("✅ No open ports found or scan failed.")
        else:
            st.info("🔍 Click the button above to scan ports.")

    # --- VULNERABILITIES TAB (Trivy-based CVE findings) ---
    with tab_vulns:
        st.header("🐞 Vulnerability Management")
        st.caption(
            "CVE findings from the offline Trivy scanner — which package on which target is affected, and whether a fix exists."
        )

        counts = get_vulnerability_counts()

        if counts["total"] == 0:
            st.info(
                "No vulnerability findings yet. Run a scan with "
                "`python -m modules.vuln_scanner` (configure targets via "
                "`VULN_SCAN_IMAGES` / `VULN_SCAN_PATHS`) after pre-downloading Trivy's DB."
            )
        else:
            # KPI row — reuse the shared render_kpi card component.
            k1, k2, k3, k4 = st.columns(4)
            render_kpi(k1, "🔴", "Critical", counts["critical"], accent="#e5484d")
            render_kpi(k2, "🟠", "High", counts["high"], accent="#f5a623")
            render_kpi(k3, "🟡", "Medium", counts["medium"], accent="#e2c541")
            fix_pct = round(100 * counts["fixable"] / counts["total"]) if counts["total"] else 0
            render_kpi(k4, "🩹", "Fix available", f"{fix_pct}%", foot=f"{counts['fixable']} of {counts['total']}")

            st.markdown("---")

            # Filters
            fcol1, fcol2 = st.columns([1, 1])
            with fcol1:
                sev_filter = st.selectbox(
                    "Severity", ["All", "Critical", "High", "Medium", "Low", "Unknown"], key="vuln_sev"
                )
            with fcol2:
                fixable_only = st.checkbox("Only findings with a fix available", key="vuln_fixable")

            rows = get_vulnerabilities(
                severity=None if sev_filter == "All" else sev_filter,
                fixable_only=fixable_only,
            )

            if rows:
                vuln_df = pd.DataFrame(
                    rows,
                    columns=[
                        "id",
                        "CVE",
                        "Package",
                        "Installed",
                        "Fixed",
                        "Severity",
                        "Target",
                        "Type",
                        "CVSS",
                        "Title",
                        "Scanned",
                    ],
                ).drop(columns=["id"])
                st.subheader(f"🐞 Findings ({len(vuln_df)})")
                st.dataframe(vuln_df, use_container_width=True, hide_index=True)
            else:
                st.info("No findings match the current filters.")

    # --- TAB 3: AI ASSISTANT (UPDATED UI) ---
    with tab_chat:
        st.header("💬 Cybersecurity Assistant")
        st.caption("You can ask questions about your system. AI will respond based on log and port data.")

        # Typewriter effect generator
        def stream_data(text):
            """Generator function for typewriter effect"""
            words = text.split(" ")
            for word in words:
                yield word + " "
                time.sleep(0.02)  # Small delay between words

        # Initialize Session State
        if "messages" not in st.session_state:
            st.session_state.messages = []
            # Initial welcome message
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": "Hello! I'm the LocalShield Cybersecurity Assistant. "
                    "You can ask questions about your system. "
                    "For example: 'Are there any risks in my system?', 'Which ports are open?', 'What are the latest security events?'",
                }
            )

        # Display Message History (in bubbles)
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        # New Message Input
        if prompt := st.chat_input("What would you like to know about your system's status?"):
            # Add and show user message
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            # Ask Assistant
            with st.chat_message("assistant"):
                with st.spinner("Analyzing data..."):
                    try:
                        response = ask_assistant(prompt)
                        # Use typewriter effect
                        st.write_stream(stream_data(response))
                        st.session_state.messages.append({"role": "assistant", "content": response})
                    except Exception as e:
                        error_msg = f"Sorry, an error occurred: {str(e)}"
                        st.error(error_msg)
                        st.session_state.messages.append({"role": "assistant", "content": error_msg})

        # Clear chat history button
        if st.session_state.messages and len(st.session_state.messages) > 1:
            st.markdown("---")
            col_clear1, col_clear2, col_clear3 = st.columns([1, 1, 1])
            with col_clear2:
                if st.button("🗑️ Clear Chat History", use_container_width=True):
                    st.session_state.messages = []
                    st.rerun()

    # Bottom section - refresh status + opt-in auto-refresh
    st.markdown("---")
    col_refresh1, col_refresh2, col_refresh3 = st.columns([1, 2, 1])
    with col_refresh2:
        current_time = datetime.now().strftime("%H:%M:%S")
        status = "on" if auto_refresh else "off"
        st.caption(f"🔄 Last update: {current_time}  ·  Auto-refresh: {status}")

    # Auto-refresh is opt-in (sidebar toggle). When enabled, reload after 5s,
    # but never while the user is typing in the AI chat input.
    if auto_refresh:
        auto_refresh_script = """
        <script>
            setTimeout(function(){
                var chatInput = document.querySelector('[data-testid="stChatInput"] textarea');
                if (!chatInput || document.activeElement !== chatInput) {
                    location.reload();
                }
            }, 5000);
        </script>
        """
        st.markdown(auto_refresh_script, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
