"""Reusable rendered widgets: KPI cards and log-entry cards."""

import html

import pandas as pd
import streamlit as st

from ui.helpers import get_risk_color_class, get_risk_icon, translate_risk_level


def render_kpi(column, icon, label, value, foot="", accent="var(--ls-accent)") -> None:
    """Renders a single professional KPI card into the given column.

    Values are escaped: the threat model treats log-derived content as
    attacker-influenced, and these cards render with unsafe_allow_html.
    """
    column.markdown(
        f"""
        <div class="ls-kpi" style="--kpi-accent:{accent}">
            <div class="k-top">
                <span class="k-label">{html.escape(str(label))}</span>
                <span class="k-ico">{icon}</span>
            </div>
            <div class="k-val">{html.escape(str(value))}</div>
            <div class="k-foot">{html.escape(str(foot))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


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
            risk_display = f"<span class='{risk_class}'>**{html.escape(str(risk_level_en))}** {risk_icon}</span>"
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
