"""Incidents tab: grouped high-risk detections for triage."""

import html

import streamlit as st

import config
from db_manager import get_incidents, set_incident_status
from ui.components import render_kpi


def render() -> None:
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
            card_col, btn_col = st.columns([6, 1])
            with card_col:
                st.markdown(
                    f"""
                    <div class="ls-ip-card" style="border-left-color:{border}">
                        <div>
                            <div class="ip">#{inc_id} · {html.escape(str(key))}</div>
                            <div class="meta">{html.escape((title or "Incident")[:90])}</div>
                            <div class="meta">{count} event(s) · {html.escape(str(first_seen))} → {html.escape(str(last_seen))} · {status_badge}</div>
                        </div>
                        <span class="ls-chip {chip}" style="margin-left:auto">{html.escape(sev.upper())}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with btn_col:
                if status == "open":
                    if st.button("✔ Close", key=f"inc_close_{inc_id}", use_container_width=True):
                        if set_incident_status(inc_id, "closed", db_path=config.DB_PATH):
                            st.rerun()
                        else:
                            st.error("Could not close incident.")
                else:
                    if st.button("↻ Reopen", key=f"inc_reopen_{inc_id}", use_container_width=True):
                        if set_incident_status(inc_id, "open", db_path=config.DB_PATH):
                            st.rerun()
                        else:
                            st.error("Could not reopen incident.")
    else:
        st.info("✅ No incidents yet. High-risk detections will be grouped here as they occur.")
