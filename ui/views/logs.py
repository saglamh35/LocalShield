"""Log Analysis tab: charts, MITRE coverage, filters and paginated log cards."""

from datetime import datetime

import streamlit as st

from ui.charts import create_mitre_chart, create_risk_distribution_chart, create_timeline_chart
from ui.components import render_log_card
from ui.data import load_data
from ui.helpers import filter_data, map_severity, translate_risk_level


def render(filters: dict) -> None:
    """Renders the Log Analysis tab using the sidebar filter selections."""
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
        filtered_df = filter_data(
            df,
            filters["selected_risks"],
            filters["event_id_filter"],
            filters["text_search"],
            filters["date_range"],
        )

        # Add Severity column (map from Risk Level)
        if not filtered_df.empty and "Risk Level" in filtered_df.columns:
            filtered_df["Severity"] = filtered_df["Risk Level"].apply(map_severity)

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
            page_size = filters["page_size"]
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
