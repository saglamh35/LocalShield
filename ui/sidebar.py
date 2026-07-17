"""Sidebar: filters, live-view toggle and database management."""

import streamlit as st

import config
from db_manager import clear_all_logs


def render_sidebar() -> dict:
    """Renders the sidebar and returns the selected filter/view options."""
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

    return {
        "selected_risks": selected_risks,
        "event_id_filter": event_id_filter,
        "text_search": text_search,
        "date_range": date_range,
        "page_size": page_size,
        "auto_refresh": auto_refresh,
    }
