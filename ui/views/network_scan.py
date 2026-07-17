"""Network Scan tab: TCP ports in LISTEN mode on this machine."""

from datetime import datetime

import pandas as pd
import streamlit as st

from modules.network_scanner import get_port_summary, scan_open_ports


def render() -> None:
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
                if row["Risk"] == "High":
                    return ["background-color: #ff4444; color: white; font-weight: bold;"] * len(row)
                return styles

            # Add icon to Risk column
            df_ports_display = df_ports.copy()
            df_ports_display["Risk"] = df_ports_display["Risk"].apply(lambda x: f"🚨 {x}" if x == "High" else f"✅ {x}")

            styled_df = df_ports_display.style.apply(highlight_high_risk, axis=1)

            st.dataframe(styled_df, use_container_width=True, hide_index=True, height=500)

            # Warning for high risk ports
            high_risk_ports = [p for p in ports if p["Risk"] == "High"]
            if high_risk_ports:
                st.warning(
                    f"⚠️ **{len(high_risk_ports)} high risk port(s) detected!** "
                    "These ports should be carefully examined from a security perspective."
                )

                # High risk port details
                with st.expander("🚨 High Risk Port Details", expanded=True):
                    for port_info in high_risk_ports:
                        st.markdown(f"""
                        **Port {port_info["Port"]}** - {port_info.get("Service", "N/A")}
                        - **PID:** {port_info["PID"]}
                        - **Application:** {port_info.get("Application", "N/A")}
                        - **Description:** {port_info.get("Description", "N/A")}
                        """)
                        st.markdown("---")
        else:
            st.info("✅ No open ports found or scan failed.")
    else:
        st.info("🔍 Click the button above to scan ports.")
