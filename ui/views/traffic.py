"""Network Traffic tab: live packet capture (Wireshark-like view)."""

import asyncio
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

from modules.packet_capture import PacketSniffer


def render() -> None:
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
                        finally:
                            loop.close()
                            # The temp file must go away even when the
                            # capture or download setup fails.
                            if os.path.exists(temp_file.name):
                                os.unlink(temp_file.name)
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
