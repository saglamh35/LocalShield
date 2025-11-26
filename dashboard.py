"""
Streamlit Dashboard - LocalShield Professional SIEM Interface
"""
import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime
import config
from db_manager import get_all_logs, get_high_risk_count, get_total_log_count, get_latest_detection, clear_all_logs
from modules.network_scanner import scan_open_ports, get_port_summary
from modules.chat_manager import ask_assistant


# Page configuration
st.set_page_config(
    page_title="LocalShield Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS - Professional SIEM design
st.markdown("""
<style>
    .main > div {
        padding-top: 2rem;
    }
    .stExpander {
        border: 1px solid rgba(250, 250, 250, 0.2);
        border-radius: 0.5rem;
        margin-bottom: 0.5rem;
    }
    .risk-high {
        color: #ff4444;
        font-weight: bold;
    }
    .risk-medium {
        color: #ffaa00;
        font-weight: bold;
    }
    .risk-low {
        color: #44ff44;
        font-weight: bold;
    }
    h1 {
        color: #1f77b4;
    }
    .metric-card {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: rgba(255, 255, 255, 0.05);
    }
    .high-risk-port {
        background-color: #ff4444 !important;
        color: white !important;
        font-weight: bold;
    }
    .port-table {
        border-radius: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_data(ttl=5)  # 5 second cache
def load_data():
    """Loads log data from database"""
    try:
        logs = get_all_logs(config.DB_PATH, limit=1000)
        
        if not logs:
            return pd.DataFrame()
        
        # Create DataFrame (including mitre_technique)
        df = pd.DataFrame(logs, columns=[
            'ID', 'Time', 'Event ID', 'Message', 'AI Analysis', 'Risk Level', 'MITRE Technique'
        ])
        
        # Convert Time column to datetime
        try:
            df['Time'] = pd.to_datetime(df['Time'])
        except:
            pass
        
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()


def get_risk_icon(risk_level):
    """Returns icon based on risk level"""
    if pd.isna(risk_level):
        return "❓"
    
    risk_str = str(risk_level).strip().lower()
    if 'high' in risk_str or 'yüksek' in risk_str:
        return "🔴"
    elif 'medium' in risk_str or 'orta' in risk_str:
        return "🟠"
    elif 'low' in risk_str or 'düşük' in risk_str:
        return "🟢"
    return "⚪"


def get_risk_color_class(risk_level):
    """Returns CSS class based on risk level"""
    if pd.isna(risk_level):
        return ""
    
    risk_str = str(risk_level).strip().lower()
    if 'high' in risk_str or 'yüksek' in risk_str:
        return "risk-high"
    elif 'medium' in risk_str or 'orta' in risk_str:
        return "risk-medium"
    elif 'low' in risk_str or 'düşük' in risk_str:
        return "risk-low"
    return ""


def filter_data(df, risk_filters, event_id_filter, text_search=None):
    """Filters data"""
    filtered_df = df.copy()
    
    # Risk level filter
    if risk_filters:
        filtered_df = filtered_df[
            filtered_df['Risk Level'].str.contains('|'.join(risk_filters), case=False, na=False)
        ]
    
    # Event ID filter
    if event_id_filter:
        filtered_df = filtered_df[
            filtered_df['Event ID'].astype(str).str.contains(event_id_filter, case=False, na=False)
        ]
    
    # Advanced Search (Text Search) - Search in Message, AI Analysis, MITRE Technique
    if text_search and text_search.strip():
        search_term = text_search.strip().lower()
        mask = (
            filtered_df['Message'].astype(str).str.lower().str.contains(search_term, na=False) |
            filtered_df['AI Analysis'].astype(str).str.lower().str.contains(search_term, na=False) |
            filtered_df['MITRE Technique'].astype(str).str.lower().str.contains(search_term, na=False)
        )
        filtered_df = filtered_df[mask]
    
    return filtered_df


def create_timeline_chart(df):
    """Log intensity chart by timeline (Area Chart)"""
    if df.empty or 'Time' not in df.columns:
        return None
    
    try:
        # Zaman damgasına göre grupla (15 dakikalık aralıklar)
        df_chart = df.copy()
        
        # Convert Time column to datetime (if not already)
        if not pd.api.types.is_datetime64_any_dtype(df_chart['Time']):
            df_chart['Time'] = pd.to_datetime(df_chart['Time'], errors='coerce')
        
        # Filter invalid dates
        df_chart = df_chart[df_chart['Time'].notna()]
        
        if df_chart.empty:
            return None
        
        # Split into 15-minute intervals
        df_chart['Time_Interval'] = df_chart['Time'].dt.floor('15min')
        timeline_data = df_chart.groupby('Time_Interval').size().reset_index(name='Log Count')
        
        chart = alt.Chart(timeline_data).mark_area(
            interpolate='monotone',
            fillOpacity=0.6,
            stroke='#1f77b4',
            strokeWidth=2
        ).encode(
            x=alt.X('Time_Interval:T', title='Time', axis=alt.Axis(format='%H:%M')),
            y=alt.Y('Log Count:Q', title='Log Count'),
            tooltip=[
                alt.Tooltip('Time_Interval:T', format='%Y-%m-%d %H:%M', title='Time'),
                alt.Tooltip('Log Count:Q', title='Log Count')
            ]
        ).properties(
            height=300,
            title='Log Intensity by Timeline'
        ).configure_axis(
            gridColor='rgba(255,255,255,0.1)'
        ).configure_view(
            strokeWidth=0
        )
        
        return chart
    except Exception as e:
        # Silently ignore error (show empty chart)
        return None


def create_risk_distribution_chart(df):
    """Risk level distribution chart (Donut Chart)"""
    if df.empty or 'Risk Level' not in df.columns:
        return None
    
    try:
        # Normalize risk levels
        df_chart = df.copy()
        df_chart['Risk_Level_Normal'] = df_chart['Risk Level'].apply(
            lambda x: 'High' if 'high' in str(x).lower() or 'yüksek' in str(x).lower()
            else 'Medium' if 'medium' in str(x).lower() or 'orta' in str(x).lower()
            else 'Low' if 'low' in str(x).lower() or 'düşük' in str(x).lower()
            else 'Unspecified'
        )
        
        risk_counts = df_chart['Risk_Level_Normal'].value_counts().reset_index()
        risk_counts.columns = ['Risk Level', 'Count']
        
        # Color palette
        color_map = {
            'High': '#ff4444',
            'Medium': '#ffaa00',
            'Low': '#44ff44',
            'Unspecified': '#888888'
        }
        risk_counts['Color'] = risk_counts['Risk Level'].map(color_map).fillna('#888888')
        
        chart = alt.Chart(risk_counts).mark_arc(
            innerRadius=60,
            outerRadius=120
        ).encode(
            theta=alt.Theta(field='Count', type='quantitative'),
            color=alt.Color(
                field='Risk Level',
                type='nominal',
                scale=alt.Scale(
                    domain=risk_counts['Risk Level'].tolist(),
                    range=risk_counts['Color'].tolist()
                ),
                legend=alt.Legend(title="Risk Level")
            ),
            tooltip=['Risk Level:N', 'Count:Q']
        ).properties(
            height=300,
            title='Risk Level Distribution'
        )
        
        return chart
    except Exception as e:
        st.error(f"Error creating risk distribution chart: {e}")
        return None


def render_log_card(row):
    """Renders a log entry as a card"""
    risk_level = str(row.get('Risk Level', 'Unspecified'))
    risk_icon = get_risk_icon(risk_level)
    risk_class = get_risk_color_class(risk_level)
    
    # Time format
    try:
        if pd.notna(row.get('Time')):
            if isinstance(row['Time'], pd.Timestamp):
                time_str = row['Time'].strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(row['Time'], str):
                # If string, parse it
                try:
                    dt = pd.to_datetime(row['Time'])
                    time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    time_str = row['Time']
            else:
                time_str = str(row['Time'])
        else:
            time_str = "Unknown"
    except:
        time_str = str(row.get('Time', 'Unknown'))
    
    event_id = str(row.get('Event ID', 'N/A'))
    
    # Get MITRE technique
    mitre_technique = row.get('MITRE Technique', None)
    mitre_display = ""
    if mitre_technique and pd.notna(mitre_technique) and str(mitre_technique).strip():
        mitre_display = f" 🔴 {mitre_technique}"
    
    # Create header - risk level emphasized (Markdown format)
    header = f"{risk_icon} {time_str} - {risk_level}{mitre_display} - Event ID: {event_id}"
    
    # Expander content
    with st.expander(header, expanded=False):
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("**📋 Event Details**")
            st.write(f"**ID:** `{row.get('ID', 'N/A')}`")
            st.write(f"**Event ID:** `{event_id}`")
            st.write(f"**Time:** `{time_str}`")
            risk_display = f"<span class='{risk_class}'>**{risk_level}** {risk_icon}</span>"
            st.markdown(f"**Risk Level:** {risk_display}", unsafe_allow_html=True)
            
            # Show MITRE Technique
            if mitre_technique and pd.notna(mitre_technique) and str(mitre_technique).strip():
                st.markdown(f"**🔴 MITRE ATT&CK:** `{mitre_technique}`")
        
        with col2:
            st.markdown("**🤖 AI Analysis**")
            ai_analysis = str(row.get('AI Analysis', 'No analysis'))
            if ai_analysis and ai_analysis != 'No analysis':
                # Convert AI analysis to more readable format
                st.info(f"💭 {ai_analysis}")
            else:
                st.warning("⚠️ Analysis not found")
        
        st.markdown("---")
        st.markdown("**📝 Full Message**")
        message = str(row.get('Message', 'No message'))
        if message and len(message) > 0:
            # Make message more readable
            st.code(message, language=None)
        else:
            st.caption("No message content available.")


def main():
    """Main dashboard function"""
    
    # Header
    st.title("🛡️ LocalShield - AI-Powered SIEM")
    st.markdown("---")
    
    # Sidebar - Filters
    with st.sidebar:
        st.header("🔍 Filters")
        
        # Risk level filter
        risk_options = ["High", "Medium", "Low"]
        selected_risks = st.multiselect(
            "Risk Level",
            options=risk_options,
            default=[]
        )
        
        # Event ID filter
        event_id_filter = st.text_input(
            "Event ID",
            placeholder="E.g.: 4625, 4624..."
        )
        
        # Advanced Search (Text Search)
        text_search = st.text_input(
            "🔎 Advanced Search",
            placeholder="Search in Message, AI Analysis or MITRE Technique..."
        )
        
        st.markdown("---")
        st.caption("💡 Clear selections to reset filters.")
        
        # Clear Database Button
        st.markdown("---")
        st.header("⚙️ Management")
        
        # Session state for confirmation check
        if 'confirm_reset' not in st.session_state:
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
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    
    try:
        # Metric 1: Total Logs
        total_logs = get_total_log_count(config.DB_PATH)
        with col1:
            st.metric(
                label="📊 Total Logs",
                value=total_logs,
                delta=None
            )
        
        # Metric 2: High Risk Events
        high_risk = get_high_risk_count(config.DB_PATH)
        with col2:
            st.metric(
                label="🚨 High Risk Events",
                value=high_risk,
                delta=None,
                delta_color="inverse"
            )
        
        # Metric 3: Latest Detection
        latest = get_latest_detection(config.DB_PATH)
        if latest:
            try:
                latest_dt = pd.to_datetime(latest)
                latest_str = latest_dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                latest_str = str(latest)
        else:
            latest_str = "None yet"
        
        with col3:
            st.metric(
                label="⏰ Latest Detection",
                value=latest_str,
                delta=None
            )
    except Exception as e:
        st.error(f"Error loading metrics: {e}")
    
    st.markdown("---")
    
    # 3 Tab structure (Chat is now a tab)
    tab_logs, tab_network, tab_chat = st.tabs(["📋 Log Analysis", "🌐 Network Scan", "💬 AI Assistant"])
    
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
            
            st.markdown("---")
            
            # Filtering
            filtered_df = filter_data(df, selected_risks, event_id_filter, text_search)
            
            # CSV Download Button and Log Header
            col_header1, col_header2 = st.columns([3, 1])
            with col_header1:
                st.subheader(f"📋 Security Logs ({len(filtered_df)} entries)")
            with col_header2:
                if not filtered_df.empty:
                    # Download as CSV
                    csv = filtered_df.to_csv(index=False, encoding='utf-8-sig')
                    st.download_button(
                        label="📥 Download as CSV",
                        data=csv,
                        file_name=f"localshield_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
            
            if filtered_df.empty:
                st.info("🔍 No logs found matching filter criteria.")
            else:
                # Create card for each log
                for idx, row in filtered_df.iterrows():
                    render_log_card(row)
        else:
            st.info("📭 No log entries found yet. Make sure the log watcher is running.")
    
    with tab_network:
        # Network Scan tab
        st.subheader("🌐 Network Scan - Open Ports")
        st.markdown("This section shows TCP ports in LISTEN mode on your computer.")
        
        # Port scan button
        col_btn1, col_btn2, col_btn3 = st.columns([1, 2, 1])
        with col_btn2:
            scan_button = st.button("🔍 Scan Ports Now", type="primary", use_container_width=True)
        
        # Show port scan results
        if scan_button or 'port_scan_results' not in st.session_state:
            with st.spinner("Scanning ports, please wait..."):
                try:
                    ports = scan_open_ports()
                    st.session_state.port_scan_results = ports
                    st.session_state.port_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    st.error(f"❌ Error during port scan: {e}")
                    st.session_state.port_scan_results = []
        
        # Show results
        if 'port_scan_results' in st.session_state and st.session_state.port_scan_results:
            ports = st.session_state.port_scan_results
            scan_time = st.session_state.get('port_scan_time', 'Unknown')
            
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
                    styles = [''] * len(row)
                    if row['Risk'] == 'High' or row['Risk'] == 'Yüksek':
                        return ['background-color: #ff4444; color: white; font-weight: bold;'] * len(row)
                    return styles
                
                # Add icon to Risk column
                df_ports_display = df_ports.copy()
                df_ports_display['Risk'] = df_ports_display['Risk'].apply(
                    lambda x: f"🚨 {x}" if x == "High" or x == "Yüksek" else f"✅ {x}"
                )
                
                styled_df = df_ports_display.style.apply(highlight_high_risk, axis=1)
                
                st.dataframe(
                    styled_df,
                    use_container_width=True,
                    hide_index=True,
                    height=500
                )
                
                # Warning for high risk ports
                high_risk_ports = [p for p in ports if p['Risk'] == 'High' or p['Risk'] == 'Yüksek']
                if high_risk_ports:
                    st.warning(f"⚠️ **{len(high_risk_ports)} high risk port(s) detected!** "
                              "These ports should be carefully examined from a security perspective.")
                    
                    # High risk port details
                    with st.expander("🚨 High Risk Port Details", expanded=True):
                        for port_info in high_risk_ports:
                            st.markdown(f"""
                            **Port {port_info['Port']}** - {port_info.get('Service', port_info.get('Servis', 'N/A'))}
                            - **PID:** {port_info['PID']}
                            - **Application:** {port_info.get('Application', port_info.get('Uygulama', 'N/A'))}
                            - **Description:** {port_info.get('Description', port_info.get('Açıklama', 'N/A'))}
                            """)
                            st.markdown("---")
            else:
                st.info("✅ No open ports found or scan failed.")
        else:
            st.info("🔍 Click the button above to scan ports.")
    
    # --- TAB 3: AI ASSISTANT (UPDATED UI) ---
    with tab_chat:
        st.header("💬 Cybersecurity Assistant")
        st.caption("You can ask questions about your system. AI will respond based on log and port data.")
        
        # Initialize Session State
        if "messages" not in st.session_state:
            st.session_state.messages = []
            # Initial welcome message
            st.session_state.messages.append({
                "role": "assistant",
                "content": "Hello! I'm the LocalShield Cybersecurity Assistant. "
                          "You can ask questions about your system. "
                          "For example: 'Are there any risks in my system?', 'Which ports are open?', 'What are the latest security events?'"
            })
        
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
                        st.markdown(response)
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
    
    # Bottom section - Auto refresh info (only shown on log tab)
    # Chat tab should not auto-refresh (user might be typing)
    st.markdown("---")
    col_refresh1, col_refresh2, col_refresh3 = st.columns([1, 2, 1])
    with col_refresh2:
        current_time = datetime.now().strftime("%H:%M:%S")
        st.caption(f"🔄 Last update: {current_time}")
    
    # Auto refresh should only work when log tab is active
    # We check with JavaScript - no refresh if chat tab is active
    auto_refresh_script = """
    <script>
        // Auto refresh only on log tab (not on chat tab)
        var currentTab = window.location.hash || '';
        if (currentTab === '' || currentTab.includes('log') || !currentTab.includes('chat')) {
            setTimeout(function(){
                // Refresh if chat input is not active
                var chatInput = document.querySelector('[data-testid="stChatInput"] textarea');
                if (!chatInput || document.activeElement !== chatInput) {
                    location.reload();
                }
            }, 5000);
        }
    </script>
    """
    st.markdown(auto_refresh_script, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
