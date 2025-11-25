"""
Streamlit Dashboard - LocalShield Professional SIEM Arayüzü
"""
import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime
import config
from db_manager import get_all_logs, get_high_risk_count, get_total_log_count, get_latest_detection, clear_all_logs
from modules.network_scanner import scan_open_ports, get_port_summary
from modules.chat_manager import ask_assistant


# Sayfa yapılandırması
st.set_page_config(
    page_title="LocalShield Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Özel CSS - Profesyonel SIEM tasarımı
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


@st.cache_data(ttl=5)  # 5 saniye cache
def load_data():
    """Veritabanından log verilerini yükler"""
    try:
        logs = get_all_logs(config.DB_PATH, limit=1000)
        
        if not logs:
            return pd.DataFrame()
        
        # DataFrame oluştur (mitre_technique dahil)
        df = pd.DataFrame(logs, columns=[
            'ID', 'Zaman', 'Event ID', 'Mesaj', 'AI Analiz', 'Risk Seviyesi', 'MITRE Tekniği'
        ])
        
        # Zaman sütununu datetime'a çevir
        try:
            df['Zaman'] = pd.to_datetime(df['Zaman'])
        except:
            pass
        
        return df
    except Exception as e:
        st.error(f"Veri yüklenirken hata oluştu: {e}")
        return pd.DataFrame()


def get_risk_icon(risk_level):
    """Risk seviyesine göre ikon döndürür"""
    if pd.isna(risk_level):
        return "❓"
    
    risk_str = str(risk_level).strip().lower()
    if 'yüksek' in risk_str or 'high' in risk_str:
        return "🔴"
    elif 'orta' in risk_str or 'medium' in risk_str:
        return "🟠"
    elif 'düşük' in risk_str or 'low' in risk_str:
        return "🟢"
    return "⚪"


def get_risk_color_class(risk_level):
    """Risk seviyesine göre CSS class döndürür"""
    if pd.isna(risk_level):
        return ""
    
    risk_str = str(risk_level).strip().lower()
    if 'yüksek' in risk_str or 'high' in risk_str:
        return "risk-high"
    elif 'orta' in risk_str or 'medium' in risk_str:
        return "risk-medium"
    elif 'düşük' in risk_str or 'low' in risk_str:
        return "risk-low"
    return ""


def filter_data(df, risk_filters, event_id_filter, text_search=None):
    """Verileri filtreler"""
    filtered_df = df.copy()
    
    # Risk seviyesi filtresi
    if risk_filters:
        filtered_df = filtered_df[
            filtered_df['Risk Seviyesi'].str.contains('|'.join(risk_filters), case=False, na=False)
        ]
    
    # Event ID filtresi
    if event_id_filter:
        filtered_df = filtered_df[
            filtered_df['Event ID'].astype(str).str.contains(event_id_filter, case=False, na=False)
        ]
    
    # Gelişmiş Arama (Text Search) - Mesaj, AI Analiz, MITRE Tekniği içinde ara
    if text_search and text_search.strip():
        search_term = text_search.strip().lower()
        mask = (
            filtered_df['Mesaj'].astype(str).str.lower().str.contains(search_term, na=False) |
            filtered_df['AI Analiz'].astype(str).str.lower().str.contains(search_term, na=False) |
            filtered_df['MITRE Tekniği'].astype(str).str.lower().str.contains(search_term, na=False)
        )
        filtered_df = filtered_df[mask]
    
    return filtered_df


def create_timeline_chart(df):
    """Zaman çizelgesine göre log yoğunluğu grafiği (Area Chart)"""
    if df.empty or 'Zaman' not in df.columns:
        return None
    
    try:
        # Zaman damgasına göre grupla (15 dakikalık aralıklar)
        df_chart = df.copy()
        
        # Zaman sütununu datetime'a çevir (eğer değilse)
        if not pd.api.types.is_datetime64_any_dtype(df_chart['Zaman']):
            df_chart['Zaman'] = pd.to_datetime(df_chart['Zaman'], errors='coerce')
        
        # Geçersiz tarihleri filtrele
        df_chart = df_chart[df_chart['Zaman'].notna()]
        
        if df_chart.empty:
            return None
        
        # 15 dakikalık aralıklara böl
        df_chart['Zaman_Aralik'] = df_chart['Zaman'].dt.floor('15min')
        timeline_data = df_chart.groupby('Zaman_Aralik').size().reset_index(name='Log Sayısı')
        
        chart = alt.Chart(timeline_data).mark_area(
            interpolate='monotone',
            fillOpacity=0.6,
            stroke='#1f77b4',
            strokeWidth=2
        ).encode(
            x=alt.X('Zaman_Aralik:T', title='Zaman', axis=alt.Axis(format='%H:%M')),
            y=alt.Y('Log Sayısı:Q', title='Log Sayısı'),
            tooltip=[
                alt.Tooltip('Zaman_Aralik:T', format='%Y-%m-%d %H:%M', title='Zaman'),
                alt.Tooltip('Log Sayısı:Q', title='Log Sayısı')
            ]
        ).properties(
            height=300,
            title='Zaman Çizelgesine Göre Log Yoğunluğu'
        ).configure_axis(
            gridColor='rgba(255,255,255,0.1)'
        ).configure_view(
            strokeWidth=0
        )
        
        return chart
    except Exception as e:
        # Hata mesajını sessizce yoksay (boş grafik göster)
        return None


def create_risk_distribution_chart(df):
    """Risk seviyelerine göre dağılım grafiği (Donut Chart)"""
    if df.empty or 'Risk Seviyesi' not in df.columns:
        return None
    
    try:
        # Risk seviyelerini normalize et
        df_chart = df.copy()
        df_chart['Risk_Seviyesi_Normal'] = df_chart['Risk Seviyesi'].apply(
            lambda x: 'Yüksek' if 'yüksek' in str(x).lower() or 'high' in str(x).lower()
            else 'Orta' if 'orta' in str(x).lower() or 'medium' in str(x).lower()
            else 'Düşük' if 'düşük' in str(x).lower() or 'low' in str(x).lower()
            else 'Belirtilmemiş'
        )
        
        risk_counts = df_chart['Risk_Seviyesi_Normal'].value_counts().reset_index()
        risk_counts.columns = ['Risk Seviyesi', 'Sayı']
        
        # Renk paleti
        color_map = {
            'Yüksek': '#ff4444',
            'Orta': '#ffaa00',
            'Düşük': '#44ff44',
            'Belirtilmemiş': '#888888'
        }
        risk_counts['Renk'] = risk_counts['Risk Seviyesi'].map(color_map).fillna('#888888')
        
        chart = alt.Chart(risk_counts).mark_arc(
            innerRadius=60,
            outerRadius=120
        ).encode(
            theta=alt.Theta(field='Sayı', type='quantitative'),
            color=alt.Color(
                field='Risk Seviyesi',
                type='nominal',
                scale=alt.Scale(
                    domain=risk_counts['Risk Seviyesi'].tolist(),
                    range=risk_counts['Renk'].tolist()
                ),
                legend=alt.Legend(title="Risk Seviyesi")
            ),
            tooltip=['Risk Seviyesi:N', 'Sayı:Q']
        ).properties(
            height=300,
            title='Risk Seviyesi Dağılımı'
        )
        
        return chart
    except Exception as e:
        st.error(f"Risk dağılım grafiği oluşturulurken hata: {e}")
        return None


def render_log_card(row):
    """Bir log kaydını kart olarak render eder"""
    risk_level = str(row.get('Risk Seviyesi', 'Belirtilmemiş'))
    risk_icon = get_risk_icon(risk_level)
    risk_class = get_risk_color_class(risk_level)
    
    # Zaman formatı
    try:
        if pd.notna(row.get('Zaman')):
            if isinstance(row['Zaman'], pd.Timestamp):
                time_str = row['Zaman'].strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(row['Zaman'], str):
                # String ise parse et
                try:
                    dt = pd.to_datetime(row['Zaman'])
                    time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    time_str = row['Zaman']
            else:
                time_str = str(row['Zaman'])
        else:
            time_str = "Bilinmiyor"
    except:
        time_str = str(row.get('Zaman', 'Bilinmiyor'))
    
    event_id = str(row.get('Event ID', 'N/A'))
    
    # MITRE tekniğini al
    mitre_technique = row.get('MITRE Tekniği', None)
    mitre_display = ""
    if mitre_technique and pd.notna(mitre_technique) and str(mitre_technique).strip():
        mitre_display = f" 🔴 {mitre_technique}"
    
    # Başlık oluştur - risk seviyesi vurgulanmış (Markdown formatında)
    header = f"{risk_icon} {time_str} - {risk_level}{mitre_display} - Event ID: {event_id}"
    
    # Genişletici içeriği
    with st.expander(header, expanded=False):
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("**📋 Event Detayları**")
            st.write(f"**ID:** `{row.get('ID', 'N/A')}`")
            st.write(f"**Event ID:** `{event_id}`")
            st.write(f"**Zaman:** `{time_str}`")
            risk_display = f"<span class='{risk_class}'>**{risk_level}** {risk_icon}</span>"
            st.markdown(f"**Risk Seviyesi:** {risk_display}", unsafe_allow_html=True)
            
            # MITRE Tekniği göster
            if mitre_technique and pd.notna(mitre_technique) and str(mitre_technique).strip():
                st.markdown(f"**🔴 MITRE ATT&CK:** `{mitre_technique}`")
        
        with col2:
            st.markdown("**🤖 AI Analizi**")
            ai_analysis = str(row.get('AI Analiz', 'Analiz yok'))
            if ai_analysis and ai_analysis != 'Analiz yok':
                # AI analizini daha okunabilir formata çevir
                st.info(f"💭 {ai_analysis}")
            else:
                st.warning("⚠️ Analiz bulunamadı")
        
        st.markdown("---")
        st.markdown("**📝 Tam Mesaj**")
        message = str(row.get('Mesaj', 'Mesaj yok'))
        if message and len(message) > 0:
            # Mesajı daha okunabilir yap
            st.code(message, language=None)
        else:
            st.caption("Mesaj içeriği bulunmuyor.")


def main():
    """Ana dashboard fonksiyonu"""
    
    # Başlık
    st.title("🛡️ LocalShield - AI Destekli SIEM")
    st.markdown("---")
    
    # Sidebar - Filtreler
    with st.sidebar:
        st.header("🔍 Filtreler")
        
        # Risk seviyesi filtresi
        risk_options = ["Yüksek", "Orta", "Düşük"]
        selected_risks = st.multiselect(
            "Risk Seviyesi",
            options=risk_options,
            default=[]
        )
        
        # Event ID filtresi
        event_id_filter = st.text_input(
            "Event ID",
            placeholder="Örn: 4625, 4624..."
        )
        
        # Gelişmiş Arama (Text Search)
        text_search = st.text_input(
            "🔎 Gelişmiş Arama",
            placeholder="Mesaj, AI Analiz veya MITRE Tekniği içinde ara..."
        )
        
        st.markdown("---")
        st.caption("💡 Filtreleri temizlemek için seçimleri kaldırın.")
        
        # Veritabanını Temizle Butonu
        st.markdown("---")
        st.header("⚙️ Yönetim")
        
        # Session state ile onay kontrolü
        if 'confirm_reset' not in st.session_state:
            st.session_state.confirm_reset = False
        
        if not st.session_state.confirm_reset:
            if st.button("🗑️ Veritabanını Temizle", type="secondary", use_container_width=True):
                st.session_state.confirm_reset = True
                st.rerun()
        else:
            st.warning("⚠️ Tüm log kayıtları silinecek! Bu işlem geri alınamaz.")
            col_confirm1, col_confirm2 = st.columns(2)
            with col_confirm1:
                if st.button("✅ Onayla", type="primary", use_container_width=True):
                    if clear_all_logs(config.DB_PATH):
                        st.session_state.confirm_reset = False
                        st.success("✅ Veritabanı başarıyla temizlendi!")
                        st.rerun()
                    else:
                        st.error("❌ Veritabanı temizlenirken hata oluştu.")
            with col_confirm2:
                if st.button("❌ İptal", use_container_width=True):
                    st.session_state.confirm_reset = False
                    st.rerun()
    
    # Metrikler
    col1, col2, col3 = st.columns(3)
    
    try:
        # Metrik 1: Toplam Log
        total_logs = get_total_log_count(config.DB_PATH)
        with col1:
            st.metric(
                label="📊 Toplam Log",
                value=total_logs,
                delta=None
            )
        
        # Metrik 2: Yüksek Riskli Olaylar
        high_risk = get_high_risk_count(config.DB_PATH)
        with col2:
            st.metric(
                label="🚨 Yüksek Riskli Olaylar",
                value=high_risk,
                delta=None,
                delta_color="inverse"
            )
        
        # Metrik 3: Son Tespit
        latest = get_latest_detection(config.DB_PATH)
        if latest:
            try:
                latest_dt = pd.to_datetime(latest)
                latest_str = latest_dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                latest_str = str(latest)
        else:
            latest_str = "Henüz yok"
        
        with col3:
            st.metric(
                label="⏰ Son Tespit",
                value=latest_str,
                delta=None
            )
    except Exception as e:
        st.error(f"Metrikler yüklenirken hata: {e}")
    
    st.markdown("---")
    
    # 3 Sekmeli yapı (Chat artık sekme)
    tab_logs, tab_network, tab_chat = st.tabs(["📋 Log Analizi", "🌐 Ağ Taraması", "💬 AI Asistan"])
    
    with tab_logs:
        # Log Analizi sekmesi
        # Grafikler
        df = load_data()
        
        if not df.empty:
            # Grafik satırı
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                timeline_chart = create_timeline_chart(df)
                if timeline_chart:
                    st.altair_chart(timeline_chart, use_container_width=True)
                else:
                    st.info("Zaman çizelgesi grafiği oluşturulamadı.")
            
            with chart_col2:
                risk_chart = create_risk_distribution_chart(df)
                if risk_chart:
                    st.altair_chart(risk_chart, use_container_width=True)
                else:
                    st.info("Risk dağılım grafiği oluşturulamadı.")
            
            st.markdown("---")
            
            # Filtreleme
            filtered_df = filter_data(df, selected_risks, event_id_filter, text_search)
            
            # CSV İndirme Butonu ve Log Başlığı
            col_header1, col_header2 = st.columns([3, 1])
            with col_header1:
                st.subheader(f"📋 Güvenlik Logları ({len(filtered_df)} kayıt)")
            with col_header2:
                if not filtered_df.empty:
                    # CSV olarak indir
                    csv = filtered_df.to_csv(index=False, encoding='utf-8-sig')
                    st.download_button(
                        label="📥 CSV Olarak İndir",
                        data=csv,
                        file_name=f"localshield_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
            
            if filtered_df.empty:
                st.info("🔍 Filtre kriterlerine uygun log bulunamadı.")
            else:
                # Her log için kart oluştur
                for idx, row in filtered_df.iterrows():
                    render_log_card(row)
        else:
            st.info("📭 Henüz log kaydı bulunmuyor. Log watcher'ı çalıştırdığınızdan emin olun.")
    
    with tab_network:
        # Ağ Taraması sekmesi
        st.subheader("🌐 Ağ Taraması - Açık Portlar")
        st.markdown("Bu bölüm, bilgisayarınızdaki dinleme (LISTEN) modundaki TCP portlarını gösterir.")
        
        # Port tarama butonu
        col_btn1, col_btn2, col_btn3 = st.columns([1, 2, 1])
        with col_btn2:
            scan_button = st.button("🔍 Anlık Port Taraması Yap", type="primary", use_container_width=True)
        
        # Port tarama sonuçlarını göster
        if scan_button or 'port_scan_results' not in st.session_state:
            with st.spinner("Portlar taranıyor, lütfen bekleyin..."):
                try:
                    ports = scan_open_ports()
                    st.session_state.port_scan_results = ports
                    st.session_state.port_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    st.error(f"❌ Port tarama sırasında hata oluştu: {e}")
                    st.session_state.port_scan_results = []
        
        # Sonuçları göster
        if 'port_scan_results' in st.session_state and st.session_state.port_scan_results:
            ports = st.session_state.port_scan_results
            scan_time = st.session_state.get('port_scan_time', 'Bilinmiyor')
            
            # Özet metrikler
            summary = get_port_summary(ports)
            col_sum1, col_sum2, col_sum3 = st.columns(3)
            
            with col_sum1:
                st.metric("🔌 Toplam Açık Port", summary["Toplam"])
            with col_sum2:
                st.metric("🚨 Yüksek Riskli Port", summary["Yüksek Risk"], delta_color="inverse")
            with col_sum3:
                st.metric("✅ Düşük Riskli Port", summary["Düşük Risk"])
            
            st.caption(f"📅 Son tarama: {scan_time}")
            st.markdown("---")
            
            # Port tablosu
            if ports:
                # DataFrame oluştur
                df_ports = pd.DataFrame(ports)
                
                # Yüksek riskli portları vurgula
                def highlight_high_risk(row):
                    styles = [''] * len(row)
                    if row['Risk'] == 'Yüksek':
                        return ['background-color: #ff4444; color: white; font-weight: bold;'] * len(row)
                    return styles
                
                # Risk sütununa ikon ekle
                df_ports_display = df_ports.copy()
                df_ports_display['Risk'] = df_ports_display['Risk'].apply(
                    lambda x: f"🚨 {x}" if x == "Yüksek" else f"✅ {x}"
                )
                
                styled_df = df_ports_display.style.apply(highlight_high_risk, axis=1)
                
                st.dataframe(
                    styled_df,
                    use_container_width=True,
                    hide_index=True,
                    height=500
                )
                
                # Yüksek riskli portlar için uyarı
                high_risk_ports = [p for p in ports if p['Risk'] == 'Yüksek']
                if high_risk_ports:
                    st.warning(f"⚠️ **{len(high_risk_ports)} adet yüksek riskli port tespit edildi!** "
                              "Bu portlar güvenlik açısından dikkatli incelenmelidir.")
                    
                    # Yüksek riskli portların detayları
                    with st.expander("🚨 Yüksek Riskli Port Detayları", expanded=True):
                        for port_info in high_risk_ports:
                            st.markdown(f"""
                            **Port {port_info['Port']}** - {port_info['Servis']}
                            - **PID:** {port_info['PID']}
                            - **Uygulama:** {port_info['Uygulama']}
                            - **Açıklama:** {port_info['Açıklama']}
                            """)
                            st.markdown("---")
            else:
                st.info("✅ Açık port bulunamadı veya tarama başarısız oldu.")
        else:
            st.info("🔍 Port taraması yapmak için yukarıdaki butona tıklayın.")
    
    # --- SEKME 3: AI ASİSTAN (YENİLENMİŞ UI) ---
    with tab_chat:
        st.header("💬 Siber Güvenlik Asistanı")
        st.caption("Sisteminiz hakkında sorular sorabilirsiniz. AI, log ve port verilerine göre yanıt verecektir.")
        
        # Session State Başlatma
        if "messages" not in st.session_state:
            st.session_state.messages = []
            # İlk karşılama mesajı
            st.session_state.messages.append({
                "role": "assistant",
                "content": "Merhaba! Ben LocalShield Siber Güvenlik Asistanıyım. "
                          "Sisteminiz hakkında sorular sorabilirsiniz. "
                          "Örneğin: 'Sistemimde risk var mı?', 'Hangi portlar açık?', 'Son güvenlik olayları neler?'"
            })
        
        # Geçmiş Mesajları Ekrana Bas (Baloncuk Şeklinde)
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Yeni Mesaj Girişi
        if prompt := st.chat_input("Sistemin durumu hakkında ne bilmek istersiniz?"):
            # Kullanıcı mesajını ekle ve göster
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Asistana Sor
            with st.chat_message("assistant"):
                with st.spinner("Veriler analiz ediliyor..."):
                    try:
                        response = ask_assistant(prompt)
                        st.markdown(response)
                        st.session_state.messages.append({"role": "assistant", "content": response})
                    except Exception as e:
                        error_msg = f"Üzgünüm, bir hata oluştu: {str(e)}"
                        st.error(error_msg)
                        st.session_state.messages.append({"role": "assistant", "content": error_msg})
        
        # Chat geçmişini temizleme butonu
        if st.session_state.messages and len(st.session_state.messages) > 1:
            st.markdown("---")
            col_clear1, col_clear2, col_clear3 = st.columns([1, 1, 1])
            with col_clear2:
                if st.button("🗑️ Sohbet Geçmişini Temizle", use_container_width=True):
                    st.session_state.messages = []
                    st.rerun()
    
    # Alt kısım - Otomatik yenileme bilgisi (sadece log sekmesinde göster)
    # Chat sekmesinde otomatik yenileme olmamalı (kullanıcı yazıyor olabilir)
    st.markdown("---")
    col_refresh1, col_refresh2, col_refresh3 = st.columns([1, 2, 1])
    with col_refresh2:
        current_time = datetime.now().strftime("%H:%M:%S")
        st.caption(f"🔄 Son güncelleme: {current_time}")
    
    # Otomatik yenileme sadece log sekmesi aktifken çalışmalı
    # JavaScript ile kontrol ediyoruz - chat sekmesi aktifse yenileme yok
    auto_refresh_script = """
    <script>
        // Sadece log sekmesinde otomatik yenileme (chat sekmesinde olmasın)
        var currentTab = window.location.hash || '';
        if (currentTab === '' || currentTab.includes('log') || !currentTab.includes('chat')) {
            setTimeout(function(){
                // Chat input'u aktif değilse yenile
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
