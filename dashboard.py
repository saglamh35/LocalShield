"""
Streamlit Dashboard - LocalShield SIEM Görselleştirme Arayüzü
"""
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import config
from db_manager import get_all_logs, get_high_risk_count, get_total_log_count, get_latest_detection


# Sayfa yapılandırması
st.set_page_config(
    page_title="LocalShield Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Özel CSS - Risk seviyesine göre renklendirme için
st.markdown("""
<style>
    .metric-card {
        background-color: #0E1117;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #262730;
    }
    .high-risk {
        background-color: #ff4444 !important;
        color: white !important;
    }
    .medium-risk {
        background-color: #ffaa00 !important;
        color: white !important;
    }
    .low-risk {
        background-color: #44ff44 !important;
        color: black !important;
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
        
        # DataFrame oluştur
        df = pd.DataFrame(logs, columns=[
            'ID', 'Zaman', 'Event ID', 'Mesaj', 'AI Analiz', 'Risk Seviyesi'
        ])
        
        return df
    except Exception as e:
        st.error(f"Veri yüklenirken hata oluştu: {e}")
        return pd.DataFrame()


def style_row(row):
    """Satırı risk seviyesine göre renklendirir"""
    risk_level = row.get('Risk Seviyesi', '')
    
    if pd.isna(risk_level):
        return [''] * len(row)
    
    risk_str = str(risk_level).strip().lower()
    
    if 'yüksek' in risk_str or 'high' in risk_str:
        return ['background-color: #ff4444; color: white;'] * len(row)
    elif 'orta' in risk_str or 'medium' in risk_str:
        return ['background-color: #ffaa00; color: white;'] * len(row)
    elif 'düşük' in risk_str or 'low' in risk_str:
        return ['background-color: #44ff44; color: black;'] * len(row)
    
    return [''] * len(row)


def main():
    """Ana dashboard fonksiyonu"""
    
    # Başlık
    st.title("🛡️ LocalShield - AI Destekli SIEM")
    st.markdown("---")
    
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
            # Tarih formatını düzelt
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
    
    # Veri tablosu
    st.subheader("📋 Güvenlik Logları")
    
    # Verileri yükle
    df = load_data()
    
    if df.empty:
        st.info("📭 Henüz log kaydı bulunmuyor. Log watcher'ı çalıştırdığınızdan emin olun.")
    else:
        # Risk seviyesine göre tüm satırı renklendir
        styled_df = df.style.apply(
            style_row,
            axis=1
        )
        
        # Tabloyu göster
        st.dataframe(
            styled_df,
            use_container_width=True,
            hide_index=True,
            height=600
        )
        
        # Bilgi
        st.caption(f"📌 Toplam {len(df)} kayıt gösteriliyor (En yeni {min(1000, len(df))} kayıt)")
    
    # Alt kısım - Otomatik yenileme bilgisi
    col_refresh1, col_refresh2, col_refresh3 = st.columns([1, 2, 1])
    with col_refresh2:
        current_time = datetime.now().strftime("%H:%M:%S")
        st.caption(f"🔄 Son güncelleme: {current_time} | Sayfa 5 saniyede bir otomatik olarak yenileniyor...")
    
    # Otomatik yenileme için JavaScript (basit ve etkili)
    auto_refresh_script = """
    <script>
        setTimeout(function(){
            location.reload();
        }, 5000);
    </script>
    """
    st.markdown(auto_refresh_script, unsafe_allow_html=True)


if __name__ == "__main__":
    main()

