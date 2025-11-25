"""
Chat Manager Module - AI Chatbot Asistanı
LocalShield için interaktif AI asistan modülü
"""
import ollama
from datetime import datetime
from typing import List, Dict
import config
from db_manager import get_all_logs
from modules.network_scanner import scan_open_ports


def get_system_summary() -> str:
    """
    Sistem özetini oluşturur: Son yüksek riskli loglar ve riskli portlar
    
    Returns:
        str: Sistem özeti metni
    """
    summary_parts = []
    
    try:
        # Veritabanından son 10 yüksek riskli logu al
        all_logs = get_all_logs(config.DB_PATH, limit=50, order_by='DESC')
        high_risk_logs = []
        
        for log in all_logs:
            if len(log) >= 6 and str(log[5]).strip().lower() == 'yüksek':
                high_risk_logs.append(log)
            if len(high_risk_logs) >= 10:  # En fazla 10 adet
                break
        
        # Log özeti
        if high_risk_logs:
            summary_parts.append("=== YÜKSEK RİSKLİ LOGLAR ===\n")
            for log in high_risk_logs:
                log_id = log[0]
                timestamp = log[1]
                event_id = log[2]
                message = log[3] if len(log) > 3 and log[3] else "Mesaj yok"
                ai_analysis = log[4] if len(log) > 4 and log[4] else "Analiz yok"
                risk_score = log[5] if len(log) > 5 else "Bilinmiyor"
                
                # Mesajı kısalt (çok uzunsa)
                message_short = message[:200] if len(message) > 200 else message
                ai_analysis_short = ai_analysis[:200] if len(ai_analysis) > 200 else ai_analysis
                
                summary_parts.append(
                    f"- Event ID {event_id} (Zaman: {timestamp})\n"
                    f"  Mesaj: {message_short}\n"
                    f"  AI Analiz: {ai_analysis_short}\n"
                    f"  Risk: {risk_score}\n"
                )
        else:
            summary_parts.append("=== YÜKSEK RİSKLİ LOG ===\nYüksek riskli log bulunmuyor.\n")
        
        summary_parts.append("\n")
        
    except Exception as e:
        summary_parts.append(f"=== LOG VERİLERİ ===\nLog verileri okunamadı: {e}\n\n")
    
    try:
        # Port taraması yap
        ports = scan_open_ports()
        high_risk_ports = [p for p in ports if p.get('Risk') == 'Yüksek']
        
        # Port özeti
        if high_risk_ports:
            summary_parts.append("=== YÜKSEK RİSKLİ AÇIK PORTLAR ===\n")
            for port_info in high_risk_ports[:10]:  # En fazla 10 adet
                summary_parts.append(
                    f"- Port {port_info['Port']} ({port_info['Servis']})\n"
                    f"  PID: {port_info.get('PID', 'N/A')}\n"
                    f"  Uygulama: {port_info.get('Uygulama', 'Bilinmiyor')}\n"
                    f"  Açıklama: {port_info.get('Açıklama', 'Açıklama yok')}\n"
                )
        else:
            summary_parts.append("=== AÇIK PORTLAR ===\nYüksek riskli açık port bulunmuyor.\n")
        
        # Toplam port istatistiği
        if ports:
            total_ports = len(ports)
            high_count = len(high_risk_ports)
            low_count = total_ports - high_count
            summary_parts.append(
                f"\nToplam Açık Port: {total_ports}\n"
                f"Yüksek Riskli: {high_count}\n"
                f"Düşük Riskli: {low_count}\n"
            )
        
    except Exception as e:
        summary_parts.append(f"=== PORT VERİLERİ ===\nPort verileri okunamadı: {e}\n")
    
    return "\n".join(summary_parts)


def ask_assistant(user_question: str) -> str:
    """
    AI asistanına soru sorar ve sistem verilerine göre cevap alır
    
    Args:
        user_question: Kullanıcının sorusu
    
    Returns:
        str: AI'ın cevabı
    """
    try:
        # Sistem özetini al
        system_data = get_system_summary()
        
        # System prompt oluştur
        system_prompt = (
            "Sen LocalShield Siber Güvenlik Asistanısın. "
            "Görevin, kullanıcının güvenlik sorularını aşağıdaki sistem verilerine göre yanıtlamak.\n\n"
            
            "SİSTEM VERİLERİ:\n"
            f"{system_data}\n\n"
            
            "KURALLAR:\n"
            "1. Yanıtlarını Türkçe, net ve anlaşılır şekilde ver.\n"
            "2. Sistem verilerindeki bilgilere dayanarak yanıt ver.\n"
            "3. Eğer yüksek riskli durum varsa bunu vurgula ve tavsiyelerde bulun.\n"
            "4. Kullanıcı dostu, teknik olmayan bir dil kullan.\n"
            "5. Eğer sistem verilerinde ilgili bilgi yoksa, bunu dürüstçe belirt.\n"
            "6. Tavsiyeler verirken pratik ve uygulanabilir öneriler sun.\n\n"
            
            "Kullanıcının sorusunu yanıtla:"
        )
        
        # Ollama'ya gönder
        response = ollama.chat(
            model=config.MODEL_NAME,
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': user_question
                }
            ]
        )
        
        # AI'ın cevabını al
        answer = response['message']['content'].strip()
        
        return answer
        
    except Exception as e:
        # Hata durumunda
        error_message = f"Üzgünüm, bir hata oluştu: {str(e)}\n"
        error_message += "Lütfen tekrar deneyin veya sistem yöneticisi ile iletişime geçin."
        return error_message

