# modules/ai_engine.py
import ollama
import re
from config import MODEL_NAME
# Knowledge Base modülünü (RAG Motoru) import ediyoruz
from modules.knowledge_base import get_event_info

class Brain:
    def __init__(self):
        self.model = MODEL_NAME
        # Base System Prompt (AI'ın Temel Kişiliği)
        self.system_prompt = """
        Sen Kıdemli bir SOC Analistisin (Cyber Security Expert).
        Sana verilen Windows Logunu analiz et.
        Cevabını SADECE şu Markdown formatında ver:

        🛑 Risk: [Düşük/Orta/Yüksek]
        👤 Kullanıcı/Varlık: [Tespit edilen kullanıcı adı veya makine]
        📝 Olay Özeti: [Olayın teknik olmayan, net Türkçe açıklaması]
        💡 Öneri: [Bu durumda ne yapılmalı?]

        Lütfen kısa, net ve profesyonel ol.
        """

    def extract_event_id(self, log_text):
        """Log metninden Event ID'yi çeker"""
        # Örn: "Event ID 4625" veya "EventId : 4625"
        match = re.search(r'Event ID\s*[:#]?\s*(\d+)', log_text, re.IGNORECASE)
        if match:
            return match.group(1)
        # Bazen log formatı farklı olabilir, sadece sayıyı yakalamaya çalışalım
        return None

    def analyze(self, log_text):
        """
        Log metnini analiz eder, Knowledge Base'den (RAG) bilgi çeker ve yanıt döndürür.
        """
        current_system_prompt = self.system_prompt
        event_id = self.extract_event_id(log_text)

        # --- RAG (RETRIEVAL AUGMENTED GENERATION) ENTEGRASYONU ---
        if event_id:
            # Önce Local (Senin yazdığın), sonra External (GitHub) bilgiyi dener
            # Bu fonksiyon zaten öncelik sırasını kendi içinde hallediyor.
            kb_info = get_event_info(event_id)

            if kb_info:
                # --- ÇÖZÜM 3: PROMPT HARDENING (AI'I ZORLAMA) ---
                # AI'ın bilgiyi değiştirmesini veya "bence şöyle yap" demesini engellemek için
                # çok sert ve kesin bir talimat ekliyoruz.
                
                extra_instruction = f"""

                [🛑 KRİTİK GÜVENLİK PROTOKOLÜ - ZORUNLU UYGULAMA]:
                Bu olay (ID: {event_id}) için veritabanında tanımlanmış KESİN BİR PROSEDÜR mevcut.
                
                1. Analiz raporunun '💡 Öneri' kısmına, aşağıdaki metni HİÇBİR DEĞİŞİKLİK YAPMADAN, KELİMESİ KELİMESİNE (Verbatim) yapıştırmak ZORUNDASIN. Kendi cümleni kurma.
                2. Analiz raporunun '🛑 Risk' kısmına, aşağıda belirtilen risk seviyesini yaz.

                --- KULLANILACAK ZORUNLU VERİLER ---
                RİSK SEVİYESİ: {kb_info['risk_level']}
                ZORUNLU ÖNERİ METNİ: "{kb_info['advice']}"
                ------------------------------------
                """
                current_system_prompt += extra_instruction
                
                # --- DEBUG: Terminalde RAG'ın çalıştığını görmek için ---
                print(f"\n📢 --- [DEBUG] RAG DEVREDE (ID: {event_id}) ---")
                print(f"Çekilen Bilgi Kaynağı: Local/External Knowledge Base")
                print(f"Zorunlu Öneri: {kb_info['advice']}")
                print("------------------------------------------------\n")

        try:
            response = ollama.chat(model=self.model, messages=[
                {'role': 'system', 'content': current_system_prompt},
                {'role': 'user', 'content': f"Analiz et:\n{log_text}"},
            ])
            return response['message']['content']
            
        except Exception as e:
            # Hata durumunda güvenli çıkış
            return f"🛑 Risk: Orta\n📝 Olay Özeti: AI Hatası - {str(e)}\n💡 Öneri: Logları manuel inceleyin."