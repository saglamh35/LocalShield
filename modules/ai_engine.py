"""
AI Engine Module - Windows Log Analizi için Brain Sınıfı
Production-Ready: JSON çıktı formatı ve type hints ile güncellendi
"""
import ollama
import re
import json
import logging
from typing import Optional, Dict, Any, Tuple
from pydantic import ValidationError

import config
from modules.knowledge_base import get_event_info
from modules.ai_models import AIAnalysisResponse

# Logging yapılandırması
logger = logging.getLogger(__name__)


class Brain:
    """
    Windows güvenlik loglarını analiz eden AI sınıfı.
    Ollama üzerinde çalışan lokal LLM kullanır.
    Production-Ready: JSON çıktı formatı ve type-safe parsing
    """
    
    def __init__(self, model_name: Optional[str] = None) -> None:
        """
        Brain sınıfını başlatır.
        
        Args:
            model_name: Ollama model adı (varsayılan: config.py'den alınır)
        """
        self.model_name: str = model_name or config.MODEL_NAME
        
        # JSON çıktı formatı için system prompt
        self.system_prompt: str = """Sen Kıdemli bir SOC Analistisin (Cyber Security Expert).
Sana verilen Windows Logunu analiz et ve yanıtını MUTLAKA şu JSON formatında ver:

{
    "risk_score": "Düşük" veya "Orta" veya "Yüksek",
    "user_entity": "Tespit edilen kullanıcı adı veya makine adı",
    "summary": "Olayın teknik olmayan, net Türkçe açıklaması",
    "advice": "Bu durumda ne yapılmalı? Pratik tavsiyeler",
    "event_id_explanation": "Event ID hakkında eğitici açıklama (opsiyonel)"
}

ÖNEMLİ: 
- Cevabın SADECE JSON olmalı, başka metin olmamalı
- JSON geçerli ve parse edilebilir olmalı
- Kısa, net ve profesyonel ol"""
    
    def extract_event_id(self, log_text: str) -> Optional[str]:
        """
        Log metninden Event ID'yi çıkarır.
        
        Args:
            log_text: Log metni
        
        Returns:
            Event ID (string) veya None
        """
        match = re.search(r'Event ID\s*[:#]?\s*(\d+)', log_text, re.IGNORECASE)
        return match.group(1) if match else None
    
    def analyze(self, log_text: str) -> Tuple[str, str]:
        """
        Windows log metnini analiz eder ve JSON formatında yanıt döndürür.
        Knowledge base'den bilgi çekerek analiz kalitesini artırır (Hibrit RAG).
        
        Args:
            log_text: Analiz edilecek Windows log metni
        
        Returns:
            tuple[str, str]: (markdown_analysis, risk_score) - Dashboard için markdown ve risk seviyesi
        """
        try:
            # Log metninden Event ID'yi çıkarmaya çalış
            event_id: Optional[str] = self.extract_event_id(log_text)
            
            # Knowledge base'den bilgi çek (RAG)
            kb_info: Optional[Dict[str, Any]] = None
            if event_id:
                try:
                    kb_info = get_event_info(event_id)
                    if kb_info:
                        logger.info(f"Knowledge base bilgisi bulundu (Event ID: {event_id}, Kaynak: {kb_info.get('source', 'bilinmiyor')})")
                except Exception as e:
                    logger.warning(f"Knowledge base hatası: {e}")
            
            # System prompt'u hazırla
            enhanced_prompt = self.system_prompt
            
            # RAG bilgisini prompt'a ekle (eğer varsa) - PROMPT HARDENING
            if kb_info:
                extra_instruction = f"""

[🛑 ÖZEL TALİMAT - KRİTİK GÜVENLİK PROTOKOLÜ]:
Bu olay (ID: {event_id}) için tanımlanmış bir GÜVENLİK PROTOKOLÜ var.

JSON çıktındaki "advice" alanına, aşağıdaki metni KELİMESİ KELİMESİNE (Verbatim) yapıştır. Kendin cümle kurma.

ZORUNLU METİN: "{kb_info.get('advice', '')}"

Ayrıca "risk_score" alanına şunu yaz: "{kb_info.get('risk_level', 'Orta')}"

[ÖNEMLİ]: Yukarıdaki "ZORUNLU METİN"i değiştirme, kopyala-yapıştır yap.
"""
                enhanced_prompt += extra_instruction
            
            # AI'a gönder
            logger.debug(f"AI analizi başlatılıyor (Event ID: {event_id})")
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': enhanced_prompt
                    },
                    {
                        'role': 'user',
                        'content': f"Bu Windows güvenlik logunu analiz et:\n\n{log_text}"
                    }
                ]
            )
            
            # AI'ın cevabını al
            raw_response: str = response['message']['content'].strip()
            
            # JSON parse et
            try:
                # JSON'u temizle (eğer markdown code block içindeyse)
                json_str = raw_response
                if "```json" in json_str:
                    json_str = json_str.split("```json")[1].split("```")[0].strip()
                elif "```" in json_str:
                    json_str = json_str.split("```")[1].split("```")[0].strip()
                
                # JSON parse et
                json_data = json.loads(json_str)
                
                # Pydantic model ile validate et
                analysis_response = AIAnalysisResponse(**json_data)
                
                logger.info(f"AI analizi başarıyla parse edildi (Risk: {analysis_response.risk_score})")
                
                # Markdown formatına çevir ve risk_score ile birlikte döndür
                markdown_analysis = analysis_response.to_markdown()
                return markdown_analysis, analysis_response.risk_score
                
            except (json.JSONDecodeError, ValidationError) as e:
                logger.error(f"JSON parse hatası: {e}, Raw response: {raw_response[:200]}")
                # Fallback: Raw response'u döndür
                fallback_markdown = self._create_fallback_response(event_id, raw_response)
                return fallback_markdown, "Orta"
                
        except Exception as e:
            logger.error(f"AI analiz hatası: {e}", exc_info=True)
            fallback_markdown = self._create_fallback_response(event_id, f"AI Hatası: {str(e)}")
            return fallback_markdown, "Orta"
    
    def _create_fallback_response(self, event_id: Optional[str], error_message: str) -> str:
        """
        Hata durumunda fallback response oluşturur.
        
        Args:
            event_id: Event ID (varsa)
            error_message: Hata mesajı
        
        Returns:
            str: Fallback markdown response
        """
        event_id_str = event_id if event_id else "Bilinmiyor"
        return f"""🆔 Event ID {event_id_str} Nedir?
Bu Event ID, Windows güvenlik sisteminin kaydettiği bir olaydır.

🕵️‍♂️ Olay Analizi
Kullanıcı: Analiz Edilemedi
Durum: {error_message}
Risk: Orta

💡 Tavsiye
Log mesajını manuel olarak kontrol edin veya sistem yöneticisi ile iletişime geçin."""
