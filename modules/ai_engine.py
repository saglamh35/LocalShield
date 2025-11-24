"""
AI Engine Module - Windows Log Analizi için Brain Sınıfı
"""
import ollama
from config import MODEL_NAME


class Brain:
    """
    Windows güvenlik loglarını analiz eden AI sınıfı.
    Ollama üzerinde çalışan lokal LLM kullanır.
    """
    
    def __init__(self, model_name: str = MODEL_NAME):
        """
        Brain sınıfını başlatır.
        
        Args:
            model_name: Ollama model adı (varsayılan: config.py'den alınır)
        """
        self.model_name = model_name
        self.system_prompt = (
            "Sen bir siber güvenlik uzmanısın. Gelen Windows logunu analiz et. "
            "Çıktıyı SADECE şu formatta ver: "
            "Risk Seviyesi: [Düşük/Orta/Yüksek] | Özet: [Kısa Türkçe açıklama]"
        )
    
    def analyze(self, log_text: str) -> str:
        """
        Windows log metnini analiz eder ve risk seviyesi ile özet döndürür.
        
        Args:
            log_text: Analiz edilecek Windows log metni
        
        Returns:
            str: "Risk Seviyesi: [Düşük/Orta/Yüksek] | Özet: [Türkçe açıklama]" formatında analiz
                 Hata durumunda: "Analiz Edilemedi"
        """
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': self.system_prompt
                    },
                    {
                        'role': 'user',
                        'content': f"Bu Windows logunu analiz et:\n\n{log_text}"
                    }
                ]
            )
            
            # AI'ın cevabını al
            analysis = response['message']['content'].strip()
            
            # Format kontrolü - eğer beklenen formatta değilse düzenle
            if "Risk Seviyesi:" in analysis and "Özet:" in analysis:
                return analysis
            else:
                # Formatı düzeltmeye çalış
                return f"Risk Seviyesi: Orta | Özet: {analysis}"
                
        except Exception as e:
            # Hata durumunda
            print(f"AI analiz hatası: {e}")
            return "Analiz Edilemedi"

